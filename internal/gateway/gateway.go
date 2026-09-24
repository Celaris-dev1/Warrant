// Package gateway is Warrant's protocol-native PEP: an HTTP proxy that
// speaks MCP (Streamable HTTP JSON-RPC) or A2A (JSON-RPC) to a single
// configured upstream server/agent, and gates the calls that actually
// exercise authority — MCP's "tools/call", A2A's "message/send" and
// "tasks/*" — through the same broker.Service.Authorize used by
// internal/pep, while letting protocol plumbing (initialize, tools/list,
// notifications, agent-card discovery) pass straight through.
//
// Unlike internal/pep's POST /call/{tool} wire format, a gateway speaks the
// upstream's own wire protocol: the model or calling agent talks JSON-RPC
// exactly as it would to the real MCP server or A2A agent, and never sees
// Warrant's own request shape. A denial comes back as a spec-shaped
// JSON-RPC error object with the original request's id preserved, not an
// HTTP-level failure, so a well-behaved client can react to it like any
// other tool error.
package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/pop"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// Protocol selects which JSON-RPC method set a Gateway gates.
type Protocol string

const (
	MCP Protocol = "mcp"
	A2A Protocol = "a2a"
)

// ResourceFunc derives Warrant's resource string for a gated call from its
// JSON-RPC params. The default is "*" (no per-resource distinction).
type ResourceFunc func(method string, params map[string]any) string

// Gateway proxies one upstream MCP or A2A server, authorizing every gated
// call against Svc before forwarding it.
type Gateway struct {
	Svc      *broker.Service
	Protocol Protocol
	Upstream string
	HTTP     *http.Client

	// ToolPrefix is prepended to the MCP tool name / A2A method or skill to
	// form the token.Call.Tool Warrant checks scopes against, e.g. a scope
	// {"tool":"mcp.fs.*"} for an upstream MCP server named "fs". Defaults
	// to "mcp." or "a2a." for the respective protocol.
	ToolPrefix string
	// ResourceOf derives the resource string for a gated call. Defaults to
	// always "*".
	ResourceOf ResourceFunc
	// FilterToolsList, if true, filters an MCP tools/list response down to
	// only the tools the presented credential's scopes would allow (a
	// best-effort, policy-independent check: it does not run per-tool
	// policy rules or argument constraints, only scope tool-name/resource
	// matching, since no call arguments exist yet at listing time).
	FilterToolsList bool
	// MaxBodyBytes bounds request body size. Default 1 MiB.
	MaxBodyBytes int64

	Replay   pop.ReplayStore
	Audience string
}

// New builds a Gateway with defaults filled in.
func New(svc *broker.Service, protocol Protocol, upstream string) *Gateway {
	g := &Gateway{Svc: svc, Protocol: protocol, Upstream: upstream,
		HTTP: &http.Client{Timeout: 30 * time.Second}, MaxBodyBytes: 1 << 20,
		Replay: pop.NewMemoryReplayStore(), Audience: "warrant-gateway"}
	switch protocol {
	case MCP:
		g.ToolPrefix = "mcp."
	case A2A:
		g.ToolPrefix = "a2a."
	}
	return g
}

func (g *Gateway) resourceOf(method string, params map[string]any) string {
	if g.ResourceOf != nil {
		return g.ResourceOf(method, params)
	}
	return "*"
}

// --- JSON-RPC wire types -------------------------------------------------

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const jsonrpcVersion = "2.0"

// Standard JSON-RPC error codes, plus a Warrant-specific one for denials.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInternal       = -32603
	codeDenied         = -32001 // Warrant: authorization denied
)

func errResp(id json.RawMessage, code int, msg string, data any) rpcResp {
	return rpcResp{JSONRPC: jsonrpcVersion, ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}}
}

func isNotification(m rpcMsg) bool { return m.ID == nil }

// gateKind says whether a message is gated (needs authorization), and if
// so what tool name and A2A-skill-derived resource hint to use.
type gateKind int

const (
	passthrough gateKind = iota
	gated
)

func (g *Gateway) classify(m rpcMsg) (kind gateKind, toolSuffix string) {
	switch g.Protocol {
	case MCP:
		if m.Method == "tools/call" {
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(m.Params, &p)
			return gated, p.Name
		}
		return passthrough, ""
	case A2A:
		if m.Method == "message/send" {
			var p struct {
				Skill   string `json:"skill"`
				Message struct {
					Skill string `json:"skill"`
				} `json:"message"`
			}
			_ = json.Unmarshal(m.Params, &p)
			skill := p.Skill
			if skill == "" {
				skill = p.Message.Skill
			}
			if skill == "" {
				skill = m.Method
			}
			return gated, skill
		}
		if len(m.Method) >= 6 && m.Method[:6] == "tasks/" {
			return gated, m.Method
		}
		return passthrough, ""
	}
	return passthrough, ""
}

// ServeHTTP implements the Streamable HTTP transport both protocols use for
// their JSON-RPC exchange: POST a single JSON-RPC object or a batch array,
// get back the matching object/array (notifications receive no entry; an
// all-notification batch gets 204 No Content).
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "gateway: use POST")
		return
	}
	limit := g.MaxBodyBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeSingle(w, http.StatusRequestEntityTooLarge,
			errResp(nil, codeParseError, "parse error: request body too large", nil))
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeSingle(w, http.StatusBadRequest, errResp(nil, codeInvalidRequest, "empty request", nil))
		return
	}

	var msgs []rpcMsg
	batch := body[0] == '['
	if batch {
		if err := json.Unmarshal(body, &msgs); err != nil {
			writeSingle(w, http.StatusBadRequest, errResp(nil, codeParseError, "parse error: "+err.Error(), nil))
			return
		}
		if len(msgs) == 0 {
			writeSingle(w, http.StatusBadRequest, errResp(nil, codeInvalidRequest, "empty batch", nil))
			return
		}
	} else {
		var m rpcMsg
		if err := json.Unmarshal(body, &m); err != nil {
			writeSingle(w, http.StatusBadRequest, errResp(nil, codeParseError, "parse error: "+err.Error(), nil))
			return
		}
		msgs = []rpcMsg{m}
	}

	creds := credentials{
		Token:    bearerToken(r),
		SVID:     r.Header.Get("X-Warrant-SVID"),
		Approval: r.Header.Get("X-Warrant-Approval"),
		PoPKey:   r.Header.Get("X-Warrant-PoP-Key"),
		PoPProof: r.Header.Get("X-Warrant-PoP"),
	}

	// toSend keeps, in order, the raw messages actually forwarded upstream
	// (passthrough + notifications + allowed gated calls). results holds
	// the final per-message outcome, nil where an upstream reply is still
	// pending.
	toSend := make([]json.RawMessage, 0, len(msgs))
	toSendMsgs := make([]rpcMsg, 0, len(msgs))
	results := make([]*rpcResp, len(msgs))
	filterFor := map[string]struct{}{} // ids of tools/list calls to filter, keyed by string(id)

	for i, m := range msgs {
		kind, toolSuffix := g.classify(m)
		if kind == passthrough {
			if g.FilterToolsList && g.Protocol == MCP && m.Method == "tools/list" && !isNotification(m) {
				filterFor[string(m.ID)] = struct{}{}
			}
			raw, _ := json.Marshal(m)
			toSend = append(toSend, raw)
			toSendMsgs = append(toSendMsgs, m)
			continue
		}
		if toolSuffix == "" {
			results[i] = ptr(errResp(m.ID, codeInvalidRequest, "gateway: missing tool/skill name", nil))
			continue
		}
		var params map[string]any
		_ = json.Unmarshal(m.Params, &params)
		call := token.Call{Tool: g.ToolPrefix + toolSuffix, Resource: g.resourceOf(m.Method, params), Args: args(m.Method, params)}
		d := g.Svc.Authorize(r.Context(), broker.AuthorizeRequest{Token: creds.Token, SVID: creds.SVID, Approval: creds.Approval, Call: call})
		if !d.Allow {
			results[i] = ptr(errResp(m.ID, codeDenied, "warrant: denied", map[string]any{
				"reason": d.Reason, "token_id": d.TokenID, "action_hash": d.ActionHash, "tool": call.Tool}))
			continue
		}
		if d.Claims.Cnf != nil {
			if err := g.checkPoP(r, creds, d.Claims); err != nil {
				results[i] = ptr(errResp(m.ID, codeDenied, "warrant: proof-of-possession: "+err.Error(), map[string]any{
					"token_id": d.TokenID, "action_hash": d.ActionHash}))
				continue
			}
		}
		raw, _ := json.Marshal(m)
		toSend = append(toSend, raw)
		toSendMsgs = append(toSendMsgs, m)
	}

	if len(toSend) > 0 {
		var payload []byte
		if len(toSend) == 1 && !batch {
			payload = toSend[0]
		} else {
			payload = []byte("[" + joinRaw(toSend) + "]")
		}
		upResps, err := g.forward(r.Context(), payload)
		if err != nil {
			// Every forwarded, non-notification message that hasn't
			// already been decided gets an upstream-error reply.
			for i, m := range msgs {
				if results[i] == nil && !isNotification(m) {
					results[i] = ptr(errResp(m.ID, codeInternal, "gateway: upstream: "+err.Error(), nil))
				}
			}
		} else {
			byID := map[string]rpcResp{}
			for _, ur := range upResps {
				byID[string(ur.ID)] = ur
			}
			for i, m := range msgs {
				if results[i] != nil || isNotification(m) {
					continue
				}
				if ur, ok := byID[string(m.ID)]; ok {
					if _, want := filterFor[string(m.ID)]; want {
						ur = g.filterToolsListResult(ur, creds, r.Context())
					}
					results[i] = &ur
				} else {
					results[i] = ptr(errResp(m.ID, codeInternal, "gateway: no upstream reply for this id", nil))
				}
			}
		}
	}

	var out []rpcResp
	for i, m := range msgs {
		if isNotification(m) {
			continue
		}
		if results[i] != nil {
			out = append(out, *results[i])
		}
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if batch {
		_ = json.NewEncoder(w).Encode(out)
	} else {
		_ = json.NewEncoder(w).Encode(out[0])
	}
}

func args(method string, params map[string]any) map[string]any {
	if a, ok := params["arguments"].(map[string]any); ok {
		return a
	}
	return params
}

func joinRaw(rs []json.RawMessage) string {
	out := make([]byte, 0)
	for i, r := range rs {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, r...)
	}
	return string(out)
}

func ptr[T any](v T) *T { return &v }

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return h
}

type credentials struct {
	Token, SVID, Approval, PoPKey, PoPProof string
}

// forward POSTs payload (a single object or a JSON array) to the upstream
// and returns every reply as an rpcResp, regardless of whether the upstream
// itself responded with one object or a batch array.
func (g *Gateway) forward(ctx context.Context, payload []byte) ([]rpcResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.Upstream, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %d: %s", resp.StatusCode, string(b))
	}
	if b[0] == '[' {
		var rs []rpcResp
		if err := json.Unmarshal(b, &rs); err != nil {
			return nil, fmt.Errorf("bad upstream batch reply: %w", err)
		}
		return rs, nil
	}
	var one rpcResp
	if err := json.Unmarshal(b, &one); err != nil {
		return nil, fmt.Errorf("bad upstream reply: %w", err)
	}
	return []rpcResp{one}, nil
}

// filterToolsListResult drops tools the presented credential's scopes do
// not permit from an MCP tools/list reply.
func (g *Gateway) filterToolsListResult(ur rpcResp, creds credentials, ctx context.Context) rpcResp {
	if ur.Error != nil || ur.Result == nil {
		return ur
	}
	c, err := g.Svc.Peek(ctx, creds.Token, creds.SVID)
	if err != nil {
		return ur
	}
	var whole map[string]json.RawMessage
	if err := json.Unmarshal(ur.Result, &whole); err != nil {
		return ur
	}
	toolsRaw, ok := whole["tools"]
	if !ok {
		return ur
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return ur
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var td struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(t, &td) == nil {
			if token.FirstMatch(c.Scopes, token.Call{Tool: g.ToolPrefix + td.Name, Resource: "*"}) >= 0 {
				kept = append(kept, t)
			}
		}
	}
	filtered, err := json.Marshal(kept)
	if err != nil {
		return ur
	}
	whole["tools"] = filtered
	newResult, err := json.Marshal(whole)
	if err != nil {
		return ur
	}
	ur.Result = newResult
	return ur
}

// checkPoP mirrors internal/pep's holder-bound proof-of-possession check,
// bound to this HTTP request's method+path, for a JSON-RPC gated call.
func (g *Gateway) checkPoP(r *http.Request, creds credentials, c token.Claims) error {
	if creds.PoPKey == "" || creds.PoPProof == "" {
		return errors.New("holder-bound token requires X-Warrant-PoP and X-Warrant-PoP-Key")
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(creds.PoPKey)
	if err != nil {
		if kb, err2 := base64.StdEncoding.DecodeString(creds.PoPKey); err2 == nil {
			keyBytes = kb
		} else {
			return fmt.Errorf("bad X-Warrant-PoP-Key: %w", err)
		}
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return errors.New("bad X-Warrant-PoP-Key length")
	}
	pc, err := pop.Verify(ed25519.PublicKey(keyBytes), creds.PoPProof, c, g.Audience, time.Now(), g.Replay)
	if err != nil {
		return err
	}
	if pc.Method != "" && pc.Method != r.Method {
		return fmt.Errorf("proof bound to method %s, got %s", pc.Method, r.Method)
	}
	if pc.Path != "" && pc.Path != r.URL.Path {
		return fmt.Errorf("proof bound to path %s, got %s", pc.Path, r.URL.Path)
	}
	return nil
}

func writeSingle(w http.ResponseWriter, status int, resp rpcResp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func httpErr(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}
