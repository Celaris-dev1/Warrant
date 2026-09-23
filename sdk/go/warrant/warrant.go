// Package warrant is the Go SDK for the Warrant capability broker and PEP.
//
// Integration is "swap your tool-call function for a wrapped one":
//
//	agent := warrant.NewAgent(brokerURL, pepURL)
//	_ = agent.Attest(ctx, "planner", secret, "")
//	agent.Token = rootToken // minted by an operator, or received via Delegate
//	search := warrant.WrapTool[Query, Result](agent, "web.search", func(q Query) string { return q.Domain })
//	res, err := search(ctx, Query{...}) // goes through the PEP, never directly to the tool
package warrant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Scope mirrors the broker's scope type.
type Scope struct {
	Tool            string                   `json:"tool"`
	Resources       []string                 `json:"resources"`
	Args            map[string]ArgConstraint `json:"args,omitempty"`
	MaxCalls        int                      `json:"max_calls"`
	RequireApproval bool                     `json:"require_approval,omitempty"`
}

// ArgConstraint mirrors the broker's argument constraint.
type ArgConstraint struct {
	Enum    []string `json:"enum,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// Error is a non-2xx response from the broker or PEP.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("warrant: %d: %s", e.Status, e.Msg) }

// Denied reports whether err is an authorization denial.
func Denied(err error) bool {
	e, ok := err.(*Error)
	return ok && (e.Status == 401 || e.Status == 403)
}

// Agent holds one workload instance's identity and current capability token.
type Agent struct {
	BrokerURL, PEPURL string
	HTTP              *http.Client
	SVID, SpiffeID    string
	Token             string
	TokenID           string
	// Approvals keyed by tool name, consumed on the next call to that tool.
	approvals map[string]string
}

// NewAgent builds an agent client.
func NewAgent(brokerURL, pepURL string) *Agent {
	return &Agent{BrokerURL: brokerURL, PEPURL: pepURL, HTTP: &http.Client{Timeout: 30 * time.Second}, approvals: map[string]string{}}
}

func (a *Agent) post(ctx context.Context, url string, hdr map[string]string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct{ Error string }
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = string(body)
		}
		return &Error{Status: resp.StatusCode, Msg: e.Error}
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// Attest obtains a workload identity (JWT-SVID) using the registration secret.
func (a *Agent) Attest(ctx context.Context, workload, secret, instance string) error {
	var out struct {
		SVID     string `json:"svid"`
		SpiffeID string `json:"spiffe_id"`
	}
	if err := a.post(ctx, a.BrokerURL+"/v1/identity", nil, map[string]string{"workload": workload, "secret": secret, "instance": instance}, &out); err != nil {
		return err
	}
	a.SVID, a.SpiffeID = out.SVID, out.SpiffeID
	return nil
}

// Issued is a newly minted token.
type Issued struct {
	Token  string `json:"token"`
	Claims struct {
		ID       string  `json:"jti"`
		Subject  string  `json:"sub"`
		Expires  int64   `json:"exp"`
		Depth    int     `json:"depth"`
		MaxCalls int     `json:"max_calls"`
		Scopes   []Scope `json:"scopes"`
	} `json:"claims"`
}

// MintRoot asks the broker (with an admin token) for a root token for this agent.
func (a *Agent) MintRoot(ctx context.Context, adminToken, human string, scopes []Scope, ttl time.Duration, maxCalls int) (Issued, error) {
	var out Issued
	err := a.post(ctx, a.BrokerURL+"/v1/tokens", map[string]string{"Authorization": "Bearer " + adminToken},
		map[string]any{"svid": a.SVID, "human": human, "scopes": scopes, "ttl_seconds": int(ttl.Seconds()), "max_calls": maxCalls}, &out)
	if err == nil {
		a.Token, a.TokenID = out.Token, out.Claims.ID
	}
	return out, err
}

// Delegate asks the broker to issue child (which must already be attested) a
// token that is the intersection of this agent's authority and scopes.
func (a *Agent) Delegate(ctx context.Context, child *Agent, scopes []Scope, ttl time.Duration, maxCalls int) (Issued, error) {
	var out Issued
	err := a.post(ctx, a.BrokerURL+"/v1/tokens/delegate", nil, map[string]any{
		"parent_token": a.Token, "parent_svid": a.SVID, "child_svid": child.SVID,
		"scopes": scopes, "ttl_seconds": int(ttl.Seconds()), "max_calls": maxCalls}, &out)
	if err == nil {
		child.Token, child.TokenID = out.Token, out.Claims.ID
	}
	return out, err
}

// UseApproval attaches an approval token to the next call of tool.
func (a *Agent) UseApproval(tool, approval string) { a.approvals[tool] = approval }

// Call sends one tool call through the PEP and decodes the upstream response.
func (a *Agent) Call(ctx context.Context, tool, resource string, args map[string]any, out any) error {
	hdr := map[string]string{"Authorization": "Bearer " + a.Token, "X-Warrant-SVID": a.SVID, "X-Warrant-Approval": a.approvals[tool]}
	delete(a.approvals, tool)
	return a.post(ctx, a.PEPURL+"/call/"+tool, hdr, map[string]any{"resource": resource, "args": args}, out)
}

// WrapTool turns a tool into a function that always goes through the PEP.
// resourceOf extracts the resource the call touches from the input; the
// input's JSON fields become the call args.
func WrapTool[In, Out any](a *Agent, tool string, resourceOf func(In) string) func(context.Context, In) (Out, error) {
	return func(ctx context.Context, in In) (Out, error) {
		var out Out
		raw, err := json.Marshal(in)
		if err != nil {
			return out, err
		}
		args := map[string]any{}
		if err := json.Unmarshal(raw, &args); err != nil {
			return out, fmt.Errorf("warrant: tool input must encode as a JSON object: %w", err)
		}
		err = a.Call(ctx, tool, resourceOf(in), args, &out)
		return out, err
	}
}

// Admin is an operator client (workload registration, approvals, revocation,
// blast radius).
type Admin struct {
	a     *Agent
	Token string
}

// NewAdmin builds an operator client.
func NewAdmin(brokerURL, adminToken string) *Admin {
	return &Admin{a: NewAgent(brokerURL, ""), Token: adminToken}
}

func (ad *Admin) hdr() map[string]string { return map[string]string{"Authorization": "Bearer " + ad.Token} }

// RegisterWorkload registers a workload and its attestation secret.
func (ad *Admin) RegisterWorkload(ctx context.Context, name, secret string) error {
	return ad.a.post(ctx, ad.a.BrokerURL+"/v1/workloads", ad.hdr(), map[string]string{"name": name, "secret": secret}, nil)
}

// Approve signs an approval bound to sha256(canonical tool+resource+args) on one token.
func (ad *Admin) Approve(ctx context.Context, tokenID, approver, tool, resource string, args map[string]any) (string, error) {
	var out struct{ Approval string }
	err := ad.a.post(ctx, ad.a.BrokerURL+"/v1/approvals", ad.hdr(), map[string]any{"token_id": tokenID, "approver": approver,
		"call": map[string]any{"tool": tool, "resource": resource, "args": args}}, &out)
	return out.Approval, err
}

// Revoke revokes a token and its whole delegation subtree.
func (ad *Admin) Revoke(ctx context.Context, tokenID, reason string) error {
	return ad.a.post(ctx, ad.a.BrokerURL+"/v1/tokens/"+tokenID+"/revoke", ad.hdr(), map[string]string{"reason": reason}, nil)
}

// BlastRadius fetches what a token can do right now (raw JSON object).
func (ad *Admin) BlastRadius(ctx context.Context, tokenID string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ad.a.BrokerURL+"/v1/tokens/"+tokenID+"/blast-radius", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ad.Token)
	resp, err := ad.a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.StatusCode != 200 {
		return nil, &Error{Status: resp.StatusCode, Msg: "blast-radius"}
	}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
