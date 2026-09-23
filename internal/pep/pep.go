// Package pep is Warrant's Policy Enforcement Point: an HTTP gateway every
// tool call passes through. The model can ask for anything; only the PEP can
// forward a call to the real tool, and only after the broker authorizes it.
//
// Wire format:
//
//	POST /call/{tool}
//	Authorization: Bearer <capability token>
//	X-Warrant-SVID: <workload JWT-SVID of the caller>
//	X-Warrant-Approval: <approval token>   (only for require_approval scopes)
//	{"resource": "...", "args": {...}}
//
// Allowed calls are forwarded as POST <upstream> with body
// {"tool","resource","args"} and headers X-Warrant-Subject / -Human /
// -Token-ID. The caller's credentials are never forwarded upstream.
package pep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// Route maps a tool pattern to an upstream URL.
type Route struct {
	Tool     string `json:"tool"`
	Upstream string `json:"upstream"`
}

// Gateway is the PEP.
type Gateway struct {
	Svc    *broker.Service
	Routes []Route
	HTTP   *http.Client
}

// LoadRoutes reads routes from a JSON file ([{"tool":"fs.*","upstream":"http://..."}]).
func LoadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs []Route
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	for _, r := range rs {
		if err := token.ValidatePattern(r.Tool); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// New builds a gateway; the most specific (longest) pattern wins.
func New(svc *broker.Service, routes []Route) *Gateway {
	rs := append([]Route{}, routes...)
	sort.SliceStable(rs, func(i, j int) bool { return len(rs[i].Tool) > len(rs[j].Tool) })
	return &Gateway{Svc: svc, Routes: rs, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (g *Gateway) upstream(tool string) (string, bool) {
	for _, r := range g.Routes {
		if token.Match(r.Tool, tool) {
			return r.Upstream, true
		}
	}
	return "", false
}

// ServeHTTP enforces and forwards.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/call/") {
		deny(w, 404, "use POST /call/{tool}", nil)
		return
	}
	tool := strings.TrimPrefix(r.URL.Path, "/call/")
	var body struct {
		Resource string         `json:"resource"`
		Args     map[string]any `json:"args"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		deny(w, 400, "bad body: "+err.Error(), nil)
		return
	}
	call := token.Call{Tool: tool, Resource: body.Resource, Args: body.Args}
	up, ok := g.upstream(tool)
	if !ok {
		deny(w, 404, "no upstream route for tool "+tool, nil)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	d := g.Svc.Authorize(r.Context(), broker.AuthorizeRequest{Token: tok, SVID: r.Header.Get("X-Warrant-SVID"),
		Approval: r.Header.Get("X-Warrant-Approval"), Call: call})
	w.Header().Set("X-Warrant-Decision-Ms", fmt.Sprintf("%.3f", float64(time.Since(start).Microseconds())/1000))
	w.Header().Set("X-Warrant-Action-Hash", d.ActionHash)
	if !d.Allow {
		deny(w, 403, d.Reason, &d)
		return
	}
	fb, _ := json.Marshal(map[string]any{"tool": tool, "resource": call.Resource, "args": call.Args})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, up, bytes.NewReader(fb))
	if err != nil {
		deny(w, 502, err.Error(), nil)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Warrant-Subject", d.Claims.Subject)
	req.Header.Set("X-Warrant-Human", d.Claims.Human)
	req.Header.Set("X-Warrant-Token-ID", d.Claims.ID)
	req.Header.Set("X-Warrant-Action-Hash", d.ActionHash)
	resp, err := g.HTTP.Do(req)
	if err != nil {
		var ue interface{ Timeout() bool }
		if errors.As(err, &ue) && ue.Timeout() {
			deny(w, 504, "upstream timeout", nil)
			return
		}
		deny(w, 502, "upstream: "+err.Error(), nil)
		return
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func deny(w http.ResponseWriter, code int, reason string, d *broker.Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	out := map[string]any{"allow": false, "error": reason}
	if d != nil {
		out["token_id"] = d.TokenID
		out["action_hash"] = d.ActionHash
	}
	_ = json.NewEncoder(w).Encode(out)
}
