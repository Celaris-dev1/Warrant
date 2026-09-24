// Package adapters provides thin, tested Warrant Policy Enforcement Point
// (PEP) wrappers for the calling conventions agent frameworks actually use:
// a generic HTTP middleware, an MCP tool-call gate, an A2A task gate, an
// OpenAI-style function-calling gate and a LangChain-style tool wrapper.
// Every adapter does the same thing underneath — build a token.Call from
// the framework's own request shape and run it through
// broker.Service.Authorize (in-process) or a PEP HTTP call (out-of-process)
// — so a denial always carries the same structured reason, and adding a new
// framework only means writing a new "extract the call" function.
package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// Credentials are what every adapter needs to authorize a call: the
// presented capability token, the caller's workload SVID, and an optional
// approval token for require_approval scopes.
type Credentials struct {
	Token    string
	SVID     string
	Approval string
}

// Denied is returned by every adapter when Warrant refuses a call. It
// carries enough structure for a caller (or an LLM reading the error) to
// understand exactly what was denied and why, without leaking anything
// about tools or resources beyond what was already being attempted.
type Denied struct {
	TokenID    string `json:"token_id,omitempty"`
	ActionHash string `json:"action_hash,omitempty"`
	Reason     string `json:"reason"`
	Tool       string `json:"tool"`
	Resource   string `json:"resource"`
}

func (d *Denied) Error() string {
	return fmt.Sprintf("warrant: denied %s on %s: %s", d.Tool, d.Resource, d.Reason)
}

// Enforcer is the shared core every adapter calls: authorize one
// (tool, resource, args) call in-process against a broker.Service.
type Enforcer struct {
	Svc *broker.Service
}

// New builds an Enforcer around a broker.Service (typically the same one
// warrantd's HTTP API wraps, used here in-process instead of over HTTP).
func New(svc *broker.Service) *Enforcer { return &Enforcer{Svc: svc} }

// Authorize runs one call through Warrant. On denial it returns *Denied
// (use errors.As to recover it); on success it returns the decision, whose
// Claims/ActionHash callers can log or forward.
func (e *Enforcer) Authorize(ctx context.Context, creds Credentials, tool, resource string, args map[string]any) (broker.Decision, error) {
	d := e.Svc.Authorize(ctx, broker.AuthorizeRequest{
		Token: creds.Token, SVID: creds.SVID, Approval: creds.Approval,
		Call: token.Call{Tool: tool, Resource: resource, Args: args},
	})
	if !d.Allow {
		return d, &Denied{TokenID: d.TokenID, ActionHash: d.ActionHash, Reason: d.Reason, Tool: tool, Resource: resource}
	}
	return d, nil
}

// marshalArgs is a small helper adapters use to turn an arbitrary
// JSON-ish payload (an MCP/A2A/OpenAI call's arguments, however typed on
// the wire) into the map[string]any Warrant's arg constraints operate on.
func marshalArgs(v any) (map[string]any, error) {
	switch m := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return m, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("adapters: could not marshal args: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("adapters: args must be a JSON object: %w", err)
	}
	return m, nil
}
