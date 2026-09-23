// Package policy is Warrant's small JSON policy engine. Rules are Cedar-like
// (principal / action / resource + conditions) with deny-overrides semantics:
// any matching forbid denies; otherwise at least one matching permit is
// required; no match denies (default deny).
package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

// Actions a rule may apply to.
const (
	ActionCall     = "call"     // a tool call at the PEP
	ActionMint     = "mint"     // root token issuance
	ActionDelegate = "delegate" // child token issuance
)

// Rule is one policy statement. Empty match fields match anything.
type Rule struct {
	ID        string `json:"id"`
	Effect    string `json:"effect"` // "permit" | "forbid"
	Action    string `json:"action,omitempty"`
	Principal string `json:"principal,omitempty"` // pattern on workload id
	Human     string `json:"human,omitempty"`     // pattern on originating human
	Tool      string `json:"tool,omitempty"`
	Resource  string `json:"resource,omitempty"`
	// When conditions (all must hold).
	When *Cond `json:"when,omitempty"`
	// For permit rules on "delegate": raise the depth cap up to this value
	// for delegations matched by this rule (sub-delegation is off by default).
	AllowDepth int `json:"allow_depth,omitempty"`
}

// Cond are extra conditions on the request.
type Cond struct {
	MaxDepth *int                           `json:"max_depth,omitempty"`
	Args     map[string]token.ArgConstraint `json:"args,omitempty"`
	// Hours (UTC) during which the rule applies, e.g. [9,17] = 09:00-16:59.
	HoursUTC []int `json:"hours_utc,omitempty"`
}

// Set is a versioned policy set.
type Set struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Request is what is evaluated.
type Request struct {
	Action    string
	Principal string
	Human     string
	Depth     int
	Call      token.Call // Tool/Resource/Args; Args may be empty for mint/delegate
	HourUTC   int
}

// Decision is the outcome.
type Decision struct {
	Allow      bool   `json:"allow"`
	Reason     string `json:"reason"`
	RuleID     string `json:"rule_id,omitempty"`
	AllowDepth int    `json:"allow_depth,omitempty"`
}

// Load reads a policy set from a JSON file.
func Load(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses and validates a policy set.
func Parse(b []byte) (*Set, error) {
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	for i, r := range s.Rules {
		if r.Effect != "permit" && r.Effect != "forbid" {
			return nil, fmt.Errorf("rule %d (%s): effect must be permit or forbid", i, r.ID)
		}
		for _, p := range []string{r.Principal, r.Human, r.Tool, r.Resource} {
			if p != "" {
				if err := token.ValidatePattern(p); err != nil {
					return nil, fmt.Errorf("rule %s: %w", r.ID, err)
				}
			}
		}
	}
	return &s, nil
}

func m(p, s string) bool { return p == "" || token.Match(p, s) }

func (r Rule) matches(q Request) bool {
	if r.Action != "" && r.Action != q.Action {
		return false
	}
	if !m(r.Principal, q.Principal) || !m(r.Human, q.Human) || !m(r.Tool, q.Call.Tool) || !m(r.Resource, q.Call.Resource) {
		return false
	}
	if c := r.When; c != nil {
		if c.MaxDepth != nil && q.Depth > *c.MaxDepth {
			return false
		}
		for n, con := range c.Args {
			v, ok := q.Call.Args[n]
			if !con.AllowsArg(v, ok) {
				return false
			}
		}
		if len(c.HoursUTC) == 2 && (q.HourUTC < c.HoursUTC[0] || q.HourUTC >= c.HoursUTC[1]) {
			return false
		}
	}
	return true
}

// Evaluate applies deny-overrides.
func (s *Set) Evaluate(q Request) Decision {
	if s == nil {
		return Decision{Allow: false, Reason: "no policy loaded (default deny)"}
	}
	var permit *Rule
	for i := range s.Rules {
		r := &s.Rules[i]
		if !r.matches(q) {
			continue
		}
		if r.Effect == "forbid" {
			return Decision{Allow: false, Reason: "forbidden by rule " + r.ID, RuleID: r.ID}
		}
		if permit == nil || r.AllowDepth > permit.AllowDepth {
			permit = r
		}
	}
	if permit == nil {
		return Decision{Allow: false, Reason: "no permit rule matched (default deny)"}
	}
	return Decision{Allow: true, Reason: "permitted by rule " + permit.ID, RuleID: permit.ID, AllowDepth: permit.AllowDepth}
}

// Forbids lists forbid rules that could apply to a principal/human for the
// given tool (used by the blast-radius view).
func (s *Set) Forbids(principal, human string) []Rule {
	if s == nil {
		return nil
	}
	var out []Rule
	for _, r := range s.Rules {
		if r.Effect == "forbid" && (r.Action == "" || r.Action == ActionCall) && m(r.Principal, principal) && m(r.Human, human) {
			out = append(out, r)
		}
	}
	return out
}
