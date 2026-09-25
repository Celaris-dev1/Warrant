// Package token implements Warrant capability tokens: scopes, structural
// attenuation (intersection), and Ed25519-signed JWT encoding.
package token

import (
	"errors"
	"sort"
	"strings"
)

// Pattern is a glob restricted to two forms so that subset and intersection
// are decidable structurally:
//   - a literal string ("fs.read", "repo/acme/api"), matching exactly itself
//   - a prefix wildcard ending in a single trailing "*" ("fs.*", "repo/acme/*"),
//     matching every string with that prefix. "*" alone matches everything.
//
// Any other use of "*" is rejected by ValidatePattern.
type Pattern = string

// ValidatePattern reports whether p is a well-formed pattern.
func ValidatePattern(p string) error {
	if p == "" {
		return errors.New("empty pattern")
	}
	if i := strings.Index(p, "*"); i >= 0 && i != len(p)-1 {
		return errors.New("pattern may only contain a single trailing '*': " + p)
	}
	return nil
}

func isWild(p string) bool   { return strings.HasSuffix(p, "*") }
func prefix(p string) string { return strings.TrimSuffix(p, "*") }

// Match reports whether s matches pattern p.
//
// A prefix wildcard never matches a subject that could escape the prefix once
// a tool resolves it ("repo/acme/docs/../secrets", "%2e%2e", "a\\..\\b"):
// Warrant denies those itself rather than trusting every caller to clean paths.
func Match(p, s string) bool {
	if isWild(p) {
		return strings.HasPrefix(s, prefix(p)) && !escapesPrefix(s)
	}
	return p == s
}

// escapesPrefix reports whether s contains a traversal or encoding trick.
func escapesPrefix(s string) bool {
	if strings.ContainsAny(s, "\\\x00") {
		return true
	}
	l := strings.ToLower(s)
	if strings.Contains(l, "%2e") || strings.Contains(l, "%2f") || strings.Contains(l, "%5c") || strings.Contains(l, "%00") {
		return true
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// PatternSubset reports whether every string matched by child is matched by parent.
func PatternSubset(child, parent string) bool {
	if !isWild(parent) {
		return !isWild(child) && child == parent
	}
	return strings.HasPrefix(prefix(child), prefix(parent))
}

// PatternIntersect returns the pattern matching exactly the strings matched
// by both a and b, and false if that set is empty.
func PatternIntersect(a, b string) (string, bool) {
	if PatternSubset(a, b) {
		return a, true
	}
	if PatternSubset(b, a) {
		return b, true
	}
	return "", false
}

// ArgConstraint restricts one named argument of a tool call. All set fields
// must hold. Values are compared as strings (Enum, Pattern) or numbers (Min, Max).
type ArgConstraint struct {
	Enum    []string `json:"enum,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
	// Enum == nil means unconstrained; EnumSet distinguishes "enum: []"
	// (nothing allowed) after an empty intersection.
	EnumSet bool `json:"enum_set,omitempty"`
}

// Scope is one grant: a tool, the resources it may touch, argument
// constraints, a per-scope call budget and whether each call needs a
// human approval bound to its exact action hash.
type Scope struct {
	Tool            string                   `json:"tool"`
	Resources       []string                 `json:"resources,omitempty"`
	Args            map[string]ArgConstraint `json:"args,omitempty"`
	MaxCalls        int                      `json:"max_calls"`
	RequireApproval bool                     `json:"require_approval,omitempty"`
}

// Validate checks a scope is well-formed.
func (s Scope) Validate() error {
	if err := ValidatePattern(s.Tool); err != nil {
		return err
	}
	if len(s.Resources) == 0 {
		return errors.New("scope must list at least one resource pattern (use \"*\" for any)")
	}
	for _, r := range s.Resources {
		if err := ValidatePattern(r); err != nil {
			return err
		}
	}
	for _, c := range s.Args {
		if c.Pattern != "" {
			if err := ValidatePattern(c.Pattern); err != nil {
				return err
			}
		}
	}
	if s.MaxCalls <= 0 {
		return errors.New("max_calls must be > 0")
	}
	return nil
}

// Call is a concrete tool invocation presented at the PEP.
type Call struct {
	Tool     string         `json:"tool"`
	Resource string         `json:"resource"`
	Args     map[string]any `json:"args"`
}

// AllowsArg reports whether value v satisfies the constraint.
func (c ArgConstraint) AllowsArg(v any, present bool) bool {
	if !present {
		// A constrained argument must be supplied; otherwise a callee
		// default could bypass the constraint.
		return false
	}
	if c.Enum != nil || c.EnumSet {
		s, ok := asString(v)
		if !ok {
			return false
		}
		found := false
		for _, e := range c.Enum {
			if e == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if c.Pattern != "" {
		s, ok := asString(v)
		if !ok || !Match(c.Pattern, s) {
			return false
		}
	}
	if c.Min != nil || c.Max != nil {
		f, ok := v.(float64)
		if !ok {
			if i, ok2 := v.(int); ok2 {
				f, ok = float64(i), true
			}
		}
		if !ok {
			return false
		}
		if c.Min != nil && f < *c.Min {
			return false
		}
		if c.Max != nil && f > *c.Max {
			return false
		}
	}
	return true
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// Allows reports whether the scope (ignoring call budgets) admits the call.
func (s Scope) Allows(c Call) bool {
	if !Match(s.Tool, c.Tool) {
		return false
	}
	ok := false
	for _, r := range s.Resources {
		if Match(r, c.Resource) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for name, con := range s.Args {
		v, present := c.Args[name]
		if !con.AllowsArg(v, present) {
			return false
		}
	}
	return true
}

func argSubset(child, parent ArgConstraint) bool {
	if parent.Enum != nil || parent.EnumSet {
		if child.Enum == nil && !child.EnumSet {
			return false
		}
		for _, e := range child.Enum {
			if !contains(parent.Enum, e) {
				return false
			}
		}
	}
	if parent.Pattern != "" {
		if child.Pattern == "" {
			// a child enum whose every member matches the parent pattern is narrower
			if child.Enum == nil && !child.EnumSet {
				return false
			}
			for _, e := range child.Enum {
				if !Match(parent.Pattern, e) {
					return false
				}
			}
		} else if !PatternSubset(child.Pattern, parent.Pattern) {
			return false
		}
	}
	if parent.Min != nil && (child.Min == nil || *child.Min < *parent.Min) {
		return false
	}
	if parent.Max != nil && (child.Max == nil || *child.Max > *parent.Max) {
		return false
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Subset reports whether child is narrower than or equal to parent.
func (child Scope) Subset(parent Scope) bool {
	if !PatternSubset(child.Tool, parent.Tool) {
		return false
	}
	for _, cr := range child.Resources {
		ok := false
		for _, pr := range parent.Resources {
			if PatternSubset(cr, pr) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for name, pc := range parent.Args {
		cc, ok := child.Args[name]
		if !ok || !argSubset(cc, pc) {
			return false
		}
	}
	if child.MaxCalls > parent.MaxCalls {
		return false
	}
	if parent.RequireApproval && !child.RequireApproval {
		return false
	}
	return true
}

func intersectArg(a, b ArgConstraint) ArgConstraint {
	var out ArgConstraint
	switch {
	case (a.Enum != nil || a.EnumSet) && (b.Enum != nil || b.EnumSet):
		out.Enum = []string{}
		for _, e := range a.Enum {
			if contains(b.Enum, e) {
				out.Enum = append(out.Enum, e)
			}
		}
		out.EnumSet = true
	case a.Enum != nil || a.EnumSet:
		out.Enum, out.EnumSet = append([]string{}, a.Enum...), true
	case b.Enum != nil || b.EnumSet:
		out.Enum, out.EnumSet = append([]string{}, b.Enum...), true
	}
	switch {
	case a.Pattern != "" && b.Pattern != "":
		if p, ok := PatternIntersect(a.Pattern, b.Pattern); ok {
			out.Pattern = p
		} else {
			out.Enum, out.EnumSet = []string{}, true // empty set
		}
	case a.Pattern != "":
		out.Pattern = a.Pattern
	case b.Pattern != "":
		out.Pattern = b.Pattern
	}
	// Normalise: fold the pattern into the enum when both are present.
	if out.EnumSet && out.Pattern != "" {
		kept := []string{}
		for _, e := range out.Enum {
			if Match(out.Pattern, e) {
				kept = append(kept, e)
			}
		}
		out.Enum, out.Pattern = kept, ""
	}
	out.Min = maxPtr(a.Min, b.Min)
	out.Max = minPtr(a.Max, b.Max)
	return out
}

func maxPtr(a, b *float64) *float64 {
	if a == nil {
		return cp(b)
	}
	if b == nil || *a >= *b {
		return cp(a)
	}
	return cp(b)
}

func minPtr(a, b *float64) *float64 {
	if a == nil {
		return cp(b)
	}
	if b == nil || *a <= *b {
		return cp(a)
	}
	return cp(b)
}

func cp(f *float64) *float64 {
	if f == nil {
		return nil
	}
	v := *f
	return &v
}

// Intersect computes the scope admitting exactly the calls admitted by both
// a and b (budget = min, approval = either). Returns false if empty.
func Intersect(a, b Scope) (Scope, bool) {
	tool, ok := PatternIntersect(a.Tool, b.Tool)
	if !ok {
		return Scope{}, false
	}
	var res []string
	seen := map[string]bool{}
	for _, ra := range a.Resources {
		for _, rb := range b.Resources {
			if r, ok := PatternIntersect(ra, rb); ok && !seen[r] {
				seen[r] = true
				res = append(res, r)
			}
		}
	}
	if len(res) == 0 {
		return Scope{}, false
	}
	sort.Strings(res)
	args := map[string]ArgConstraint{}
	for n, c := range a.Args {
		args[n] = c
	}
	for n, c := range b.Args {
		if prev, ok := args[n]; ok {
			args[n] = intersectArg(prev, c)
		} else {
			args[n] = c
		}
	}
	for _, c := range args {
		if c.EnumSet && len(c.Enum) == 0 {
			return Scope{}, false
		}
		if c.Min != nil && c.Max != nil && *c.Min > *c.Max {
			return Scope{}, false
		}
	}
	if len(args) == 0 {
		args = nil
	}
	mc := a.MaxCalls
	if b.MaxCalls < mc {
		mc = b.MaxCalls
	}
	if mc <= 0 {
		return Scope{}, false
	}
	return Scope{Tool: tool, Resources: res, Args: args, MaxCalls: mc,
		RequireApproval: a.RequireApproval || b.RequireApproval}, true
}

// Attenuate structurally computes the authority granted to a delegate: every
// requested scope is intersected with every parent scope and only non-empty
// intersections survive. The result is always a subset of parent (see
// property tests); it never depends on the requester being honest.
func Attenuate(parent, requested []Scope) []Scope {
	var out []Scope
	for _, r := range requested {
		for _, p := range parent {
			if s, ok := Intersect(r, p); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ScopesSubset reports whether every child scope is contained in some parent scope.
func ScopesSubset(child, parent []Scope) bool {
	for _, c := range child {
		ok := false
		for _, p := range parent {
			if c.Subset(p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// FirstMatch returns the index of the first scope allowing the call, or -1.
func FirstMatch(scopes []Scope, c Call) int {
	for i, s := range scopes {
		if s.Allows(c) {
			return i
		}
	}
	return -1
}
