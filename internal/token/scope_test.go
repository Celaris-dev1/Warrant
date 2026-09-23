package token

import (
	"math/rand"
	"testing"
	"time"
)

var (
	toolAtoms = []string{"fs.read", "fs.write", "fs.*", "http.get", "http.*", "*", "db.query", "d*"}
	resAtoms  = []string{"*", "repo/*", "repo/a/*", "repo/a/x", "repo/b/*", "repo/b/y", "s3://bkt/*", "s3://bkt/k"}
	strVals   = []string{"x", "y", "z", "ab", "ac", "b"}
	callTools = []string{"fs.read", "fs.write", "http.get", "db.query", "shell"}
	callRes   = []string{"repo/a/x", "repo/a/z", "repo/b/y", "s3://bkt/k", "other"}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

func fptr(f float64) *float64 { return &f }

func randConstraint(r *rand.Rand) ArgConstraint {
	var c ArgConstraint
	if r.Intn(2) == 0 {
		n := r.Intn(4)
		c.Enum = []string{}
		for i := 0; i < n; i++ {
			c.Enum = append(c.Enum, pick(r, strVals))
		}
		c.EnumSet = true
	}
	if r.Intn(3) == 0 {
		c.Pattern = pick(r, []string{"a*", "ab", "*", "b*"})
	}
	if r.Intn(3) == 0 {
		c.Min = fptr(float64(r.Intn(10)))
	}
	if r.Intn(3) == 0 {
		c.Max = fptr(float64(r.Intn(10)))
	}
	return c
}

func randScope(r *rand.Rand) Scope {
	s := Scope{Tool: pick(r, toolAtoms), MaxCalls: 1 + r.Intn(20), RequireApproval: r.Intn(4) == 0}
	for i := 0; i <= r.Intn(3); i++ {
		s.Resources = append(s.Resources, pick(r, resAtoms))
	}
	if r.Intn(2) == 0 {
		s.Args = map[string]ArgConstraint{}
		for _, n := range []string{"mode", "n"} {
			if r.Intn(2) == 0 {
				s.Args[n] = randConstraint(r)
			}
		}
	}
	return s
}

func randScopes(r *rand.Rand) []Scope {
	var out []Scope
	for i := 0; i <= r.Intn(3); i++ {
		out = append(out, randScope(r))
	}
	return out
}

func randCall(r *rand.Rand) Call {
	c := Call{Tool: pick(r, callTools), Resource: pick(r, callRes), Args: map[string]any{}}
	if r.Intn(4) != 0 {
		if r.Intn(2) == 0 {
			c.Args["mode"] = pick(r, strVals)
		} else {
			c.Args["mode"] = float64(r.Intn(10))
		}
	}
	if r.Intn(4) != 0 {
		if r.Intn(3) == 0 {
			c.Args["n"] = pick(r, strVals)
		} else {
			c.Args["n"] = float64(r.Intn(10))
		}
	}
	return c
}

func allows(scopes []Scope, c Call) bool { return FirstMatch(scopes, c) >= 0 }

// Property: attenuation never widens. For random parent/requested scope sets
// and random calls, anything the child allows the parent allows; every child
// scope is structurally a subset of some parent scope; budgets never grow;
// approval requirements are never dropped.
func TestPropertyAttenuationNeverWidens(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	seed := r.Int63()
	r = rand.New(rand.NewSource(seed))
	for i := 0; i < 20000; i++ {
		parent := randScopes(r)
		req := randScopes(r)
		child := Attenuate(parent, req)
		if !ScopesSubset(child, parent) {
			t.Fatalf("seed %d: child not structural subset\nparent=%+v\nreq=%+v\nchild=%+v", seed, parent, req, child)
		}
		for j := 0; j < 30; j++ {
			c := randCall(r)
			if i := FirstMatch(child, c); i >= 0 {
				if !allows(parent, c) {
					t.Fatalf("seed %d: child allows %+v but parent does not\nparent=%+v\nchild=%+v", seed, c, parent, child)
				}
				if !allows(req, c) {
					t.Fatalf("seed %d: child allows %+v beyond request", seed, c)
				}
				// approval never dropped: if every parent scope admitting c
				// requires approval, the child scope must too.
				needs := true
				for _, p := range parent {
					if p.Allows(c) && !p.RequireApproval {
						needs = false
					}
				}
				if needs && !child[i].RequireApproval {
					t.Fatalf("seed %d: approval requirement dropped", seed)
				}
			}
		}
		// repeated attenuation (multi-hop) is still a subset of the root
		grand := Attenuate(child, randScopes(r))
		if !ScopesSubset(grand, parent) {
			t.Fatalf("seed %d: grandchild escaped root", seed)
		}
	}
}

// Property: Intersect is the exact intersection on sampled calls.
func TestPropertyIntersectIsExact(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 20000; i++ {
		a, b := randScope(r), randScope(r)
		s, ok := Intersect(a, b)
		for j := 0; j < 30; j++ {
			c := randCall(r)
			both := a.Allows(c) && b.Allows(c)
			got := ok && s.Allows(c)
			if got && !both {
				t.Fatalf("intersection widened: a=%+v b=%+v s=%+v c=%+v", a, b, s, c)
			}
			if both && !got {
				t.Fatalf("intersection lost a call: a=%+v b=%+v s=%+v c=%+v", a, b, s, c)
			}
		}
		if ok && (s.MaxCalls > a.MaxCalls || s.MaxCalls > b.MaxCalls) {
			t.Fatal("budget widened")
		}
	}
}

// Property: Subset is sound w.r.t. Allows.
func TestPropertySubsetSound(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 50000; i++ {
		a, b := randScope(r), randScope(r)
		if !a.Subset(b) {
			continue
		}
		for j := 0; j < 30; j++ {
			c := randCall(r)
			if a.Allows(c) && !b.Allows(c) {
				t.Fatalf("Subset unsound: a=%+v b=%+v c=%+v", a, b, c)
			}
		}
	}
}

func TestPatterns(t *testing.T) {
	cases := []struct {
		c, p string
		want bool
	}{{"fs.read", "fs.*", true}, {"fs.*", "fs.read", false}, {"fs.*", "*", true}, {"*", "fs.*", false}, {"a", "a", true}, {"fs.r*", "fs.*", true}}
	for _, tc := range cases {
		if PatternSubset(tc.c, tc.p) != tc.want {
			t.Errorf("PatternSubset(%q,%q) != %v", tc.c, tc.p, tc.want)
		}
	}
	if ValidatePattern("a*b") == nil {
		t.Error("infix wildcard should be rejected")
	}
}

func TestSignVerify(t *testing.T) {
	s, _ := NewSigner(nil)
	now := time.Now()
	tok, err := s.Sign(Claims{ID: "x", Expires: now.Add(time.Minute).Unix(), Kind: "capability"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s.Pub, tok, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s.Pub, tok, now.Add(2*time.Minute)); err != ErrExpired {
		t.Fatalf("want expired, got %v", err)
	}
	other, _ := NewSigner(nil)
	if _, err := Verify(other.Pub, tok, now); err != ErrSignature {
		t.Fatalf("want bad sig, got %v", err)
	}
	tampered := tok[:len(tok)-3] + "AAA"
	if _, err := Verify(s.Pub, tampered, now); err == nil {
		t.Fatal("tampered token verified")
	}
}

func TestActionHashCanonical(t *testing.T) {
	a := ActionHash(Call{Tool: "t", Resource: "r", Args: map[string]any{"b": 1.0, "a": "x"}})
	b := ActionHash(Call{Tool: "t", Resource: "r", Args: map[string]any{"a": "x", "b": 1}})
	if a != b {
		t.Fatal("hash not canonical")
	}
	c := ActionHash(Call{Tool: "t", Resource: "r", Args: map[string]any{"a": "x", "b": 2}})
	if a == c {
		t.Fatal("hash collision on different args")
	}
}
