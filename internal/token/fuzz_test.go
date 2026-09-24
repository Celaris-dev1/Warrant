package token

import (
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary strings to token parsing/verification. It must
// never panic: malformed input is always a normal error, never a crash.
func FuzzVerify(f *testing.F) {
	signer, _ := NewSigner(nil)
	good, _ := signer.Sign(Claims{ID: "x", Subject: "s", Human: "h",
		Expires: time.Now().Add(time.Hour).Unix(), Scopes: []Scope{{Tool: "t", Resources: []string{"*"}, MaxCalls: 1}}})
	f.Add(good)
	f.Add("")
	f.Add("a.b.c")
	f.Add("...")
	f.Add(good + "x")
	f.Add(good[:len(good)/2])
	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked on input %q: %v", s, r)
			}
		}()
		_, _ = Verify(signer.Pub, s, time.Now())
	})
}

// FuzzPatternIntersect must never panic on arbitrary (even malformed) two-
// pattern input, and its result — when it reports one — must be internally
// consistent (a valid subset of both operands).
func FuzzPatternIntersect(f *testing.F) {
	f.Add("fs.*", "fs.read")
	f.Add("*", "*")
	f.Add("", "")
	f.Add("a*b*c", "a")
	f.Fuzz(func(t *testing.T, a, b string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PatternIntersect panicked on (%q,%q): %v", a, b, r)
			}
		}()
		p, ok := PatternIntersect(a, b)
		if !ok {
			return
		}
		if ValidatePattern(a) != nil || ValidatePattern(b) != nil {
			return // intersect on malformed patterns has no subset contract
		}
		if !PatternSubset(p, a) || !PatternSubset(p, b) {
			t.Fatalf("intersection %q of (%q,%q) is not a subset of both", p, a, b)
		}
	})
}
