package policy

import "testing"

// FuzzParse feeds arbitrary bytes as a policy document. Parse must never
// panic on malformed/adversarial JSON — always a normal error.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"rules":[{"id":"m","effect":"permit","action":"mint"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"rules":[{"tool":"a*b*c"}]}`))
	f.Add([]byte(`{"rules":[{"effect":"forbid","when":{"max_depth":-1}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse panicked on input %q: %v", b, r)
			}
		}()
		_, _ = Parse(b)
	})
}
