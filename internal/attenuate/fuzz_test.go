package attenuate

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

// FuzzVerifyChain feeds arbitrary JSON as a Chain to Verify. Must never
// panic, regardless of how malformed the input is.
func FuzzVerifyChain(f *testing.F) {
	signer, _ := token.NewSigner(nil)
	base := mkBaseForFuzz(signer)
	_, holderPriv, _ := ed25519.GenerateKey(nil)
	c, _ := New(base).Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"*"}, MaxCalls: 1}}, 0, "")
	good, _ := json.Marshal(c)
	f.Add(string(good))
	f.Add("{}")
	f.Add(`{"base_token":"x"}`)
	f.Add(`{"base_token":"` + base + `","blocks":[{}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Verify panicked on input %q: %v", s, r)
			}
		}()
		var chain Chain
		if json.Unmarshal([]byte(s), &chain) != nil {
			return
		}
		_, _ = Verify(signer.Pub, chain, time.Now())
	})
}

func mkBaseForFuzz(signer *token.Signer) string {
	c := token.Claims{ID: token.NewID(), Subject: "s", Human: "h",
		Expires: time.Now().Add(time.Hour).Unix(), Scopes: []token.Scope{{Tool: "fs.*", Resources: []string{"*"}, MaxCalls: 5}}}
	tok, _ := signer.Sign(c)
	return tok
}
