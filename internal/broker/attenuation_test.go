package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/Celaris-dev1/Warrant/internal/attenuate"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// mintRoot mints a root capability token over the given scopes, returning
// the compact JWT and its claims.
func mintRootTok(t *testing.T, s *Service, svidTok string, scopes []token.Scope) string {
	t.Helper()
	ctx := context.Background()
	iss, err := s.MintRoot(ctx, MintRequest{SVID: svidTok, Human: "h", Scopes: scopes, MaxCalls: 10})
	if err != nil {
		t.Fatal(err)
	}
	return iss.Token
}

func TestAuthorizeAcceptsAttenuationChainNarrowed(t *testing.T) {
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"c","effect":"permit","action":"call"}]}`)
	a := svid(t, s, "a")
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 5}}
	rootTok := mintRootTok(t, s, a, base)

	_, holderPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := attenuate.New(rootTok)
	chain, err = chain.Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 3}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// The narrowed action is allowed.
	d := s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a,
		Call: token.Call{Tool: "fs.read", Resource: "repo/docs/readme.md"}})
	if !d.Allow {
		t.Fatalf("narrowed call should be allowed: %s", d.Reason)
	}

	// Anything the block attenuated away is denied, even though the base
	// token would have allowed it.
	d = s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a,
		Call: token.Call{Tool: "fs.write", Resource: "repo/docs/readme.md"}})
	if d.Allow {
		t.Fatal("call outside the narrowed chain must be denied")
	}
	d = s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a,
		Call: token.Call{Tool: "fs.read", Resource: "repo/other/x"}})
	if d.Allow {
		t.Fatal("resource outside the narrowed chain must be denied")
	}

	// The base token itself still allows the wider action directly (the
	// chain only narrows what THAT credential can do).
	d = s.Authorize(ctx, AuthorizeRequest{Token: rootTok, SVID: a,
		Call: token.Call{Tool: "fs.write", Resource: "repo/x"}})
	if !d.Allow {
		t.Fatalf("base token directly presented should still be governed by its own scopes: %s", d.Reason)
	}
}

func TestAuthorizeDeniesTamperedChain(t *testing.T) {
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"c","effect":"permit","action":"call"}]}`)
	a := svid(t, s, "a")
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 5}}
	rootTok := mintRootTok(t, s, a, base)

	_, holderPriv, _ := ed25519.GenerateKey(nil)
	chain, err := attenuate.New(rootTok).Append(holderPriv,
		[]token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 3}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	// Attempt to widen the resources back out after signing.
	chain.Blocks[0].Scopes[0].Resources = []string{"*"}
	chainJSON, _ := json.Marshal(chain)

	d := s.Authorize(context.Background(), AuthorizeRequest{Token: string(chainJSON), SVID: a,
		Call: token.Call{Tool: "fs.read", Resource: "repo/other/x"}})
	if d.Allow {
		t.Fatal("tampered (widened) chain must be denied")
	}
}

func TestAuthorizeDeniesRevokedBaseViaChain(t *testing.T) {
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"c","effect":"permit","action":"call"}]}`)
	a := svid(t, s, "a")
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 5}}
	ctx := context.Background()
	iss, err := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: base, MaxCalls: 10})
	if err != nil {
		t.Fatal(err)
	}

	_, holderPriv, _ := ed25519.GenerateKey(nil)
	chain, err := attenuate.New(iss.Token).Append(holderPriv,
		[]token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 3}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	chainJSON, _ := json.Marshal(chain)

	if err := s.Revoke(ctx, iss.Claims.ID, "compromised", "admin"); err != nil {
		t.Fatal(err)
	}

	d := s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a,
		Call: token.Call{Tool: "fs.read", Resource: "repo/docs/x"}})
	if d.Allow {
		t.Fatal("revoking the base token must deny a chain built on it")
	}
}

func TestAuthorizeChainSharesBaseBudget(t *testing.T) {
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"c","effect":"permit","action":"call"}]}`)
	a := svid(t, s, "a")
	// A narrow base scope with max_calls 2; the chain narrows resources
	// further but must still be charged against the SAME broker-tracked
	// per-scope counter (index 0 of the base token), not an out-of-range
	// index for a shorter effective scope list.
	base := []token.Scope{{Tool: "fs.read", Resources: []string{"repo/*"}, MaxCalls: 2}}
	rootTok := mintRootTok(t, s, a, base)

	_, holderPriv, _ := ed25519.GenerateKey(nil)
	chain, err := attenuate.New(rootTok).Append(holderPriv,
		[]token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 2}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	chainJSON, _ := json.Marshal(chain)
	ctx := context.Background()
	call := token.Call{Tool: "fs.read", Resource: "repo/docs/x"}

	for i := 0; i < 2; i++ {
		d := s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a, Call: call})
		if !d.Allow {
			t.Fatalf("call %d should be allowed: %s", i, d.Reason)
		}
	}
	// Third call exhausts the base scope's max_calls.
	d := s.Authorize(ctx, AuthorizeRequest{Token: string(chainJSON), SVID: a, Call: call})
	if d.Allow {
		t.Fatal("third call should exhaust the shared base budget")
	}
}

func TestAttenuationChainCnfRebindRequiresCurrentHolderKey(t *testing.T) {
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"c","effect":"permit","action":"call"}]}`)
	a := svid(t, s, "a")
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 5}}
	ctx := context.Background()
	origPub, origPriv, _ := ed25519.GenerateKey(nil)
	iss, err := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: base, MaxCalls: 10,
		Cnf: &token.Cnf{JKT: token.Thumbprint(origPub)}})
	if err != nil {
		t.Fatal(err)
	}

	// A legitimate rebind: signed by the CURRENT holder key.
	newPub, _, _ := ed25519.GenerateKey(nil)
	chain, err := attenuate.New(iss.Token).AppendCnf(origPriv, nil, 0, &token.Cnf{JKT: token.Thumbprint(newPub)}, "")
	if err != nil {
		t.Fatal(err)
	}
	eff, err := attenuate.Verify(s.Signer.Pub, chain, s.Now())
	if err != nil {
		t.Fatal(err)
	}
	if eff.Cnf == nil || eff.Cnf.JKT != token.Thumbprint(newPub) {
		t.Fatal("expected effective cnf to be rebound to the new key")
	}

	// An attacker holding only the chain bytes (not origPriv) cannot rebind
	// to a key of their own.
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	attackerPub, _, _ := ed25519.GenerateKey(nil)
	badChain, err := attenuate.New(iss.Token).AppendCnf(attackerPriv, nil, 0, &token.Cnf{JKT: token.Thumbprint(attackerPub)}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attenuate.Verify(s.Signer.Pub, badChain, s.Now()); err == nil {
		t.Fatal("rebind not signed by the current holder key must be rejected")
	}
}
