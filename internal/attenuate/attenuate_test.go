package attenuate

import (
	"crypto/ed25519"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

func mkBase(t *testing.T, signer *token.Signer, scopes []token.Scope, ttl time.Duration) string {
	t.Helper()
	c := token.Claims{ID: token.NewID(), Subject: "spiffe://x/workload/a/i1", Human: "h",
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(ttl).Unix(), Scopes: scopes, Kind: "capability"}
	tok, err := signer.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAppendAndVerifyNarrows(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 10}}
	tok := mkBase(t, signer, base, time.Hour)
	holderPub, holderPriv, _ := ed25519.GenerateKey(nil)
	_ = holderPub

	c := New(tok)
	c, err := c.Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 3}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	eff, err := Verify(signer.Pub, c, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(eff.Scopes) != 1 || eff.Scopes[0].Tool != "fs.read" || eff.Scopes[0].MaxCalls != 3 {
		t.Fatalf("unexpected effective scopes: %+v", eff.Scopes)
	}
}

func TestVerifyRejectsTamperedBlock(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 10}}
	tok := mkBase(t, signer, base, time.Hour)
	_, holderPriv, _ := ed25519.GenerateKey(nil)

	c := New(tok)
	c, err := c.Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 3}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	// Tamper: an attacker with the token (but not the holder key) tries to
	// widen resources back out after the fact.
	c.Blocks[0].Scopes[0].Resources = []string{"*"}
	if _, err := Verify(signer.Pub, c, time.Now()); !errors.Is(err, ErrBlockSig) {
		t.Fatalf("want ErrBlockSig for tampered block, got %v", err)
	}
}

func TestVerifyRejectsReorderedOrSplicedBlocks(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 10}}
	tokA := mkBase(t, signer, base, time.Hour)
	tokB := mkBase(t, signer, base, time.Hour)
	_, holderPriv, _ := ed25519.GenerateKey(nil)

	chainA, err := New(tokA).Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"repo/*"}, MaxCalls: 5}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	chainB, err := New(tokB).Append(holderPriv, []token.Scope{{Tool: "fs.write", Resources: []string{"repo/*"}, MaxCalls: 5}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	// Splice: attach chain B's block onto chain A's base token.
	spliced := Chain{BaseToken: tokA, Blocks: chainB.Blocks}
	if _, err := Verify(signer.Pub, spliced, time.Now()); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("want ErrChainBroken for spliced chain, got %v", err)
	}
	_ = chainA
}

func TestVerifyRejectsExpiryExtension(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	base := []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 10}}
	tok := mkBase(t, signer, base, time.Hour)
	_, holderPriv, _ := ed25519.GenerateKey(nil)

	// First block narrows expiry to 1 minute.
	c, err := New(tok).Append(holderPriv, nil, time.Now().Add(time.Minute).Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Second block tries to extend it back to an hour.
	c, err = c.Append(holderPriv, nil, time.Now().Add(time.Hour).Unix(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signer.Pub, c, time.Now()); !errors.Is(err, ErrWidened) {
		t.Fatalf("want ErrWidened for expiry extension, got %v", err)
	}
}

func TestVerifyRejectsEmptyIntersection(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	base := []token.Scope{{Tool: "fs.read", Resources: []string{"repo/a/*"}, MaxCalls: 10}}
	tok := mkBase(t, signer, base, time.Hour)
	_, holderPriv, _ := ed25519.GenerateKey(nil)

	c, err := New(tok).Append(holderPriv, []token.Scope{{Tool: "fs.read", Resources: []string{"repo/b/*"}, MaxCalls: 5}}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signer.Pub, c, time.Now()); !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty for disjoint resources, got %v", err)
	}
}

// TestMonotonicNarrowingProperty is the core guarantee: for any random
// sequence of holder-appended blocks, the final effective scopes are always
// a subset of the base token's scopes (never wider, on any dimension), or
// verification fails outright.
func TestMonotonicNarrowingProperty(t *testing.T) {
	signer, _ := token.NewSigner(nil)
	rng := rand.New(rand.NewSource(1))
	tools := []string{"fs.read", "fs.write", "fs.*", "net.*", "db.exec"}
	resources := []string{"repo/a", "repo/a/*", "repo/*", "*", "db/prod"}

	randScope := func() token.Scope {
		return token.Scope{Tool: tools[rng.Intn(len(tools))], Resources: []string{resources[rng.Intn(len(resources))]},
			MaxCalls: 1 + rng.Intn(20)}
	}

	for iter := 0; iter < 200; iter++ {
		base := []token.Scope{randScope(), randScope()}
		tok := mkBase(t, signer, base, time.Hour)
		_, holderPriv, _ := ed25519.GenerateKey(nil)
		c := New(tok)
		nBlocks := rng.Intn(4)
		for i := 0; i < nBlocks; i++ {
			var err error
			c, err = c.Append(holderPriv, []token.Scope{randScope()}, 0, "")
			if err != nil {
				t.Fatal(err)
			}
		}
		eff, err := Verify(signer.Pub, c, time.Now())
		if err != nil {
			// A disjoint random intersection is expected sometimes; any
			// other verify failure is a bug.
			if !errors.Is(err, ErrEmpty) {
				t.Fatalf("iter %d: unexpected verify error: %v", iter, err)
			}
			continue
		}
		if !token.ScopesSubset(eff.Scopes, base) {
			t.Fatalf("iter %d: effective scopes %+v not a subset of base %+v", iter, eff.Scopes, base)
		}
	}
}
