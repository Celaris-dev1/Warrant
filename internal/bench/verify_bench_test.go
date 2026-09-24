// Package bench holds latency benchmarks for the hot verification paths:
// a plain capability token, a holder-bound (PoP) token, and a 3-block
// offline-attenuated chain. Run with:
//
//	go test ./internal/bench/... -bench . -benchmem
//
// Results are recorded in docs/benchmarks.md.
package bench

import (
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/attenuate"
	"github.com/Celaris-dev1/Warrant/internal/pop"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

var baseScopes = []token.Scope{{Tool: "fs.*", Resources: []string{"repo/*"}, MaxCalls: 10}}

func BenchmarkVerifyPlainToken(b *testing.B) {
	signer, _ := token.NewSigner(nil)
	c := token.Claims{ID: token.NewID(), Subject: "spiffe://x/workload/a/i1", Human: "h",
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), Scopes: baseScopes, Kind: "capability"}
	tok, err := signer.Sign(c)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := token.Verify(signer.Pub, tok, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPoPToken(b *testing.B) {
	signer, _ := token.NewSigner(nil)
	holderPub, holderPriv, err := pop.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	c := token.Claims{ID: token.NewID(), Subject: "spiffe://x/workload/a/i1", Human: "h",
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), Scopes: baseScopes, Kind: "capability",
		Cnf: &token.Cnf{JKT: token.Thumbprint(holderPub)}}
	tok, err := signer.Sign(c)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now()
		tc, err := token.Verify(signer.Pub, tok, now)
		if err != nil {
			b.Fatal(err)
		}
		proof, err := pop.Sign(holderPriv, tc.ID, "pep", "POST", "/call/fs.read", 30*time.Second, now)
		if err != nil {
			b.Fatal(err)
		}
		// A fresh replay store per iteration: benchmark verification cost,
		// not an ever-growing map (a real PEP process amortizes this).
		rs := pop.NewMemoryReplayStore()
		if _, err := pop.Verify(holderPub, proof, tc, "pep", now, rs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAttenuatedChain3Blocks(b *testing.B) {
	signer, _ := token.NewSigner(nil)
	c := token.Claims{ID: token.NewID(), Subject: "spiffe://x/workload/a/i1", Human: "h",
		IssuedAt: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), Scopes: baseScopes, Kind: "capability"}
	tok, err := signer.Sign(c)
	if err != nil {
		b.Fatal(err)
	}
	_, holderPriv, err := pop.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	chain := attenuate.New(tok)
	steps := [][]token.Scope{
		{{Tool: "fs.*", Resources: []string{"repo/docs/*"}, MaxCalls: 8}},
		{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 5}},
		{{Tool: "fs.read", Resources: []string{"repo/docs/intro*"}, MaxCalls: 2}},
	}
	for _, s := range steps {
		chain, err = chain.Append(holderPriv, s, 0, "")
		if err != nil {
			b.Fatal(err)
		}
	}
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := attenuate.Verify(signer.Pub, chain, now); err != nil {
			b.Fatal(err)
		}
	}
}
