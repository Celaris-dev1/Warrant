package pop

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

// signClaims signs arbitrary (possibly out-of-policy, e.g. over-long TTL)
// claims directly, bypassing Sign's clamping, to test that Verify itself
// enforces the invariants rather than relying on a well-behaved signer.
func signClaims(t *testing.T, priv ed25519.PrivateKey, c Claims) string {
	t.Helper()
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "pop+jwt"})
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(in))
	return in + "." + b64.EncodeToString(sig)
}

func mkToken(t *testing.T, jkt string) token.Claims {
	t.Helper()
	return token.Claims{ID: token.NewID(), Cnf: &token.Cnf{JKT: jkt}}
}

func TestVerifyAcceptsFreshValidProof(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, err := Sign(priv, tc.ID, "pep:8431", "POST", "/call/fs.read", 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, proof, tc, "pep:8431", now.Add(time.Second), rs); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, _ := Sign(priv, tc.ID, "aud", "GET", "/x", 30*time.Second, now)
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, proof, tc, "aud", now, rs); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if _, err := Verify(pub, proof, tc, "aud", now, rs); err != ErrReplay {
		t.Fatalf("second use should be a replay, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, _ := Sign(priv, tc.ID, "aud", "GET", "/x", 5*time.Second, now)
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, proof, tc, "aud", now.Add(10*time.Second), rs); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, _ := Sign(priv, tc.ID, "aud-a", "GET", "/x", 30*time.Second, now)
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, proof, tc, "aud-b", now, rs); err != ErrAudience {
		t.Fatalf("want ErrAudience, got %v", err)
	}
}

func TestVerifyRejectsWrongToken(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	other := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, _ := Sign(priv, tc.ID, "aud", "GET", "/x", 30*time.Second, now)
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, proof, other, "aud", now, rs); err != ErrTokenMismatch {
		t.Fatalf("want ErrTokenMismatch, got %v", err)
	}
}

// TestVerifyRejectsKeyMismatch is the core PoP guarantee: a token alone (no
// private key) cannot produce a valid proof, since the verifier requires
// the proof's signer to match the token's cnf/jkt. A leaked token is
// useless to an attacker who does not also have the holder's private key.
func TestVerifyRejectsKeyMismatch(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))

	attackerPub, attackerPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proof, _ := Sign(attackerPriv, tc.ID, "aud", "GET", "/x", 30*time.Second, now)
	rs := NewMemoryReplayStore()
	if _, err := Verify(attackerPub, proof, tc, "aud", now, rs); err != ErrKeyMismatch {
		t.Fatalf("want ErrKeyMismatch (proof key doesn't match token cnf), got %v", err)
	}
}

func TestVerifyRejectsTamperedProof(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	proof, _ := Sign(priv, tc.ID, "aud", "GET", "/x", 30*time.Second, now)
	tampered := proof[:len(proof)-2] + "AA"
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, tampered, tc, "aud", now, rs); err == nil {
		t.Fatal("tampered proof accepted")
	}
}

func TestVerifyRejectsTTLTooLong(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tc := mkToken(t, Thumbprint(pub))
	now := time.Now()
	// Sign clamps to MaxTTL, so hand-build a proof claiming a longer TTL.
	proof, _ := Sign(priv, tc.ID, "aud", "GET", "/x", MaxTTL, now)
	_ = proof
	// Directly construct claims with excessive TTL and sign them to prove
	// Verify enforces the cap even if a client sends one.
	c := Claims{Jti: "n1", Sub: Thumbprint(pub), Aud: "aud", TokenJTI: tc.ID,
		IssuedAt: now.Unix(), Expires: now.Add(10 * time.Minute).Unix()}
	forged := signClaims(t, priv, c)
	rs := NewMemoryReplayStore()
	if _, err := Verify(pub, forged, tc, "aud", now, rs); err != ErrTooLong {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}
