package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims are the body of a Warrant capability token.
type Claims struct {
	ID       string  `json:"jti"`
	Issuer   string  `json:"iss"`
	Subject  string  `json:"sub"` // SPIFFE-style workload id of the holder
	Human    string  `json:"human"`
	IssuedAt int64   `json:"iat"`
	Expires  int64   `json:"exp"`
	Parent   string  `json:"parent,omitempty"`
	Chain    []string `json:"chain,omitempty"` // ancestor ids, root first
	Depth    int     `json:"depth"`
	MaxDepth int     `json:"max_depth"`
	MaxCalls int     `json:"max_calls"` // whole-token budget
	Scopes   []Scope `json:"scopes"`
	Kind     string  `json:"kind"` // "capability", "svid" or "approval"
	// Approval-only fields.
	ActionHash string `json:"action_hash,omitempty"`
	Token      string `json:"tok,omitempty"`
}

// Lineage returns chain + self.
func (c Claims) Lineage() []string { return append(append([]string{}, c.Chain...), c.ID) }

// Signer signs and verifies compact EdDSA JWTs.
type Signer struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	KID  string
}

// NewSigner builds a signer from a 32-byte seed, or a fresh key if seed is nil.
func NewSigner(seed []byte) (*Signer, error) {
	var priv ed25519.PrivateKey
	if seed == nil {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = p
	} else {
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("signing seed must be %d bytes", ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return &Signer{Priv: priv, Pub: pub, KID: hex.EncodeToString(h[:8])}, nil
}

var b64 = base64.RawURLEncoding

// Sign encodes and signs claims.
func (s *Signer) Sign(c Claims) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": s.KID})
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	sig := ed25519.Sign(s.Priv, []byte(in))
	return in + "." + b64.EncodeToString(sig), nil
}

// Errors returned by Verify.
var (
	ErrMalformed = errors.New("malformed token")
	ErrSignature = errors.New("bad signature")
	ErrExpired   = errors.New("token expired")
)

// Verify checks signature and expiry (with the given clock) and returns claims.
func Verify(pub ed25519.PublicKey, tok string, now time.Time) (Claims, error) {
	var c Claims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c, ErrMalformed
	}
	var hdr map[string]string
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil || hdr["alg"] != "EdDSA" {
		return c, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return c, ErrMalformed
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrSignature
	}
	bb, err := b64.DecodeString(parts[1])
	if err != nil || json.Unmarshal(bb, &c) != nil {
		return c, ErrMalformed
	}
	if now.Unix() >= c.Expires {
		return c, ErrExpired
	}
	return c, nil
}

// NewID returns a random 128-bit hex id.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
