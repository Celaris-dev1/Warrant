// Package pop implements holder-bound proof-of-possession for Warrant
// capability tokens (RFC 7800 "cnf"/"jkt" style, RFC 9449 DPoP-flavored
// proof). A holder-bound token (token.Claims.Cnf != nil) is useless on its
// own: the caller must additionally present a short-lived, single-use proof
// signed by the private key matching the token's cnf/jkt thumbprint, bound
// to the specific request (method + path) and a verifier-chosen audience.
// A verifier rejects a replayed proof (same jti) via ReplaySeen.
package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

var b64 = base64.RawURLEncoding

// MaxTTL bounds how long a proof may claim to be valid for. Verify rejects
// anything longer, regardless of what the proof itself says, so a stolen
// *signed proof* (not just a stolen token) has a small blast radius too.
const MaxTTL = 60 * time.Second

// Claims are the body of a PoP proof: who is proving possession (Sub, the
// same holder public key thumbprint as the token's cnf/jkt), for which
// request (Method+Path, and the token's own jti so a proof can't be
// replayed against a different token), for which audience (Aud, normally
// the PEP's own identity or the tool name), and a nonce (Jti) for replay
// detection.
type Claims struct {
	Jti      string `json:"jti"`
	Sub      string `json:"sub"` // cnf/jkt thumbprint of the signer
	Aud      string `json:"aud"`
	Method   string `json:"htm,omitempty"`
	Path     string `json:"htu,omitempty"`
	TokenJTI string `json:"tid,omitempty"` // the capability token this proof accompanies
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// GenerateKey returns a fresh Ed25519 holder keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Thumbprint is an alias of token.Thumbprint kept local for readability.
func Thumbprint(pub ed25519.PublicKey) string { return token.Thumbprint(pub) }

// Sign builds and signs a proof for the given request/token/audience, valid
// for ttl (capped to MaxTTL).
func Sign(priv ed25519.PrivateKey, tokenJTI, aud, method, path string, ttl time.Duration, now time.Time) (string, error) {
	if ttl <= 0 || ttl > MaxTTL {
		ttl = MaxTTL
	}
	pub := priv.Public().(ed25519.PublicKey)
	c := Claims{
		Jti: newNonce(), Sub: Thumbprint(pub), Aud: aud, Method: method, Path: path,
		TokenJTI: tokenJTI, IssuedAt: now.Unix(), Expires: now.Add(ttl).Unix(),
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "pop+jwt"})
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(in))
	return in + "." + b64.EncodeToString(sig), nil
}

// Errors returned by Verify.
var (
	ErrMalformed    = errors.New("pop: malformed proof")
	ErrSignature    = errors.New("pop: bad signature")
	ErrExpired      = errors.New("pop: expired")
	ErrTooLong      = errors.New("pop: ttl exceeds max")
	ErrAudience     = errors.New("pop: audience mismatch")
	ErrTokenMismatch = errors.New("pop: not bound to this token")
	ErrReplay       = errors.New("pop: replayed proof")
	ErrKeyMismatch  = errors.New("pop: proof key does not match token cnf")
)

// ReplayStore records proof ids so each can be accepted only once. Seen must
// be safe for concurrent use.
type ReplayStore interface {
	// Seen atomically checks whether jti has been observed before expires,
	// and if not, records it. Returns true if this is a replay.
	Seen(jti string, expires time.Time) bool
}

// Verify checks a proof's signature, freshness, audience and binding to the
// given holder-bound token claims (tc.Cnf), and enforces replay protection
// via rs. The public key used for signature verification is the one
// embedded in the request by the caller (pub) — the verifier is expected to
// have obtained it out of band (e.g. from the same SVID/mTLS channel that
// presented the token) or, for the common case, the holder key registered
// at delegation time; VerifyAgainstToken below does that lookup for you
// given the raw key.
func Verify(pub ed25519.PublicKey, proof string, tc token.Claims, aud string, now time.Time, rs ReplayStore) (Claims, error) {
	var c Claims
	if tc.Cnf == nil {
		return c, errors.New("pop: token is not holder-bound (no cnf)")
	}
	if Thumbprint(pub) != tc.Cnf.JKT {
		return c, ErrKeyMismatch
	}
	i := strings.IndexByte(proof, '.')
	if i < 0 {
		return c, ErrMalformed
	}
	j := strings.IndexByte(proof[i+1:], '.')
	if j < 0 {
		return c, ErrMalformed
	}
	j += i + 1
	hdrPart, bodyPart, sigPart := proof[:i], proof[i+1:j], proof[j+1:]
	if strings.IndexByte(sigPart, '.') >= 0 {
		return c, ErrMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	hb, err := b64.DecodeString(hdrPart)
	if err != nil || json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" {
		return c, ErrMalformed
	}
	sig, err := b64.DecodeString(sigPart)
	if err != nil {
		return c, ErrMalformed
	}
	if !ed25519.Verify(pub, token.UnsafeBytes(proof[:j]), sig) {
		return c, ErrSignature
	}
	bb, err := b64.DecodeString(bodyPart)
	if err != nil || json.Unmarshal(bb, &c) != nil {
		return c, ErrMalformed
	}
	if c.Sub != tc.Cnf.JKT {
		return c, ErrKeyMismatch
	}
	if c.Expires-c.IssuedAt > int64(MaxTTL.Seconds()) {
		return c, ErrTooLong
	}
	if now.Unix() >= c.Expires {
		return c, ErrExpired
	}
	if c.Aud != aud {
		return c, ErrAudience
	}
	if c.TokenJTI != "" && c.TokenJTI != tc.ID {
		return c, ErrTokenMismatch
	}
	if rs != nil && rs.Seen(c.Jti, time.Unix(c.Expires, 0)) {
		return c, ErrReplay
	}
	return c, nil
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
