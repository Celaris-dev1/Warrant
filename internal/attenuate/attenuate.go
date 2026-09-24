// Package attenuate implements holder-side offline attenuation of a Warrant
// capability token, Biscuit-style: once a holder has a broker-signed token,
// it can append signed "blocks" that further narrow scopes/resources/args
// and shorten the expiry, without contacting the broker at all. Each block
// is cryptographically chained to the one before it (and to the base
// token's own signature), so blocks cannot be reordered, dropped, or
// spliced from a different chain. A verifier that only trusts the broker's
// public key can still check the whole chain and is structurally guaranteed
// that every block is narrower-than-or-equal to its parent: attenuation can
// only take authority away, never add it, regardless of who signed a block
// or what key they used.
package attenuate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

var b64 = base64.RawURLEncoding

// Block is one holder-appended attenuation step. Scopes, if non-nil, is
// intersected with the current effective scopes (never unioned): anything
// not expressible as an intersection of the parent authority is simply
// dropped, exactly like broker-side Attenuate. Expires, if non-zero,
// further caps (never extends) the effective expiry.
type Block struct {
	Scopes  []token.Scope `json:"scopes,omitempty"`
	Expires int64         `json:"expires,omitempty"`
	// Cnf, if set, rebinds the chain's effective proof-of-possession holder
	// key to a new key. To prevent a bearer of the chain bytes from
	// hijacking PoP protection by rebinding to a key of their own choosing,
	// Verify requires that a block setting Cnf be signed (Signer/Signature)
	// by the key matching the CURRENT effective cnf (i.e. only someone who
	// already holds the current holder's private key can hand off to a new
	// one). If the chain is not yet holder-bound (no cnf in force), any
	// signer may introduce one.
	Cnf       *token.Cnf        `json:"cnf,omitempty"`
	Nonce     string            `json:"nonce"`
	Signer    ed25519.PublicKey `json:"signer"` // key that signs THIS block
	PrevSig   []byte            `json:"prev_sig"` // signature of the previous link (block or base token)
	Signature []byte            `json:"signature"` // over the block's canonical bytes, excluding Signature itself
}

func (b Block) signingBytes() ([]byte, error) {
	cp := b
	cp.Signature = nil
	return json.Marshal(cp)
}

// Chain is a base capability token plus zero or more attenuation blocks.
type Chain struct {
	BaseToken string  `json:"base_token"` // the compact broker-signed JWT
	Blocks    []Block `json:"blocks,omitempty"`
}

// baseSig returns the signature bytes of the base JWT (its third segment),
// which anchors the first block's PrevSig, chaining attenuation to this
// exact token and not some other one with the same claims.
func baseSig(compactJWT string) ([]byte, error) {
	parts := splitJWT(compactJWT)
	if len(parts) != 3 {
		return nil, errors.New("attenuate: malformed base token")
	}
	return b64.DecodeString(parts[2])
}

func splitJWT(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// New starts a chain from a broker-issued token, no blocks yet.
func New(baseToken string) Chain { return Chain{BaseToken: baseToken} }

// Append signs and adds a new attenuation block on top of the chain's
// current tip, using priv (any Ed25519 key the holder controls — it need
// not be, and normally isn't, the broker's signing key). The block is only
// cryptographically well-formed here; call Verify to check that it is also
// a legitimate narrowing.
func (c Chain) Append(priv ed25519.PrivateKey, scopes []token.Scope, expires int64, nonce string) (Chain, error) {
	return c.appendBlock(priv, scopes, expires, nil, nonce)
}

// AppendCnf is like Append but additionally rebinds the chain's effective
// proof-of-possession holder key to cnf. priv must be the CURRENT holder's
// private key (matching the chain's effective cnf so far), unless the chain
// is not yet holder-bound, in which case any key may introduce the first
// cnf. Verify enforces this at check time; Append itself only produces a
// well-formed (but not yet verified) block.
func (c Chain) AppendCnf(priv ed25519.PrivateKey, scopes []token.Scope, expires int64, cnf *token.Cnf, nonce string) (Chain, error) {
	return c.appendBlock(priv, scopes, expires, cnf, nonce)
}

func (c Chain) appendBlock(priv ed25519.PrivateKey, scopes []token.Scope, expires int64, cnf *token.Cnf, nonce string) (Chain, error) {
	var prevSig []byte
	var err error
	if n := len(c.Blocks); n > 0 {
		prevSig = c.Blocks[n-1].Signature
	} else {
		prevSig, err = baseSig(c.BaseToken)
		if err != nil {
			return c, err
		}
	}
	if nonce == "" {
		nonce = token.NewID()
	}
	b := Block{Scopes: scopes, Expires: expires, Cnf: cnf, Nonce: nonce,
		Signer: priv.Public().(ed25519.PublicKey), PrevSig: prevSig}
	sb, err := b.signingBytes()
	if err != nil {
		return c, err
	}
	b.Signature = ed25519.Sign(priv, sb)
	out := c
	out.Blocks = append(append([]Block{}, c.Blocks...), b)
	return out, nil
}

// Errors returned by Verify.
var (
	ErrBaseSignature = errors.New("attenuate: base token signature invalid")
	ErrBaseExpired   = errors.New("attenuate: base token expired")
	ErrBlockSig      = errors.New("attenuate: block signature invalid")
	ErrChainBroken   = errors.New("attenuate: block not linked to previous link")
	ErrWidened       = errors.New("attenuate: block would widen authority")
	ErrEmpty         = errors.New("attenuate: attenuation produced empty authority")
)

// Effective is the outcome of verifying a chain: the narrowed scopes and
// expiry actually in force, and the base claims for anything else
// (subject, human, revocation lineage, etc).
type Effective struct {
	Base    token.Claims
	Scopes  []token.Scope
	Expires int64
	// Cnf is the effective proof-of-possession holder key in force: the
	// base token's cnf, unless a block rebound it (see Block.Cnf).
	Cnf *token.Cnf
	// Origins maps each entry of Scopes back to the index in Base.Scopes it
	// descends from, so a verifier can charge budget against the broker's
	// own per-scope counters (which are indexed by base scope) while still
	// enforcing the narrower, offline-attenuated effective scope.
	Origins []int
}

// Verify checks the base token against brokerPub, then walks every block:
// its signature, its chain link to the previous block/base, and — the
// core property — that its resulting scopes are a subset of (never wider
// than) the scopes in force before it, and its expiry only ever shrinks.
// now is used for both the base token's expiry and (implicitly, via
// Expires) the chain's final effective expiry, which the caller should
// also compare against now.
func Verify(brokerPub ed25519.PublicKey, c Chain, now time.Time) (Effective, error) {
	base, err := token.Verify(brokerPub, c.BaseToken, now)
	if err != nil {
		if errors.Is(err, token.ErrExpired) {
			return Effective{}, ErrBaseExpired
		}
		return Effective{}, fmt.Errorf("%w: %v", ErrBaseSignature, err)
	}
	origins := make([]int, len(base.Scopes))
	for i := range origins {
		origins[i] = i
	}
	eff := Effective{Base: base, Scopes: base.Scopes, Expires: base.Expires, Cnf: base.Cnf, Origins: origins}
	prevSig, err := baseSig(c.BaseToken)
	if err != nil {
		return Effective{}, err
	}
	for i, b := range c.Blocks {
		if !bytesEqual(b.PrevSig, prevSig) {
			return Effective{}, fmt.Errorf("%w (block %d)", ErrChainBroken, i)
		}
		sb, err := b.signingBytes()
		if err != nil {
			return Effective{}, err
		}
		if len(b.Signer) != ed25519.PublicKeySize || !ed25519.Verify(b.Signer, sb, b.Signature) {
			return Effective{}, fmt.Errorf("%w (block %d)", ErrBlockSig, i)
		}
		newScopes := eff.Scopes
		newOrigins := eff.Origins
		if b.Scopes != nil {
			newScopes, newOrigins = attenuateWithOrigin(eff.Scopes, eff.Origins, b.Scopes)
			if len(newScopes) == 0 {
				return Effective{}, fmt.Errorf("%w (block %d)", ErrEmpty, i)
			}
			// Attenuate (structural intersection) is narrowing by
			// construction, but double-check explicitly: it is the
			// property this whole package exists to guarantee.
			if !token.ScopesSubset(newScopes, eff.Scopes) {
				return Effective{}, fmt.Errorf("%w (block %d)", ErrWidened, i)
			}
		}
		newExpires := eff.Expires
		if b.Expires != 0 {
			if b.Expires > eff.Expires {
				return Effective{}, fmt.Errorf("%w (block %d): expires cannot grow", ErrWidened, i)
			}
			newExpires = b.Expires
		}
		if b.Cnf != nil {
			// Rebinding is only legitimate if it is authorized by the
			// CURRENT holder: the block must be signed by the key that
			// matches the effective cnf in force so far. Otherwise anyone
			// who merely possesses the bearer chain bytes could rebind PoP
			// protection to a key of their own and defeat it entirely.
			if eff.Cnf != nil && token.Thumbprint(b.Signer) != eff.Cnf.JKT {
				return Effective{}, fmt.Errorf("%w (block %d): cnf rebind not signed by current holder key", ErrWidened, i)
			}
			eff.Cnf = b.Cnf
		}
		eff.Scopes, eff.Origins, eff.Expires = newScopes, newOrigins, newExpires
		prevSig = b.Signature
	}
	if now.Unix() >= eff.Expires {
		return Effective{}, ErrBaseExpired
	}
	return eff, nil
}

// attenuateWithOrigin mirrors token.Attenuate's structural intersection
// (for each requested scope, intersect against every current effective
// scope) while tracking, for every resulting scope, which base-token scope
// index it ultimately descends from.
func attenuateWithOrigin(parent []token.Scope, parentOrigins []int, requested []token.Scope) ([]token.Scope, []int) {
	var out []token.Scope
	var origins []int
	for _, r := range requested {
		for i, p := range parent {
			if s, ok := token.Intersect(r, p); ok {
				out = append(out, s)
				origins = append(origins, parentOrigins[i])
			}
		}
	}
	return out, origins
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
