// Package broker implements the Warrant capability broker: workload
// identity, root mint, attenuated delegation, action-hash-bound approvals,
// authorization (used by the PEP), revocation and blast radius.
package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/attenuate"
	"github.com/Celaris-dev1/Warrant/internal/ledger"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/receipt"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// receiptKinds maps the ledger record types this service emits to a stack-receipt/v1 "kind",
// for the subset that are genuine authorization decisions (issuance, allow, deny, revoke) worth
// a signed cross-product receipt. Bookkeeping types (e.g. workload registration) are skipped.
var receiptKinds = map[string]string{
	"warrant.token.issued":  "warrant.decision",
	"warrant.token.revoked": "warrant.decision",
	"warrant.call.allowed":  "warrant.decision",
	"warrant.call.denied":   "warrant.decision",
}

// Config holds broker settings.
type Config struct {
	TrustDomain string        // e.g. "warrant.local"
	MaxDepth    int           // default depth cap (1): root may delegate once, delegates may not
	MaxTTL      time.Duration // cap on any capability token TTL
	DefaultTTL  time.Duration
	SVIDTTL     time.Duration
	ApprovalTTL time.Duration
}

// Service is the broker core. HTTP handlers and the PEP are thin wrappers.
type Service struct {
	Cfg    Config
	Store  store.Store
	Signer *token.Signer
	Policy *policy.Set
	Ledger ledger.Recorder
	Now    func() time.Time
}

// Errors.
var (
	ErrBadSecret   = errors.New("workload attestation failed")
	ErrDepth       = errors.New("delegation depth cap reached")
	ErrEmptyScope  = errors.New("requested scope does not intersect parent authority")
	ErrRevoked     = errors.New("token revoked")
	ErrWrongKind   = errors.New("wrong token kind")
	ErrBinding     = errors.New("svid does not match token subject")
	ErrPolicy      = errors.New("denied by policy")
	ErrNoScope     = errors.New("no scope in token allows this call")
	ErrApproval    = errors.New("approval required for this exact call")
	ErrBadRequest  = errors.New("bad request")
)

// New fills defaults.
func New(cfg Config, st store.Store, s *token.Signer, p *policy.Set, l ledger.Recorder) *Service {
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "warrant.local"
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 1
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 15 * time.Minute
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.SVIDTTL == 0 {
		cfg.SVIDTTL = 10 * time.Minute
	}
	if cfg.ApprovalTTL == 0 {
		cfg.ApprovalTTL = 5 * time.Minute
	}
	if l == nil {
		l = ledger.Noop{}
	}
	return &Service{Cfg: cfg, Store: st, Signer: s, Policy: p, Ledger: l, Now: time.Now}
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte("warrant-workload:" + s))
	return hex.EncodeToString(h[:])
}

func (s *Service) policyVersion() string {
	if s.Policy == nil {
		return ""
	}
	return s.Policy.Version
}

func (s *Service) record(ctx context.Context, typ, human string, agents []string, payload map[string]any) {
	chain := []ledger.Actor{{Kind: "human", ID: human}}
	for _, a := range agents {
		if a != "" {
			chain = append(chain, ledger.Actor{Kind: "agent", ID: a})
		}
	}
	if human == "" {
		chain[0].ID = "unknown"
	}
	if kind, ok := receiptKinds[typ]; ok {
		s.attachReceipt(ctx, kind, chain, payload)
	}
	err := s.Ledger.Record(ctx, ledger.Record{Chain: "warrant", Type: typ, ActorChain: chain,
		PolicyVersion: s.policyVersion(), Payload: payload, GoalID: strOf(payload["goal_id"])})
	if err != nil {
		log.Printf("ledger: %s: %v", typ, err)
	}
}

// attachReceipt signs a stack-receipt/v1 envelope over payload and sets payload["receipt"] to
// it, so Ledger stores and the incident report verify it alongside the record itself. It never
// fails the caller: a receipt is evidence in addition to the ledger record, not a precondition
// for recording the decision.
func (s *Service) attachReceipt(ctx context.Context, kind string, actors []ledger.Actor, payload map[string]any) {
	if s.Signer == nil || s.Signer.Priv == nil {
		return
	}
	ph, err := receipt.PayloadHash(payload)
	if err != nil {
		log.Printf("receipt: payload_hash: %v", err)
		return
	}
	racts := make([]receipt.Actor, len(actors))
	for i, a := range actors {
		racts[i] = receipt.Actor{Kind: a.Kind, ID: a.ID, Model: a.Model, ModelVersion: a.ModelVersion}
	}
	subject := strOf(payload["token_id"])
	env, err := receipt.Sign(ctx, receipt.Ed25519Signer{Key: s.Signer.Priv}, receipt.Envelope{
		Product: "warrant", Kind: kind, GoalID: strOf(payload["goal_id"]), Actors: racts,
		Subject: subject, PayloadHash: ph,
	})
	if err != nil {
		log.Printf("receipt: sign: %v", err)
		return
	}
	payload["receipt"] = env
}

func strOf(v any) string { s, _ := v.(string); return s }

// RegisterWorkload registers (or rotates) a workload's attestation secret.
func (s *Service) RegisterWorkload(ctx context.Context, name, secret string) error {
	if name == "" || strings.ContainsAny(name, "/*") || len(secret) < 16 {
		return fmt.Errorf("%w: name must be non-empty without '/' or '*', secret >= 16 chars", ErrBadRequest)
	}
	return s.Store.PutWorkload(ctx, store.Workload{Name: name, SecretHash: hashSecret(secret)})
}

// SpiffeID builds the workload id.
func (s *Service) SpiffeID(workload, instance string) string {
	return "spiffe://" + s.Cfg.TrustDomain + "/workload/" + workload + "/" + instance
}

// IssueSVID attests a workload instance by its registration secret and
// returns a short-lived JWT-SVID bound to that instance.
func (s *Service) IssueSVID(ctx context.Context, workload, secret, instance string) (string, token.Claims, error) {
	w, err := s.Store.GetWorkload(ctx, workload)
	if err != nil || subtle.ConstantTimeCompare([]byte(w.SecretHash), []byte(hashSecret(secret))) != 1 {
		return "", token.Claims{}, ErrBadSecret
	}
	if instance == "" {
		instance = token.NewID()[:12]
	}
	if strings.ContainsAny(instance, "/*") {
		return "", token.Claims{}, fmt.Errorf("%w: bad instance", ErrBadRequest)
	}
	now := s.Now()
	c := token.Claims{ID: token.NewID(), Issuer: s.issuer(), Subject: s.SpiffeID(workload, instance), IssuedAt: now.Unix(),
		Expires: now.Add(s.Cfg.SVIDTTL).Unix(), Kind: "svid"}
	t, err := s.Signer.Sign(c)
	return t, c, err
}

func (s *Service) issuer() string { return "spiffe://" + s.Cfg.TrustDomain + "/warrantd" }

func (s *Service) verifyKind(tok, kind string) (token.Claims, error) {
	c, err := token.Verify(s.Signer.Pub, tok, s.Now())
	if err != nil {
		return c, err
	}
	if c.Kind != kind {
		return c, ErrWrongKind
	}
	return c, nil
}

// MintRequest asks for a root token.
type MintRequest struct {
	SVID     string        `json:"svid"`
	Human    string        `json:"human"`
	Scopes   []token.Scope `json:"scopes"`
	TTL      int           `json:"ttl_seconds"`
	MaxCalls int           `json:"max_calls"`
	MaxDepth int           `json:"max_depth"`
	GoalID   string        `json:"goal_id,omitempty"`
	// Cnf, if set, holder-binds the issued token to a public key (PoP
	// required at the PEP for every call; see internal/pop).
	Cnf *token.Cnf `json:"cnf,omitempty"`
}

// Issued is returned for any new capability token.
type Issued struct {
	Token  string       `json:"token"`
	Claims token.Claims `json:"claims"`
}

func (s *Service) ttl(req int, ceiling time.Time) time.Time {
	d := s.Cfg.DefaultTTL
	if req > 0 {
		d = time.Duration(req) * time.Second
	}
	if d > s.Cfg.MaxTTL {
		d = s.Cfg.MaxTTL
	}
	exp := s.Now().Add(d)
	if !ceiling.IsZero() && exp.After(ceiling) {
		exp = ceiling
	}
	return exp
}

func sumCalls(sc []token.Scope) int {
	n := 0
	for _, x := range sc {
		n += x.MaxCalls
	}
	return n
}

// MintRoot issues a root capability token to an attested workload on behalf
// of an originating human. Caller must be an administrator (checked by HTTP).
func (s *Service) MintRoot(ctx context.Context, r MintRequest) (Issued, error) {
	svid, err := s.verifyKind(r.SVID, "svid")
	if err != nil {
		return Issued{}, fmt.Errorf("svid: %w", err)
	}
	if r.Human == "" || len(r.Scopes) == 0 {
		return Issued{}, fmt.Errorf("%w: human and scopes are required", ErrBadRequest)
	}
	maxAllowDepth := s.Cfg.MaxDepth
	for _, sc := range r.Scopes {
		if err := sc.Validate(); err != nil {
			return Issued{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
		for _, res := range sc.Resources {
			d := s.Policy.Evaluate(policy.Request{Action: policy.ActionMint, Principal: svid.Subject, Human: r.Human,
				Call: token.Call{Tool: sc.Tool, Resource: res}, HourUTC: s.Now().UTC().Hour()})
			if !d.Allow {
				return Issued{}, fmt.Errorf("%w: mint %s on %s: %s", ErrPolicy, sc.Tool, res, d.Reason)
			}
			if d.AllowDepth > maxAllowDepth {
				maxAllowDepth = d.AllowDepth
			}
		}
	}
	md := r.MaxDepth
	if md <= 0 {
		md = s.Cfg.MaxDepth
	}
	if md > maxAllowDepth {
		return Issued{}, fmt.Errorf("%w: max_depth %d exceeds cap %d (raise via policy allow_depth)", ErrDepth, md, maxAllowDepth)
	}
	mc := r.MaxCalls
	if total := sumCalls(r.Scopes); mc <= 0 || mc > total {
		mc = total
	}
	now := s.Now()
	c := token.Claims{ID: token.NewID(), Issuer: s.issuer(), Subject: svid.Subject, Human: r.Human, IssuedAt: now.Unix(),
		Expires: s.ttl(r.TTL, time.Unix(svid.Expires, 0)).Unix(), Depth: 0, MaxDepth: md, MaxCalls: mc, Scopes: r.Scopes, Kind: "capability",
		ParentActor: svid.Subject, GoalID: r.GoalID, Cnf: r.Cnf}
	iss, err := s.persist(ctx, c)
	if err != nil {
		return Issued{}, err
	}
	s.record(ctx, "warrant.token.issued", c.Human, []string{c.Subject}, map[string]any{
		"token_id": c.ID, "subject": c.Subject, "depth": 0, "max_depth": md, "max_calls": mc,
		"expires": c.Expires, "scopes": c.Scopes, "goal_id": r.GoalID})
	return iss, nil
}

func (s *Service) persist(ctx context.Context, c token.Claims) (Issued, error) {
	tok, err := s.Signer.Sign(c)
	if err != nil {
		return Issued{}, err
	}
	raw, _ := json.Marshal(c)
	limits := make([]int, len(c.Scopes))
	for i, sc := range c.Scopes {
		limits[i] = sc.MaxCalls
	}
	err = s.Store.PutToken(ctx, store.TokenRecord{ID: c.ID, Parent: c.Parent, ParentActor: c.ParentActor, GoalID: c.GoalID,
		Subject: c.Subject, Human: c.Human, Depth: c.Depth,
		MaxCalls: c.MaxCalls, ScopeLimits: limits, Expires: time.Unix(c.Expires, 0), Claims: raw})
	if err != nil {
		return Issued{}, err
	}
	return Issued{Token: tok, Claims: c}, nil
}

// checkLive verifies a capability token and that no token in its lineage is
// revoked.
func (s *Service) checkLive(ctx context.Context, tok string) (token.Claims, error) {
	if looksLikeAttenuationChain(tok) {
		return s.checkLiveChain(ctx, tok)
	}
	c, err := s.verifyKind(tok, "capability")
	if err != nil {
		return c, err
	}
	r, err := s.Store.FirstRevoked(ctx, c.Lineage())
	if err != nil {
		return c, err
	}
	if r != "" {
		return c, fmt.Errorf("%w (%s)", ErrRevoked, r)
	}
	return c, nil
}

// looksLikeAttenuationChain distinguishes an offline attenuation chain
// (internal/attenuate.Chain, presented as a JSON object) from a compact
// broker-signed JWT.
func looksLikeAttenuationChain(tok string) bool {
	t := strings.TrimSpace(tok)
	return strings.HasPrefix(t, "{")
}

// checkLiveChain verifies an offline-attenuated credential (see
// internal/attenuate): the base token's signature/expiry, every block's
// signature and chain linkage, and that the chain only ever narrows
// authority. The returned Claims carry the chain's EFFECTIVE (narrowed)
// scopes, expiry and cnf, plus ScopeOrigins mapping each effective scope
// back to the base token's own scope index so the broker's existing
// per-scope call budgets (indexed by base scope) still apply.
func (s *Service) checkLiveChain(ctx context.Context, tok string) (token.Claims, error) {
	var chain attenuate.Chain
	if err := json.Unmarshal([]byte(tok), &chain); err != nil {
		return token.Claims{}, fmt.Errorf("bad attenuation chain: %w", err)
	}
	eff, err := attenuate.Verify(s.Signer.Pub, chain, s.Now())
	if err != nil {
		return token.Claims{}, err
	}
	c := eff.Base
	if c.Kind != "capability" {
		return c, ErrWrongKind
	}
	r, err := s.Store.FirstRevoked(ctx, c.Lineage())
	if err != nil {
		return c, err
	}
	if r != "" {
		return c, fmt.Errorf("%w (%s)", ErrRevoked, r)
	}
	c.Scopes = eff.Scopes
	c.Expires = eff.Expires
	c.Cnf = eff.Cnf
	c.ScopeOrigins = eff.Origins
	return c, nil
}

// DelegateRequest asks for an attenuated child token.
type DelegateRequest struct {
	ParentToken string        `json:"parent_token"`
	ParentSVID  string        `json:"parent_svid"`
	ChildSVID   string        `json:"child_svid"`
	Scopes      []token.Scope `json:"scopes"`
	TTL         int           `json:"ttl_seconds"`
	MaxCalls    int           `json:"max_calls"`
	MaxDepth    int           `json:"max_depth"`
	GoalID      string        `json:"goal_id,omitempty"`
	// Cnf, if set, holder-binds the child token to a (typically fresh, the
	// child's own) public key. If unset, the child is not holder-bound even
	// if the parent was — attenuation only narrows authority, it never
	// forces a binding requirement the requester didn't ask for.
	Cnf *token.Cnf `json:"cnf,omitempty"`
}

// Delegate issues B a token that is the structural intersection of A's
// authority and what was requested: narrower-or-equal scopes, TTL no longer
// than A's remaining, call budget no more than A's remaining.
func (s *Service) Delegate(ctx context.Context, r DelegateRequest) (Issued, error) {
	parent, err := s.checkLive(ctx, r.ParentToken)
	if err != nil {
		return Issued{}, fmt.Errorf("parent: %w", err)
	}
	psvid, err := s.verifyKind(r.ParentSVID, "svid")
	if err != nil {
		return Issued{}, fmt.Errorf("parent svid: %w", err)
	}
	if psvid.Subject != parent.Subject {
		return Issued{}, ErrBinding
	}
	csvid, err := s.verifyKind(r.ChildSVID, "svid")
	if err != nil {
		return Issued{}, fmt.Errorf("child svid: %w", err)
	}
	depth := parent.Depth + 1
	if depth > parent.MaxDepth {
		s.record(ctx, "warrant.call.denied", parent.Human, []string{parent.Subject, csvid.Subject}, map[string]any{
			"token_id": parent.ID, "action": "delegate", "reason": ErrDepth.Error(), "depth": depth, "max_depth": parent.MaxDepth})
		return Issued{}, fmt.Errorf("%w: depth %d > max_depth %d", ErrDepth, depth, parent.MaxDepth)
	}
	d := s.Policy.Evaluate(policy.Request{Action: policy.ActionDelegate, Principal: parent.Subject, Human: parent.Human,
		Depth: depth, Call: token.Call{Tool: "", Resource: csvid.Subject}, HourUTC: s.Now().UTC().Hour()})
	if !d.Allow {
		return Issued{}, fmt.Errorf("%w: %s", ErrPolicy, d.Reason)
	}
	for _, sc := range r.Scopes {
		if err := sc.Validate(); err != nil {
			return Issued{}, fmt.Errorf("%w: %v", ErrBadRequest, err)
		}
	}
	scopes := token.Attenuate(parent.Scopes, r.Scopes)
	if len(scopes) == 0 {
		return Issued{}, ErrEmptyScope
	}
	used, _, err := s.Store.Usage(ctx, parent.ID)
	if err != nil {
		return Issued{}, err
	}
	remaining := parent.MaxCalls - used
	mc := r.MaxCalls
	if mc <= 0 || mc > remaining {
		mc = remaining
	}
	if t := sumCalls(scopes); mc > t {
		mc = t
	}
	if mc <= 0 {
		return Issued{}, store.ErrExhausted{Which: "parent has no remaining calls"}
	}
	md := parent.MaxDepth
	if r.MaxDepth > 0 && r.MaxDepth < md {
		md = r.MaxDepth
	}
	now := s.Now()
	goalID := r.GoalID
	if goalID == "" {
		// Inherit the goal from the parent so the whole chain stays
		// attributable to the same originating task even when a delegate
		// omits goal_id.
		goalID = parent.GoalID
	}
	c := token.Claims{ID: token.NewID(), Issuer: s.issuer(), Subject: csvid.Subject, Human: parent.Human, IssuedAt: now.Unix(),
		Expires: s.ttl(r.TTL, time.Unix(parent.Expires, 0)).Unix(), Parent: parent.ID, Chain: parent.Lineage(),
		Depth: depth, MaxDepth: md, MaxCalls: mc, Scopes: scopes, Kind: "capability",
		ParentActor: parent.Subject, GoalID: goalID, Cnf: r.Cnf}
	if c.Expires > csvid.Expires {
		c.Expires = csvid.Expires
	}
	iss, err := s.persist(ctx, c)
	if err != nil {
		return Issued{}, err
	}
	s.record(ctx, "warrant.token.issued", c.Human, []string{parent.Subject, c.Subject}, map[string]any{
		"token_id": c.ID, "parent_id": parent.ID, "subject": c.Subject, "depth": depth, "max_depth": md,
		"parent_scopes": parent.Scopes, "requested_scopes": r.Scopes, "scopes": scopes,
		"parent_max_calls_remaining": remaining, "max_calls": mc,
		"parent_expires": parent.Expires, "expires": c.Expires, "goal_id": goalID, "parent_actor": parent.Subject})
	return iss, nil
}

// ApproveRequest asks for an approval bound to one exact call.
type ApproveRequest struct {
	TokenID  string     `json:"token_id"`
	Call     token.Call `json:"call"`
	Approver string     `json:"approver"`
	TTL      int        `json:"ttl_seconds"`
}

// Approval is a signed, single-use approval for sha256(canonical call).
type Approval struct {
	Approval   string `json:"approval"`
	ActionHash string `json:"action_hash"`
	Expires    int64  `json:"expires"`
}

// Approve signs an approval for exactly one call on one token.
func (s *Service) Approve(ctx context.Context, r ApproveRequest) (Approval, error) {
	if r.TokenID == "" || r.Approver == "" || r.Call.Tool == "" {
		return Approval{}, fmt.Errorf("%w: token_id, approver and call.tool required", ErrBadRequest)
	}
	if _, err := s.Store.GetToken(ctx, r.TokenID); err != nil {
		return Approval{}, err
	}
	d := s.Cfg.ApprovalTTL
	if r.TTL > 0 && time.Duration(r.TTL)*time.Second < d {
		d = time.Duration(r.TTL) * time.Second
	}
	h := token.ActionHash(r.Call)
	now := s.Now()
	c := token.Claims{ID: token.NewID(), Issuer: s.issuer(), Subject: r.Approver, Human: r.Approver, IssuedAt: now.Unix(),
		Expires: now.Add(d).Unix(), Kind: "approval", ActionHash: h, Token: r.TokenID}
	t, err := s.Signer.Sign(c)
	return Approval{Approval: t, ActionHash: h, Expires: c.Expires}, err
}

// AuthorizeRequest is one tool call presented for enforcement.
type AuthorizeRequest struct {
	Token    string     `json:"token"`
	SVID     string     `json:"svid"`
	Approval string     `json:"approval,omitempty"`
	Call     token.Call `json:"call"`
}

// Decision is the PEP verdict.
type Decision struct {
	Allow      bool         `json:"allow"`
	Reason     string       `json:"reason"`
	TokenID    string       `json:"token_id,omitempty"`
	ScopeIndex int          `json:"scope_index"`
	ActionHash string       `json:"action_hash"`
	Claims     token.Claims `json:"-"`
}

// Authorize is the single enforcement decision: token signature/expiry,
// lineage revocation, workload binding, scope match, policy, approval, and
// atomic call-budget consumption. Every decision is recorded to Ledger.
func (s *Service) Authorize(ctx context.Context, r AuthorizeRequest) Decision {
	d := s.authorize(ctx, r)
	typ := "warrant.call.allowed"
	if !d.Allow {
		typ = "warrant.call.denied"
	}
	s.record(ctx, typ, d.Claims.Human, []string{d.Claims.Subject}, map[string]any{
		"token_id": d.Claims.ID, "depth": d.Claims.Depth, "tool": r.Call.Tool, "resource": r.Call.Resource,
		"action_hash": d.ActionHash, "reason": d.Reason, "scope_index": d.ScopeIndex})
	return d
}

func (s *Service) authorize(ctx context.Context, r AuthorizeRequest) Decision {
	d := Decision{ScopeIndex: -1, ActionHash: token.ActionHash(r.Call)}
	deny := func(err error) Decision { d.Reason = err.Error(); return d }
	c, err := s.checkLive(ctx, r.Token)
	d.Claims, d.TokenID = c, c.ID
	if err != nil {
		return deny(err)
	}
	svid, err := s.verifyKind(r.SVID, "svid")
	if err != nil {
		return deny(fmt.Errorf("svid: %w", err))
	}
	if svid.Subject != c.Subject {
		return deny(ErrBinding)
	}
	idx := token.FirstMatch(c.Scopes, r.Call)
	if idx < 0 {
		return deny(ErrNoScope)
	}
	d.ScopeIndex = idx
	pd := s.Policy.Evaluate(policy.Request{Action: policy.ActionCall, Principal: c.Subject, Human: c.Human, Depth: c.Depth,
		Call: r.Call, HourUTC: s.Now().UTC().Hour()})
	if !pd.Allow {
		return deny(fmt.Errorf("%w: %s", ErrPolicy, pd.Reason))
	}
	if c.Scopes[idx].RequireApproval {
		if r.Approval == "" {
			return deny(ErrApproval)
		}
		a, err := s.verifyKind(r.Approval, "approval")
		if err != nil {
			return deny(fmt.Errorf("approval: %w", err))
		}
		if a.Token != c.ID || a.ActionHash != d.ActionHash {
			return deny(fmt.Errorf("%w: approval bound to a different action or token", ErrApproval))
		}
		ok, err := s.Store.UseApproval(ctx, a.ID, time.Unix(a.Expires, 0))
		if err != nil {
			return deny(err)
		}
		if !ok {
			return deny(fmt.Errorf("%w: approval already used", ErrApproval))
		}
	}
	// A chain's effective scopes may be reordered/narrowed relative to the
	// base token's stored (and budgeted) scopes; ScopeOrigins maps the
	// matched effective index back to the base scope the broker actually
	// tracks a counter for.
	consumeIdx := idx
	if len(c.ScopeOrigins) == len(c.Scopes) {
		consumeIdx = c.ScopeOrigins[idx]
	}
	if err := s.Store.Consume(ctx, c.ID, consumeIdx, c.Lineage()); err != nil {
		return deny(err)
	}
	d.Allow, d.Reason = true, pd.Reason
	return d
}

// Peek verifies a presented credential (a plain capability token or an
// offline attenuation chain) and its SVID binding WITHOUT evaluating policy
// or consuming any call budget. It exists for read-only, non-authorizing
// uses like filtering a tool listing down to what a credential's scopes
// would even structurally allow; it must never be used to permit an actual
// tool call.
func (s *Service) Peek(ctx context.Context, tok, svidTok string) (token.Claims, error) {
	c, err := s.checkLive(ctx, tok)
	if err != nil {
		return c, err
	}
	svid, err := s.verifyKind(svidTok, "svid")
	if err != nil {
		return c, fmt.Errorf("svid: %w", err)
	}
	if svid.Subject != c.Subject {
		return c, ErrBinding
	}
	return c, nil
}

// Revoke adds a token (and so its whole subtree) to the revoke list.
func (s *Service) Revoke(ctx context.Context, id, reason, by string) error {
	t, err := s.Store.GetToken(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Store.Revoke(ctx, id, reason); err != nil {
		return err
	}
	s.record(ctx, "warrant.token.revoked", t.Human, []string{t.Subject}, map[string]any{
		"token_id": id, "reason": reason, "revoked_by": by})
	return nil
}

// ScopeView is a scope with live remaining budget.
type ScopeView struct {
	token.Scope
	Used      int `json:"used"`
	Remaining int `json:"remaining"` // min over scope, token and every ancestor budget
}

// BlastRadius describes what a token can do right now.
type BlastRadius struct {
	TokenID        string        `json:"token_id"`
	Subject        string        `json:"subject"`
	Human          string        `json:"human"`
	Depth          int           `json:"depth"`
	MaxDepth       int           `json:"max_depth"`
	CanDelegate    bool          `json:"can_delegate"`
	Live           bool          `json:"live"`
	Revoked        string        `json:"revoked_via,omitempty"`
	ExpiresIn      int64         `json:"expires_in_seconds"`
	CallsRemaining int           `json:"calls_remaining"`
	Scopes         []ScopeView   `json:"scopes"`
	PolicyForbids  []policy.Rule `json:"policy_forbids"`
	Children       []BlastRadius `json:"children,omitempty"`
}

// BlastRadius computes the current authority of a token from its actual
// claims and counters, recursively including live delegates.
func (s *Service) BlastRadius(ctx context.Context, id string) (BlastRadius, error) {
	rec, err := s.Store.GetToken(ctx, id)
	if err != nil {
		return BlastRadius{}, err
	}
	var c token.Claims
	if err := json.Unmarshal(rec.Claims, &c); err != nil {
		return BlastRadius{}, err
	}
	now := s.Now()
	br := BlastRadius{TokenID: c.ID, Subject: c.Subject, Human: c.Human, Depth: c.Depth, MaxDepth: c.MaxDepth,
		ExpiresIn: c.Expires - now.Unix(), PolicyForbids: s.Policy.Forbids(c.Subject, c.Human)}
	if br.ExpiresIn < 0 {
		br.ExpiresIn = 0
	}
	rev, err := s.Store.FirstRevoked(ctx, c.Lineage())
	if err != nil {
		return br, err
	}
	br.Revoked = rev
	br.Live = rev == "" && br.ExpiresIn > 0
	// remaining = min over lineage of (max_calls - used)
	remaining := -1
	for _, a := range c.Lineage() {
		ar, err := s.Store.GetToken(ctx, a)
		if err != nil {
			return br, err
		}
		used, _, err := s.Store.Usage(ctx, a)
		if err != nil {
			return br, err
		}
		if left := ar.MaxCalls - used; remaining < 0 || left < remaining {
			remaining = left
		}
	}
	if !br.Live || remaining < 0 {
		remaining = 0
	}
	br.CallsRemaining = remaining
	br.CanDelegate = br.Live && c.Depth < c.MaxDepth && remaining > 0
	_, per, err := s.Store.Usage(ctx, id)
	if err != nil {
		return br, err
	}
	for i, sc := range c.Scopes {
		left := sc.MaxCalls - per[i]
		if left > remaining {
			left = remaining
		}
		if left < 0 {
			left = 0
		}
		br.Scopes = append(br.Scopes, ScopeView{Scope: sc, Used: per[i], Remaining: left})
	}
	kids, err := s.Store.Children(ctx, id)
	if err != nil {
		return br, err
	}
	for _, k := range kids {
		if k.Expires.Before(now) {
			continue
		}
		kb, err := s.BlastRadius(ctx, k.ID)
		if err != nil {
			return br, err
		}
		if kb.Live {
			br.Children = append(br.Children, kb)
		}
	}
	return br, nil
}
