package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

func svc(t *testing.T, pol string) *Service {
	ps, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	sg, _ := token.NewSigner(nil)
	return New(Config{MaxTTL: time.Minute}, store.NewMemory(), sg, ps, nil)
}

func svid(t *testing.T, s *Service, name string) string {
	ctx := context.Background()
	if err := s.RegisterWorkload(ctx, name, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.IssueSVID(ctx, name, "0123456789abcdef", "i1")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var sc = []token.Scope{{Tool: "t", Resources: []string{"*"}, MaxCalls: 5}}

func TestDepthCapDefaultsToOneAndPolicyCanRaise(t *testing.T) {
	ctx := context.Background()
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"},{"id":"d","effect":"permit","action":"delegate"}]}`)
	a, b, c := svid(t, s, "a"), svid(t, s, "b"), svid(t, s, "c")
	if _, err := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: sc, MaxDepth: 2}); !errors.Is(err, ErrDepth) {
		t.Fatalf("max_depth 2 without policy: %v", err)
	}
	root, err := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: sc, TTL: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if root.Claims.Expires-root.Claims.IssuedAt > 60 {
		t.Fatal("TTL not capped by MaxTTL")
	}
	kid, err := s.Delegate(ctx, DelegateRequest{ParentToken: root.Token, ParentSVID: a, ChildSVID: b, Scopes: sc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delegate(ctx, DelegateRequest{ParentToken: kid.Token, ParentSVID: b, ChildSVID: c, Scopes: sc}); !errors.Is(err, ErrDepth) {
		t.Fatalf("grandchild at default cap: %v", err)
	}

	s2 := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint","allow_depth":2},{"id":"d","effect":"permit","action":"delegate"}]}`)
	a, b, c = svid(t, s2, "a"), svid(t, s2, "b"), svid(t, s2, "c")
	root, err = s2.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: sc, MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	kid, _ = s2.Delegate(ctx, DelegateRequest{ParentToken: root.Token, ParentSVID: a, ChildSVID: b, Scopes: sc})
	if _, err := s2.Delegate(ctx, DelegateRequest{ParentToken: kid.Token, ParentSVID: b, ChildSVID: c, Scopes: sc}); err != nil {
		t.Fatalf("policy-authorized depth 2: %v", err)
	}
}

func TestDelegationRequiresHolderSVIDAndPolicy(t *testing.T) {
	ctx := context.Background()
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint"}]}`)
	a, b := svid(t, s, "a"), svid(t, s, "b")
	root, _ := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: sc})
	if _, err := s.Delegate(ctx, DelegateRequest{ParentToken: root.Token, ParentSVID: b, ChildSVID: b, Scopes: sc}); !errors.Is(err, ErrBinding) {
		t.Fatalf("non-holder delegated: %v", err)
	}
	if _, err := s.Delegate(ctx, DelegateRequest{ParentToken: root.Token, ParentSVID: a, ChildSVID: b, Scopes: sc}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("delegation without permit: %v", err)
	}
	if _, err := s.MintRoot(ctx, MintRequest{SVID: root.Token, Human: "h", Scopes: sc}); err == nil {
		t.Fatal("capability token accepted as SVID")
	}
}

// TestGoalIDAndParentActorPersist covers the previously-dropped fields: a
// chain's goal_id must survive delegation (inherited when omitted) and every
// token must record the actor that caused it to be issued.
func TestGoalIDAndParentActorPersist(t *testing.T) {
	ctx := context.Background()
	s := svc(t, `{"rules":[{"id":"m","effect":"permit","action":"mint","allow_depth":2},{"id":"d","effect":"permit","action":"delegate"}]}`)
	a, b, c := svid(t, s, "a"), svid(t, s, "b"), svid(t, s, "c")

	root, err := s.MintRoot(ctx, MintRequest{SVID: a, Human: "h", Scopes: sc, GoalID: "goal-1", MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if root.Claims.GoalID != "goal-1" {
		t.Fatalf("root goal_id = %q, want goal-1", root.Claims.GoalID)
	}
	rootRec, err := s.Store.GetToken(ctx, root.Claims.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rootRec.GoalID != "goal-1" {
		t.Fatalf("persisted root goal_id = %q, want goal-1", rootRec.GoalID)
	}
	if rootRec.ParentActor != a2subject(t, s, a) {
		t.Fatalf("root parent_actor = %q, want minting workload's subject", rootRec.ParentActor)
	}

	// Delegate without goal_id: it must be inherited from the parent.
	kid, err := s.Delegate(ctx, DelegateRequest{ParentToken: root.Token, ParentSVID: a, ChildSVID: b, Scopes: sc})
	if err != nil {
		t.Fatal(err)
	}
	if kid.Claims.GoalID != "goal-1" {
		t.Fatalf("child goal_id = %q, want inherited goal-1", kid.Claims.GoalID)
	}
	kidRec, err := s.Store.GetToken(ctx, kid.Claims.ID)
	if err != nil {
		t.Fatal(err)
	}
	if kidRec.GoalID != "goal-1" {
		t.Fatalf("persisted child goal_id = %q, want goal-1", kidRec.GoalID)
	}
	if kidRec.ParentActor != root.Claims.Subject {
		t.Fatalf("child parent_actor = %q, want %q (the delegating holder)", kidRec.ParentActor, root.Claims.Subject)
	}
	if kidRec.Parent != root.Claims.ID {
		t.Fatalf("child parent token id = %q, want %q", kidRec.Parent, root.Claims.ID)
	}

	// A grandchild can override goal_id explicitly.
	gc, err := s.Delegate(ctx, DelegateRequest{ParentToken: kid.Token, ParentSVID: b, ChildSVID: c, Scopes: sc, GoalID: "goal-2"})
	if err != nil {
		t.Fatal(err)
	}
	if gc.Claims.GoalID != "goal-2" {
		t.Fatalf("grandchild goal_id = %q, want explicit override goal-2", gc.Claims.GoalID)
	}
}

func a2subject(t *testing.T, s *Service, svidTok string) string {
	c, err := s.verifyKind(svidTok, "svid")
	if err != nil {
		t.Fatal(err)
	}
	return c.Subject
}
