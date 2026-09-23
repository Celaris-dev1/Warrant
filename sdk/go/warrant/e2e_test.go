package warrant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/ledger"
	"github.com/Celaris-dev1/Warrant/internal/pep"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
	"github.com/Celaris-dev1/Warrant/sdk/go/warrant"
)

const admin = "admin-secret-token"

const pol = `{"version":"test-v1","rules":[
 {"id":"mint","effect":"permit","action":"mint"},
 {"id":"deleg","effect":"permit","action":"delegate"},
 {"id":"calls","effect":"permit","action":"call"},
 {"id":"no-prod-delete","effect":"forbid","action":"call","tool":"db.exec","when":{"args":{"stmt":{"pattern":"DROP*"}}}}
]}`

type env struct {
	svc      *broker.Service
	led      *ledger.Memory
	brokerU  string
	pepU     string
	upstream int
}

func setup(t *testing.T) *env {
	t.Helper()
	var st store.Store = store.NewMemory()
	if url := os.Getenv("WARRANT_TEST_DATABASE_URL"); url != "" {
		p, err := store.OpenPostgres(context.Background(), url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.DB.Close)
		st = p
	}
	signer, _ := token.NewSigner(nil)
	ps, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{led: &ledger.Memory{}}
	e.svc = broker.New(broker.Config{}, st, signer, ps, e.led)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.upstream++
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Warrant-SVID") != "" {
			t.Error("caller credentials leaked upstream")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "tool": body["tool"], "subject": r.Header.Get("X-Warrant-Subject")})
	}))
	t.Cleanup(up.Close)
	bs := httptest.NewServer(e.svc.Handler(admin))
	t.Cleanup(bs.Close)
	gw := httptest.NewServer(pep.New(e.svc, []pep.Route{{Tool: "*", Upstream: up.URL}}))
	t.Cleanup(gw.Close)
	e.brokerU, e.pepU = bs.URL, gw.URL
	return e
}

func agent(t *testing.T, e *env, ad *warrant.Admin, name string) *warrant.Agent {
	t.Helper()
	ctx := context.Background()
	secret := "secret-for-" + name + "-0123456789"
	if err := ad.RegisterWorkload(ctx, name, secret); err != nil {
		t.Fatal(err)
	}
	a := warrant.NewAgent(e.brokerU, e.pepU)
	if err := a.Attest(ctx, name, secret, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.SpiffeID, "spiffe://warrant.local/workload/"+name+"/") {
		t.Fatalf("spiffe id %q", a.SpiffeID)
	}
	return a
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	ad := warrant.NewAdmin(e.brokerU, admin)
	planner := agent(t, e, ad, "planner")
	worker := agent(t, e, ad, "worker")
	sub := agent(t, e, ad, "sub")

	// wrong secret is refused
	if err := warrant.NewAgent(e.brokerU, e.pepU).Attest(ctx, "planner", "wrong-secret-xxxxxxxxxx", ""); !warrant.Denied(err) {
		t.Fatalf("attestation with wrong secret: %v", err)
	}

	root, err := planner.MintRoot(ctx, admin, "alice@example.com", []warrant.Scope{
		{Tool: "fs.*", Resources: []string{"repo/acme/*"}, MaxCalls: 10},
		{Tool: "db.exec", Resources: []string{"db/prod"}, MaxCalls: 5, RequireApproval: true},
	}, time.Minute, 12)
	if err != nil {
		t.Fatal(err)
	}

	// root can call within scope; outside scope is denied by the PEP
	var out map[string]any
	if err := planner.Call(ctx, "fs.read", "repo/acme/README", map[string]any{"path": "README"}, &out); err != nil {
		t.Fatal(err)
	}
	if out["subject"] != planner.SpiffeID {
		t.Fatalf("upstream did not see subject: %+v", out)
	}
	if err := planner.Call(ctx, "fs.read", "repo/other/x", nil, &out); !warrant.Denied(err) {
		t.Fatalf("out-of-scope resource: %v", err)
	}
	if err := planner.Call(ctx, "shell.exec", "repo/acme/x", nil, &out); !warrant.Denied(err) {
		t.Fatalf("out-of-scope tool: %v", err)
	}

	// stolen token without the matching SVID is useless
	thief := warrant.NewAgent(e.brokerU, e.pepU)
	thief.Token, thief.SVID = planner.Token, worker.SVID
	if err := thief.Call(ctx, "fs.read", "repo/acme/README", nil, &out); !warrant.Denied(err) {
		t.Fatalf("token replay with other workload: %v", err)
	}

	// delegation: asks for more than it has; gets the intersection
	child, err := planner.Delegate(ctx, worker, []warrant.Scope{
		{Tool: "fs.read", Resources: []string{"repo/acme/docs/*", "repo/evil/*"}, MaxCalls: 1000},
		{Tool: "net.*", Resources: []string{"*"}, MaxCalls: 3},
	}, time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(child.Claims.Scopes) != 1 || child.Claims.Scopes[0].Tool != "fs.read" ||
		len(child.Claims.Scopes[0].Resources) != 1 || child.Claims.Scopes[0].Resources[0] != "repo/acme/docs/*" ||
		child.Claims.Scopes[0].MaxCalls != 10 {
		t.Fatalf("child scopes not attenuated: %+v", child.Claims.Scopes)
	}
	if child.Claims.MaxCalls > 12-1 {
		t.Fatalf("child max_calls %d exceeds parent remaining", child.Claims.MaxCalls)
	}
	if child.Claims.Expires > root.Claims.Expires {
		t.Fatal("child outlives parent")
	}
	if err := worker.Call(ctx, "fs.read", "repo/acme/docs/a.md", nil, &out); err != nil {
		t.Fatal(err)
	}
	if err := worker.Call(ctx, "fs.write", "repo/acme/docs/a.md", nil, &out); !warrant.Denied(err) {
		t.Fatalf("child used authority it was not delegated: %v", err)
	}

	// depth cap 1: worker cannot sub-delegate
	if _, err := worker.Delegate(ctx, sub, []warrant.Scope{{Tool: "fs.read", Resources: []string{"*"}, MaxCalls: 1}}, time.Minute, 1); !warrant.Denied(err) {
		t.Fatalf("depth cap not enforced: %v", err)
	}

	// action-hash-bound approval
	args := map[string]any{"stmt": "UPDATE t SET x=1"}
	if err := planner.Call(ctx, "db.exec", "db/prod", args, &out); !warrant.Denied(err) {
		t.Fatalf("approval-required call went through: %v", err)
	}
	appr, err := ad.Approve(ctx, planner.TokenID, "bob@example.com", "db.exec", "db/prod", args)
	if err != nil {
		t.Fatal(err)
	}
	planner.UseApproval("db.exec", appr)
	if err := planner.Call(ctx, "db.exec", "db/prod", map[string]any{"stmt": "UPDATE t SET x=2"}, &out); !warrant.Denied(err) {
		t.Fatalf("approval accepted for different args: %v", err)
	}
	planner.UseApproval("db.exec", appr)
	if err := planner.Call(ctx, "db.exec", "db/prod", args, &out); err != nil {
		t.Fatalf("approved call: %v", err)
	}
	planner.UseApproval("db.exec", appr)
	if err := planner.Call(ctx, "db.exec", "db/prod", args, &out); !warrant.Denied(err) {
		t.Fatalf("approval replayed: %v", err)
	}
	// policy forbid overrides even with approval
	drop := map[string]any{"stmt": "DROP TABLE t"}
	a2, _ := ad.Approve(ctx, planner.TokenID, "bob@example.com", "db.exec", "db/prod", drop)
	planner.UseApproval("db.exec", a2)
	if err := planner.Call(ctx, "db.exec", "db/prod", drop, &out); !warrant.Denied(err) {
		t.Fatalf("forbid did not override: %v", err)
	}

	// blast radius shows child as live
	br, err := ad.BlastRadius(ctx, planner.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if kids, _ := br["children"].([]any); len(kids) != 1 || br["can_delegate"] != true {
		t.Fatalf("blast radius: %+v", br)
	}

	// revoking the root kills the child too
	if err := ad.Revoke(ctx, planner.TokenID, "compromised"); err != nil {
		t.Fatal(err)
	}
	if err := worker.Call(ctx, "fs.read", "repo/acme/docs/a.md", nil, &out); !warrant.Denied(err) {
		t.Fatalf("child survived parent revocation: %v", err)
	}
	br, _ = ad.BlastRadius(ctx, child.Claims.ID)
	if br["live"] != false || br["calls_remaining"].(float64) != 0 {
		t.Fatalf("revoked blast radius: %+v", br)
	}

	types := strings.Join(e.led.Types(), ",")
	for _, want := range []string{"warrant.token.issued", "warrant.call.allowed", "warrant.call.denied", "warrant.token.revoked"} {
		if !strings.Contains(types, want) {
			t.Errorf("ledger missing %s (got %s)", want, types)
		}
	}
	for _, r := range e.led.Records {
		if r.ActorChain[0].Kind != "human" {
			t.Fatalf("ledger record without originating human: %+v", r)
		}
	}
}

func TestBudgetSharedAcrossLineage(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	ad := warrant.NewAdmin(e.brokerU, admin)
	p := agent(t, e, ad, "p")
	c := agent(t, e, ad, "c")
	if _, err := p.MintRoot(ctx, admin, "alice", []warrant.Scope{{Tool: "t", Resources: []string{"*"}, MaxCalls: 3}}, time.Minute, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Delegate(ctx, c, []warrant.Scope{{Tool: "t", Resources: []string{"*"}, MaxCalls: 3}}, time.Minute, 3); err != nil {
		t.Fatal(err)
	}
	ok := 0
	for i := 0; i < 5; i++ {
		if c.Call(ctx, "t", "x", nil, nil) == nil {
			ok++
		}
		if p.Call(ctx, "t", "x", nil, nil) == nil {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("lineage made %d calls, root budget is 3", ok)
	}
}

type readIn struct {
	Path string `json:"path"`
}
type readOut struct {
	OK   bool   `json:"ok"`
	Tool string `json:"tool"`
}

func TestWrapTool(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	ad := warrant.NewAdmin(e.brokerU, admin)
	a := agent(t, e, ad, "w")
	if _, err := a.MintRoot(ctx, admin, "alice", []warrant.Scope{{Tool: "fs.read", Resources: []string{"repo/*"}, MaxCalls: 2}}, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	read := warrant.WrapTool[readIn, readOut](a, "fs.read", func(in readIn) string { return "repo/" + in.Path })
	res, err := read(ctx, readIn{Path: "a"})
	if err != nil || !res.OK || res.Tool != "fs.read" {
		t.Fatalf("%+v %v", res, err)
	}
	if e.upstream != 1 {
		t.Fatal("upstream not reached exactly once")
	}
}
