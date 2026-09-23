package policy

import (
	"testing"

	"github.com/Celaris-dev1/Warrant/internal/token"
)

const doc = `{"version":"v1","rules":[
 {"id":"allow-read","effect":"permit","action":"call","tool":"fs.*"},
 {"id":"no-secrets","effect":"forbid","action":"call","resource":"secrets/*"},
 {"id":"no-rm","effect":"forbid","action":"call","tool":"fs.write","when":{"args":{"mode":{"enum":["delete"]}}}},
 {"id":"deleg","effect":"permit","action":"delegate","principal":"spiffe://warrant.local/workload/planner/*","allow_depth":2}
]}`

func TestDenyOverrides(t *testing.T) {
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		q    Request
		want bool
	}{
		{Request{Action: ActionCall, Call: token.Call{Tool: "fs.read", Resource: "repo/x"}}, true},
		{Request{Action: ActionCall, Call: token.Call{Tool: "fs.read", Resource: "secrets/k"}}, false},
		{Request{Action: ActionCall, Call: token.Call{Tool: "fs.write", Resource: "r", Args: map[string]any{"mode": "delete"}}}, false},
		{Request{Action: ActionCall, Call: token.Call{Tool: "fs.write", Resource: "r", Args: map[string]any{"mode": "append"}}}, true},
		{Request{Action: ActionCall, Call: token.Call{Tool: "shell", Resource: "r"}}, false},
		{Request{Action: ActionDelegate, Principal: "spiffe://warrant.local/workload/planner/1"}, true},
	}
	for i, c := range cases {
		if d := s.Evaluate(c.q); d.Allow != c.want {
			t.Errorf("case %d: got %+v", i, d)
		}
	}
	if d := s.Evaluate(cases[5].q); d.AllowDepth != 2 {
		t.Errorf("allow_depth not propagated: %+v", d)
	}
	var nilSet *Set
	if nilSet.Evaluate(cases[0].q).Allow {
		t.Error("nil policy must default-deny")
	}
}

func TestParseRejectsBadEffect(t *testing.T) {
	if _, err := Parse([]byte(`{"rules":[{"id":"x","effect":"maybe"}]}`)); err == nil {
		t.Fatal("expected error")
	}
}
