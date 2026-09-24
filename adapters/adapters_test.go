package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// harness builds a broker with a root token scoped to fs.read on repo/docs/*
// and returns the Enforcer plus valid/invalid credentials to exercise every
// adapter against the same authority.
func harness(t *testing.T) (*Enforcer, Credentials) {
	t.Helper()
	pol, err := policy.Parse([]byte(`{"rules":[
		{"id":"m","effect":"permit","action":"mint"},
		{"id":"c","effect":"permit","action":"call"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	sg, _ := token.NewSigner(nil)
	svc := broker.New(broker.Config{MaxTTL: time.Minute}, store.NewMemory(), sg, pol, nil)
	ctx := context.Background()
	if err := svc.RegisterWorkload(ctx, "a", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	svid, _, err := svc.IssueSVID(ctx, "a", "0123456789abcdef", "i1")
	if err != nil {
		t.Fatal(err)
	}
	root, err := svc.MintRoot(ctx, broker.MintRequest{SVID: svid, Human: "h",
		Scopes: []token.Scope{{Tool: "fs.read", Resources: []string{"repo/docs/*"}, MaxCalls: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	return New(svc), Credentials{Token: root.Token, SVID: svid}
}

func TestHTTPMiddlewareAllowsAndDenies(t *testing.T) {
	e, creds := harness(t)
	called := false
	h := HTTPMiddleware(e, "fs.read", func(r *http.Request) string { return "repo/docs" + r.URL.Path })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/intro.md", nil)
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	req.Header.Set("X-Warrant-SVID", creds.SVID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !called {
		t.Fatalf("allowed call: status=%d called=%v", resp.StatusCode, called)
	}
	resp.Body.Close()

	called = false
	// No token at all: must be denied.
	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusForbidden {
		t.Fatalf("no-token call: status=%d, want 403", resp3.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp3.Body).Decode(&body)
	resp3.Body.Close()
	if body["allow"] != false {
		t.Fatalf("expected structured denial body, got %v", body)
	}
}

func TestMCPGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	if _, err := MCPGate(ctx, e, creds, MCPToolCall{Name: "fs.read", Resource: "repo/docs/intro.md"}); err != nil {
		t.Fatalf("in-scope MCP call denied: %v", err)
	}
	_, err := MCPGate(ctx, e, creds, MCPToolCall{Name: "fs.write", Resource: "repo/docs/intro.md"})
	var den *Denied
	if !errors.As(err, &den) {
		t.Fatalf("out-of-scope tool should be a *Denied, got %v", err)
	}
}

func TestA2AGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	if _, err := A2AGate(ctx, e, creds, A2ATask{Tool: "fs.read", Resource: "repo/docs/x"}); err != nil {
		t.Fatalf("in-scope A2A task denied: %v", err)
	}
	if _, err := A2AGate(ctx, e, creds, A2ATask{Tool: "fs.read", Resource: "repo/secret/x"}); err == nil {
		t.Fatal("out-of-scope resource should be denied")
	}
}

func TestOpenAIFunctionGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	resourceOf := func(args map[string]any) string {
		p, _ := args["path"].(string)
		return "repo/docs/" + p
	}
	_, args, err := OpenAIFunctionGate(ctx, e, creds, OpenAIFunctionCall{Name: "fs.read", Arguments: `{"path":"intro.md"}`}, resourceOf)
	if err != nil {
		t.Fatalf("in-scope function call denied: %v", err)
	}
	if args["path"] != "intro.md" {
		t.Fatalf("args not parsed: %v", args)
	}
	if _, _, err := OpenAIFunctionGate(ctx, e, creds, OpenAIFunctionCall{Name: "fs.write", Arguments: `{"path":"intro.md"}`}, resourceOf); err == nil {
		t.Fatal("a tool outside the granted scope should be denied")
	}
}

func TestWrapLangChainTool(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	inner := func(ctx context.Context, input any) (string, error) { return "ok", nil }
	resourceOf := func(input any) string {
		m, _ := input.(map[string]any)
		p, _ := m["path"].(string)
		return "repo/docs/" + p
	}
	wrapped := WrapLangChainTool(e, creds, LangChainToolInput{ToolName: "fs.read"}, resourceOf, inner)

	out, err := wrapped(ctx, map[string]any{"path": "intro.md"})
	if err != nil || out != "ok" {
		t.Fatalf("in-scope tool call: out=%q err=%v", out, err)
	}

	// A resource outside the granted prefix must be denied, not executed.
	wrappedOOS := WrapLangChainTool(e, creds, LangChainToolInput{ToolName: "fs.read"},
		func(any) string { return "repo/secret/x" }, inner)
	out, err = wrappedOOS(ctx, map[string]any{"path": "x"})
	if err != nil {
		t.Fatalf("denial should surface as a string observation, not an error: %v", err)
	}
	if out == "ok" {
		t.Fatal("out-of-scope call should have been denied, not executed")
	}
}
