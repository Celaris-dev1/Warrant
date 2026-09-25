package adapters

import (
	"context"
	"errors"
	"testing"
)

func TestAnthropicToolGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	resourceOf := func(input map[string]any) string {
		p, _ := input["path"].(string)
		return "repo/docs/" + p
	}

	if _, _, err := AnthropicToolGate(ctx, e, creds, AnthropicToolUse{ID: "1", Name: "fs.read", Input: map[string]any{"path": "intro.md"}}, resourceOf); err != nil {
		t.Fatalf("in-scope tool_use denied: %v", err)
	}

	called := false
	body := func() { called = true }
	_, res, err := AnthropicToolGate(ctx, e, creds, AnthropicToolUse{ID: "2", Name: "fs.write", Input: map[string]any{"path": "intro.md"}}, resourceOf)
	if err == nil {
		t.Fatal("out-of-scope tool should be denied")
	}
	var den *Denied
	if !errors.As(err, &den) {
		t.Fatalf("expected *Denied, got %v", err)
	}
	if !res.IsError || res.ToolUseID != "2" {
		t.Fatalf("expected an is_error tool_result echoing tool_use_id, got %+v", res)
	}
	if called {
		t.Fatal("tool body must never run on denial")
	}
	_ = body
}

func TestGeminiFunctionGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	resourceOf := func(args map[string]any) string {
		p, _ := args["path"].(string)
		return "repo/docs/" + p
	}

	if _, _, err := GeminiFunctionGate(ctx, e, creds, GeminiFunctionCall{Name: "fs.read", Args: map[string]any{"path": "intro.md"}}, resourceOf); err != nil {
		t.Fatalf("in-scope functionCall denied: %v", err)
	}
	_, resp, err := GeminiFunctionGate(ctx, e, creds, GeminiFunctionCall{Name: "fs.write", Args: map[string]any{"path": "intro.md"}}, resourceOf)
	if err == nil {
		t.Fatal("out-of-scope function should be denied")
	}
	if resp.Response["error"] == nil {
		t.Fatalf("expected an error functionResponse, got %+v", resp)
	}
}

func TestBedrockToolGate(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	resourceOf := func(input map[string]any) string {
		p, _ := input["path"].(string)
		return "repo/docs/" + p
	}

	if _, _, err := BedrockToolGate(ctx, e, creds, BedrockToolUse{ToolUseID: "t1", Name: "fs.read", Input: map[string]any{"path": "intro.md"}}, resourceOf); err != nil {
		t.Fatalf("in-scope toolUse denied: %v", err)
	}
	_, res, err := BedrockToolGate(ctx, e, creds, BedrockToolUse{ToolUseID: "t2", Name: "fs.write", Input: map[string]any{"path": "intro.md"}}, resourceOf)
	if err == nil {
		t.Fatal("out-of-scope tool should be denied")
	}
	if res.Status != "error" || res.ToolUseID != "t2" {
		t.Fatalf("expected an error toolResult echoing toolUseId, got %+v", res)
	}
}

func TestGRPCUnaryInterceptor(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	credsOf := func(context.Context) Credentials { return creds }
	resourceOf := func(info *GRPCUnaryInfo, req any) string {
		m, _ := req.(map[string]any)
		p, _ := m["path"].(string)
		return "repo/docs/" + p
	}
	toolOf := func(info *GRPCUnaryInfo) string { return "fs.read" }

	called := false
	handler := func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil }
	interceptor := GRPCUnaryInterceptor(e, credsOf, toolOf, resourceOf)

	out, err := interceptor(ctx, map[string]any{"path": "intro.md"}, &GRPCUnaryInfo{FullMethod: "/pkg.Service/Read"}, handler)
	if err != nil || out != "ok" || !called {
		t.Fatalf("in-scope call: out=%v err=%v called=%v", out, err, called)
	}

	called = false
	denyToolOf := func(info *GRPCUnaryInfo) string { return "fs.write" }
	interceptor2 := GRPCUnaryInterceptor(e, credsOf, denyToolOf, resourceOf)
	_, err = interceptor2(ctx, map[string]any{"path": "intro.md"}, &GRPCUnaryInfo{FullMethod: "/pkg.Service/Write"}, handler)
	if err == nil {
		t.Fatal("out-of-scope method should be denied")
	}
	if called {
		t.Fatal("handler must never run on denial")
	}
}

type rpcArgs struct{ Path string }
type rpcReply struct{ OK bool }

func TestWrapRPCMethod(t *testing.T) {
	e, creds := harness(t)
	resourceOf := func(a *rpcArgs) string { return "repo/docs/" + a.Path }
	called := false
	method := func(args *rpcArgs, reply *rpcReply) error { called = true; reply.OK = true; return nil }
	wrapped := WrapRPCMethod(e, creds, "fs.read", resourceOf, method)

	var reply rpcReply
	if err := wrapped(&rpcArgs{Path: "intro.md"}, &reply); err != nil || !reply.OK || !called {
		t.Fatalf("in-scope RPC call: err=%v reply=%+v called=%v", err, reply, called)
	}

	called = false
	wrappedOOS := WrapRPCMethod(e, creds, "fs.write", resourceOf, method)
	var reply2 rpcReply
	err := wrappedOOS(&rpcArgs{Path: "intro.md"}, &reply2)
	if err == nil {
		t.Fatal("out-of-scope RPC method should be denied")
	}
	if called {
		t.Fatal("RPC method body must never run on denial")
	}
}

func TestWrapFunc(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	resourceOf := func(input any) string {
		m, _ := input.(map[string]any)
		p, _ := m["path"].(string)
		return "repo/docs/" + p
	}
	called := false
	fn := func(ctx context.Context, input any) (any, error) { called = true; return "ok", nil }
	wrapped := WrapFunc(e, creds, "fs.read", resourceOf, fn)

	out, err := wrapped(ctx, map[string]any{"path": "intro.md"})
	if err != nil || out != "ok" || !called {
		t.Fatalf("in-scope call: out=%v err=%v called=%v", out, err, called)
	}

	called = false
	wrappedOOS := WrapFunc(e, creds, "fs.write", resourceOf, fn)
	_, err = wrappedOOS(ctx, map[string]any{"path": "intro.md"})
	if err == nil {
		t.Fatal("out-of-scope function should be denied")
	}
	if called {
		t.Fatal("function body must never run on denial")
	}
}

func TestMCPHandlerMiddleware(t *testing.T) {
	e, creds := harness(t)
	ctx := context.Background()
	credsOf := func(context.Context) Credentials { return creds }
	resourceOf := func(name string, args map[string]any) string {
		p, _ := args["path"].(string)
		return "repo/docs/" + p
	}
	called := false
	next := func(ctx context.Context, name string, arguments map[string]any) (any, error) { called = true; return "ok", nil }
	handler := MCPHandlerMiddleware(e, credsOf, resourceOf, next)

	out, err := handler(ctx, "fs.read", map[string]any{"path": "intro.md"})
	if err != nil || out != "ok" || !called {
		t.Fatalf("in-scope tools/call: out=%v err=%v called=%v", out, err, called)
	}

	called = false
	_, err = handler(ctx, "fs.write", map[string]any{"path": "intro.md"})
	if err == nil {
		t.Fatal("out-of-scope tool should be denied")
	}
	if called {
		t.Fatal("handler body must never run on denial")
	}
}
