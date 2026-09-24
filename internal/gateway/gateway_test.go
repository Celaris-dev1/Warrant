package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// fakeMCP is a minimal MCP-shaped JSON-RPC upstream: initialize,
// tools/list, tools/call (echoes back {"ok":true,"name":...}), and accepts
// notifications (no reply) — for both single and batch requests.
func fakeMCP(t *testing.T) *httptest.Server {
	t.Helper()
	handle := func(m map[string]any) map[string]any {
		id := m["id"]
		method, _ := m["method"].(string)
		switch method {
		case "initialize":
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"protocolVersion": "2025-06-18"}}
		case "tools/list":
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
				"tools": []map[string]any{{"name": "fs.read"}, {"name": "fs.write"}}}}
		case "tools/call":
			params, _ := m["params"].(map[string]any)
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"ok": true, "name": params["name"]}}
		default:
			return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}}
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := jsonBody(r)
		w.Header().Set("Content-Type", "application/json")
		if arr, ok := body.([]any); ok {
			var out []map[string]any
			for _, it := range arr {
				m, _ := it.(map[string]any)
				if _, hasID := m["id"]; !hasID {
					continue // notification: no reply
				}
				out = append(out, handle(m))
			}
			if len(out) == 0 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		m, _ := body.(map[string]any)
		if _, hasID := m["id"]; !hasID {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(handle(m))
	}))
}

// fakeA2A is a minimal A2A-shaped JSON-RPC upstream: message/send and
// tasks/get.
func fakeA2A(t *testing.T) *httptest.Server {
	t.Helper()
	handle := func(m map[string]any) map[string]any {
		id := m["id"]
		method, _ := m["method"].(string)
		switch method {
		case "message/send":
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"taskId": "t1", "state": "submitted"}}
		case "tasks/get":
			return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"state": "completed"}}
		default:
			return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}}
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		body, _ := jsonBody(r)
		m, _ = body.(map[string]any)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(handle(m))
	}))
}

func jsonBody(r *http.Request) (any, error) {
	defer r.Body.Close()
	var v any
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&v)
	return v, err
}

func testBroker(t *testing.T) (*broker.Service, string, string) {
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
	svidTok, _, err := svc.IssueSVID(ctx, "a", "0123456789abcdef", "i1")
	if err != nil {
		t.Fatal(err)
	}
	return svc, svidTok, "a"
}

func mintReadOnly(t *testing.T, svc *broker.Service, svidTok string, tool string) string {
	t.Helper()
	iss, err := svc.MintRoot(context.Background(), broker.MintRequest{SVID: svidTok, Human: "h",
		Scopes: []token.Scope{{Tool: tool, Resources: []string{"*"}, MaxCalls: 10}}})
	if err != nil {
		t.Fatal(err)
	}
	return iss.Token
}

func rpc(id int, method string, params map[string]any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

func post(t *testing.T, srv *httptest.Server, tok, svid string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if svid != "" {
		req.Header.Set("X-Warrant-SVID", svid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decodeSingle(t *testing.T, resp *http.Response) rpcResp {
	t.Helper()
	defer resp.Body.Close()
	var r rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMCPToolsCallGatedAllowAndDeny(t *testing.T) {
	svc, svidTok, _ := testBroker(t)
	up := fakeMCP(t)
	defer up.Close()
	tok := mintReadOnly(t, svc, svidTok, "mcp.fs.read")

	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := post(t, srv, tok, svidTok, rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{}}))
	r := decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("allowed call should not error: %+v", r.Error)
	}

	resp = post(t, srv, tok, svidTok, rpc(2, "tools/call", map[string]any{"name": "fs.write", "arguments": map[string]any{}}))
	r = decodeSingle(t, resp)
	if r.Error == nil {
		t.Fatal("disallowed call should be denied")
	}
	if r.Error.Code != codeDenied {
		t.Fatalf("want codeDenied, got %d", r.Error.Code)
	}
	var gotID int
	_ = json.Unmarshal(r.ID, &gotID)
	if gotID != 2 {
		t.Fatalf("denial must preserve the original id, got %d", gotID)
	}
}

func TestMCPPassthroughForInitializeToolsListNotifications(t *testing.T) {
	svc, _, _ := testBroker(t)
	up := fakeMCP(t)
	defer up.Close()
	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	// No credentials at all: initialize and tools/list still pass through
	// (only tools/call is gated).
	resp := post(t, srv, "", "", rpc(1, "initialize", nil))
	r := decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("initialize should pass through ungated: %+v", r.Error)
	}

	resp = post(t, srv, "", "", rpc(2, "tools/list", nil))
	r = decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("tools/list should pass through ungated: %+v", r.Error)
	}

	// A notification (no id) gets no reply at all: 204.
	resp = post(t, srv, "", "", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("notification: status = %d, want 204", resp.StatusCode)
	}
}

func TestMCPToolsListFiltering(t *testing.T) {
	svc, svidTok, _ := testBroker(t)
	up := fakeMCP(t)
	defer up.Close()
	tok := mintReadOnly(t, svc, svidTok, "mcp.fs.read")

	gw := New(svc, MCP, up.URL)
	gw.FilterToolsList = true
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := post(t, srv, tok, svidTok, rpc(1, "tools/list", nil))
	r := decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("tools/list: %+v", r.Error)
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "fs.read" {
		t.Fatalf("expected filtered list with only fs.read, got %+v", result.Tools)
	}
}

func TestMCPBatchRequestMixedAllowDenyNotification(t *testing.T) {
	svc, svidTok, _ := testBroker(t)
	up := fakeMCP(t)
	defer up.Close()
	tok := mintReadOnly(t, svc, svidTok, "mcp.fs.read")

	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	batch := []map[string]any{
		rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{}}),
		rpc(2, "tools/call", map[string]any{"name": "fs.write", "arguments": map[string]any{}}),
		{"jsonrpc": "2.0", "method": "notifications/progress"},
	}
	resp := post(t, srv, tok, svidTok, batch)
	defer resp.Body.Close()
	var out []rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 replies (notification excluded), got %d", len(out))
	}
	byID := map[int]rpcResp{}
	for _, r := range out {
		var id int
		_ = json.Unmarshal(r.ID, &id)
		byID[id] = r
	}
	if byID[1].Error != nil {
		t.Fatalf("id 1 should be allowed: %+v", byID[1].Error)
	}
	if byID[2].Error == nil {
		t.Fatal("id 2 should be denied")
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	svc, _, _ := testBroker(t)
	up := fakeMCP(t)
	defer up.Close()
	gw := New(svc, MCP, up.URL)
	gw.MaxBodyBytes = 64
	srv := httptest.NewServer(gw)
	defer srv.Close()

	big := strings.Repeat("x", 1000)
	resp := post(t, srv, "", "", rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{"pad": big}}))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestA2AMessageSendGatedBySkillAndTasksGetGatedByMethod(t *testing.T) {
	svc, svidTok, _ := testBroker(t)
	up := fakeA2A(t)
	defer up.Close()
	tokSend := mintReadOnly(t, svc, svidTok, "a2a.echo")

	gw := New(svc, A2A, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := post(t, srv, tokSend, svidTok, rpc(1, "message/send", map[string]any{"skill": "echo", "message": map[string]any{"text": "hi"}}))
	r := decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("allowed skill should not error: %+v", r.Error)
	}

	// Wrong skill: denied.
	resp = post(t, srv, tokSend, svidTok, rpc(2, "message/send", map[string]any{"skill": "delete-everything"}))
	r = decodeSingle(t, resp)
	if r.Error == nil {
		t.Fatal("mismatched skill should be denied")
	}

	// tasks/get gated by method name: this token doesn't have it.
	resp = post(t, srv, tokSend, svidTok, rpc(3, "tasks/get", map[string]any{"taskId": "t1"}))
	r = decodeSingle(t, resp)
	if r.Error == nil {
		t.Fatal("tasks/get should be denied without a matching scope")
	}

	tokTasks := mintReadOnly(t, svc, svidTok, "a2a.tasks/get")
	resp = post(t, srv, tokTasks, svidTok, rpc(4, "tasks/get", map[string]any{"taskId": "t1"}))
	r = decodeSingle(t, resp)
	if r.Error != nil {
		t.Fatalf("tasks/get with matching scope should be allowed: %+v", r.Error)
	}
}

func TestNoUpstreamCallWhenAllGatedCallsDenied(t *testing.T) {
	svc, svidTok, _ := testBroker(t)
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer up.Close()
	tok := mintReadOnly(t, svc, svidTok, "mcp.nothing.matches")

	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	resp := post(t, srv, tok, svidTok, rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{}}))
	r := decodeSingle(t, resp)
	if r.Error == nil {
		t.Fatal("expected denial")
	}
	if calls != 0 {
		t.Fatalf("upstream should never see a fully-denied request, called %d times", calls)
	}
}
