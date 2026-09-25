package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// BenchmarkGatewayMCPToolsCall measures full, in-process, end-to-end latency
// of a single "tools/call" through the gateway: HTTP request in, JSON-RPC
// parse, broker.Authorize (token verify + scope/budget check + audit
// record), forward to the (in-process, httptest) upstream, and the reply
// back out. This is the number a caller actually experiences per tool call,
// as opposed to internal/bench's bare token-verify numbers.
func BenchmarkGatewayMCPToolsCall(b *testing.B) {
	svc, svidTok := benchBroker(b)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"],
			"result": map[string]any{"ok": true}})
	}))
	defer up.Close()

	tok := benchMintReadOnly(b, svc, svidTok, "mcp.fs.read")
	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	body, _ := json.Marshal(rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{}}))
	client := &http.Client{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Warrant-SVID", svidTok)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		var r rpcResp
		_ = json.NewDecoder(resp.Body).Decode(&r)
		_ = resp.Body.Close()
		if r.Error != nil {
			b.Fatalf("unexpected denial: %+v", r.Error)
		}
	}
}

// BenchmarkGatewayMCPToolsCallP99 reports p50/p99 wall latency for the same
// call as BenchmarkGatewayMCPToolsCall (go test's ns/op is a mean; some
// deployments care about tail latency of the PEP sitting in the hot path).
// It is a Benchmark (not a Test) so it only runs under -bench, but it
// prints percentiles instead of relying on ns/op alone.
func BenchmarkGatewayMCPToolsCallP99(b *testing.B) {
	svc, svidTok := benchBroker(b)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"],
			"result": map[string]any{"ok": true}})
	}))
	defer up.Close()

	tok := benchMintReadOnly(b, svc, svidTok, "mcp.fs.read")
	gw := New(svc, MCP, up.URL)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	body, _ := json.Marshal(rpc(1, "tools/call", map[string]any{"name": "fs.read", "arguments": map[string]any{}}))
	client := &http.Client{}

	n := b.N
	if n < 200 {
		n = 200 // enough samples for a meaningful p99
	}
	lat := make([]time.Duration, 0, n)
	b.ResetTimer()
	for i := 0; i < n; i++ {
		start := time.Now()
		req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Warrant-SVID", svidTok)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.CopyN(discard{}, resp.Body, 1<<20)
		_ = resp.Body.Close()
		lat = append(lat, time.Since(start))
	}
	b.StopTimer()
	p50, p99 := percentile(lat, 0.50), percentile(lat, 0.99)
	b.ReportMetric(float64(p50.Microseconds()), "p50-us")
	b.ReportMetric(float64(p99.Microseconds()), "p99-us")
}

// BenchmarkBrokerAuthorizeOverhead isolates the PEP's own decision cost
// (broker.Authorize: token verify + policy/scope/budget check + audit
// write), with no HTTP or JSON-RPC framing around it, so the framing cost
// visible in BenchmarkGatewayMCPToolsCall can be separated from the
// authorization cost itself.
func BenchmarkBrokerAuthorizeOverhead(b *testing.B) {
	svc, svidTok := benchBroker(b)
	tok := benchMintReadOnly(b, svc, svidTok, "mcp.fs.read")
	call := token.Call{Tool: "mcp.fs.read", Resource: "*", Args: map[string]any{}}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := svc.Authorize(ctx, broker.AuthorizeRequest{Token: tok, SVID: svidTok, Call: call})
		if !d.Allow {
			b.Fatalf("unexpected denial: %s", d.Reason)
		}
	}
}

func benchBroker(b *testing.B) (*broker.Service, string) {
	b.Helper()
	pol, err := policy.Parse([]byte(`{"rules":[
		{"id":"m","effect":"permit","action":"mint"},
		{"id":"c","effect":"permit","action":"call"}]}`))
	if err != nil {
		b.Fatal(err)
	}
	sg, _ := token.NewSigner(nil)
	svc := broker.New(broker.Config{MaxTTL: time.Minute}, store.NewMemory(), sg, pol, nil)
	ctx := context.Background()
	if err := svc.RegisterWorkload(ctx, "a", "0123456789abcdef"); err != nil {
		b.Fatal(err)
	}
	svidTok, _, err := svc.IssueSVID(ctx, "a", "0123456789abcdef", "i1")
	if err != nil {
		b.Fatal(err)
	}
	return svc, svidTok
}

func benchMintReadOnly(b *testing.B, svc *broker.Service, svidTok, tool string) string {
	b.Helper()
	iss, err := svc.MintRoot(context.Background(), broker.MintRequest{SVID: svidTok, Human: "h",
		Scopes: []token.Scope{{Tool: tool, Resources: []string{"*"}, MaxCalls: 1 << 30}}})
	if err != nil {
		b.Fatal(err)
	}
	return iss.Token
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration{}, d...)
	sortDurations(s)
	i := int(p * float64(len(s)-1))
	return s[i]
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j-1] > d[j]; j-- {
			d[j-1], d[j] = d[j], d[j-1]
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
