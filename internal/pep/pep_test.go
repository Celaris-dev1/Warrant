package pep

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/pop"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

// setup builds a broker with an fs.read permit and a fake upstream that
// echoes 200 OK, and a Gateway routing fs.* to it.
func setup(t *testing.T) (*broker.Service, *Gateway, string, string) {
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

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	gw := New(svc, []Route{{Tool: "fs.*", Upstream: upstream.URL}})
	return svc, gw, svidTok, upstream.URL
}

func TestPoPRequiredForHolderBoundToken(t *testing.T) {
	svc, gw, svidTok, _ := setup(t)
	ctx := context.Background()

	pub, priv, err := pop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := svc.MintRoot(ctx, broker.MintRequest{SVID: svidTok, Human: "h",
		Scopes: []token.Scope{{Tool: "fs.read", Resources: []string{"*"}, MaxCalls: 5}},
		Cnf: &token.Cnf{JKT: token.Thumbprint(pub)}})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(gw)
	defer srv.Close()

	call := func(headers map[string]string) *http.Response {
		body, _ := json.Marshal(map[string]any{"resource": "x"})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/call/fs.read", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+root.Token)
		req.Header.Set("X-Warrant-SVID", svidTok)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// No PoP headers: denied.
	resp := call(nil)
	if resp.StatusCode != 401 {
		t.Fatalf("no PoP: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Valid PoP: allowed.
	proof, err := pop.Sign(priv, root.Claims.ID, gw.Audience, http.MethodPost, "/call/fs.read", 30*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyB64 := base64.RawURLEncoding.EncodeToString(pub)
	resp = call(map[string]string{"X-Warrant-PoP": proof, "X-Warrant-PoP-Key": keyB64})
	if resp.StatusCode != 200 {
		t.Fatalf("valid PoP: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Replaying the same proof: denied.
	resp = call(map[string]string{"X-Warrant-PoP": proof, "X-Warrant-PoP-Key": keyB64})
	if resp.StatusCode != 401 {
		t.Fatalf("replayed PoP: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// A different (attacker) key cannot forge a proof for this token: the
	// PEP only accepts a proof whose signer matches the token's cnf/jkt.
	attackerPub, attackerPriv, _ := pop.GenerateKey()
	forged, _ := pop.Sign(attackerPriv, root.Claims.ID, gw.Audience, http.MethodPost, "/call/fs.read", 30*time.Second, time.Now())
	attackerKeyB64 := base64.RawURLEncoding.EncodeToString(attackerPub)
	resp = call(map[string]string{"X-Warrant-PoP": forged, "X-Warrant-PoP-Key": attackerKeyB64})
	if resp.StatusCode != 401 {
		t.Fatalf("attacker-key proof: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPoPNotRequiredForUnboundToken(t *testing.T) {
	svc, gw, svidTok, _ := setup(t)
	ctx := context.Background()
	root, err := svc.MintRoot(ctx, broker.MintRequest{SVID: svidTok, Human: "h",
		Scopes: []token.Scope{{Tool: "fs.read", Resources: []string{"*"}, MaxCalls: 5}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	body, _ := json.Marshal(map[string]any{"resource": "x"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/call/fs.read", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+root.Token)
	req.Header.Set("X-Warrant-SVID", svidTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unbound token: status = %d, want 200", resp.StatusCode)
	}
}
