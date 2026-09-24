// Command warrantd runs the Warrant broker API and the PEP gateway.
//
// Environment:
//
//	WARRANT_DATABASE_URL   Postgres URL (unset => in-memory store, dev only)
//	WARRANT_ADMIN_TOKEN    bearer token for admin endpoints (required)
//	WARRANT_SIGNING_KEY    base64 32-byte Ed25519 seed (unset => ephemeral key)
//	WARRANT_RECEIPT_KEY, WARRANT_RECEIPT_KEY_FILE  persistent stack-receipt/v1 signing key
//	                       (see `warrantd keys show`; unset => key persisted under the user
//	                       config dir, or an ephemeral key if that is unwritable)
//	WARRANT_POLICY         path to JSON policy file (unset => default deny)
//	WARRANT_ROUTES         path to JSON PEP routes file
//	WARRANT_TRUST_DOMAIN   SPIFFE trust domain (default warrant.local)
//	WARRANT_MAX_DEPTH      default delegation depth cap (default 1)
//	WARRANT_ADDR           broker listen address (default :8430)
//	WARRANT_PEP_ADDR       PEP listen address (default :8431)
//	LEDGER_URL, LEDGER_TOKEN  Ledger connection (optional)
//
// Subcommand:
//
//	warrantd gateway   Runs the MCP/A2A protocol gateway instead of the
//	                   broker+PEP. See runGateway below for its env vars.
package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Celaris-dev1/Warrant/internal/broker"
	"github.com/Celaris-dev1/Warrant/internal/gateway"
	"github.com/Celaris-dev1/Warrant/internal/ledger"
	"github.com/Celaris-dev1/Warrant/internal/pep"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/receipt"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// buildService assembles a broker.Service from the environment: store,
// signing key, policy and ledger. Shared by the default broker+PEP mode and
// `warrantd gateway`.
func buildService(ctx context.Context) (*broker.Service, func() error) {
	var st store.Store
	if u := os.Getenv("WARRANT_DATABASE_URL"); u != "" {
		p, err := store.OpenPostgres(ctx, u)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		st = p
	} else {
		log.Print("WARNING: WARRANT_DATABASE_URL unset, using in-memory store (counters/revocations lost on restart)")
		st = store.NewMemory()
	}
	var seed []byte
	if k := os.Getenv("WARRANT_SIGNING_KEY"); k != "" {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			log.Fatalf("WARRANT_SIGNING_KEY: %v", err)
		}
		seed = b
	} else {
		log.Print("WARNING: WARRANT_SIGNING_KEY unset, using an ephemeral signing key")
	}
	signer, err := token.NewSigner(seed)
	if err != nil {
		log.Fatal(err)
	}
	var pol *policy.Set
	if p := os.Getenv("WARRANT_POLICY"); p != "" {
		if pol, err = policy.Load(p); err != nil {
			log.Fatalf("policy: %v", err)
		}
	} else {
		log.Print("WARNING: WARRANT_POLICY unset: everything is denied")
	}
	depth, _ := strconv.Atoi(env("WARRANT_MAX_DEPTH", "1"))
	rec, closeLedger, err := ledger.FromEnvSpooling(os.Getenv("LEDGER_SPOOL_DIR"))
	if err != nil {
		log.Fatalf("ledger: %v", err)
	}
	svc := broker.New(broker.Config{TrustDomain: env("WARRANT_TRUST_DOMAIN", "warrant.local"), MaxDepth: depth},
		st, signer, pol, rec)
	rs, err := receipt.DefaultSigner()
	if err != nil {
		log.Fatalf("receipt signing key: %v", err)
	}
	svc.ReceiptSigner = &rs
	return svc, closeLedger
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		if err := cmdKeys(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "gateway" {
		runGateway()
		return
	}
	ctx := context.Background()
	adminTok := os.Getenv("WARRANT_ADMIN_TOKEN")
	if adminTok == "" {
		log.Fatal("WARRANT_ADMIN_TOKEN is required")
	}
	svc, closeLedger := buildService(ctx)
	defer closeLedger()
	var routes []pep.Route
	if p := os.Getenv("WARRANT_ROUTES"); p != "" {
		rs, err := pep.LoadRoutes(p)
		if err != nil {
			log.Fatalf("routes: %v", err)
		}
		routes = rs
	}

	pepSrv := &http.Server{Addr: env("WARRANT_PEP_ADDR", ":8431"), Handler: pep.New(svc, routes), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("warrant PEP listening on %s (%d routes)", pepSrv.Addr, len(routes))
		log.Fatal(pepSrv.ListenAndServe())
	}()
	srv := &http.Server{Addr: env("WARRANT_ADDR", ":8430"), Handler: svc.Handler(adminTok), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("warrantd broker listening on %s (kid %s)", srv.Addr, svc.Signer.KID)
	log.Fatal(srv.ListenAndServe())
}

// runGateway runs `warrantd gateway`: the MCP/A2A protocol gateway (see
// internal/gateway) against one configured upstream. It does not run the
// broker's own admin HTTP API, so WARRANT_ADMIN_TOKEN is not required; it
// shares every other broker env var (store, signing key, policy, ledger)
// with the default mode so gateway and broker/PEP instances can be pointed
// at the same signing key and Postgres.
//
// Additional environment:
//
//	WARRANT_GATEWAY_PROTOCOL          "mcp" or "a2a" (required)
//	WARRANT_GATEWAY_UPSTREAM          upstream base URL (required)
//	WARRANT_GATEWAY_ADDR              listen address (default :8432)
//	WARRANT_GATEWAY_TOOL_PREFIX       overrides the default "mcp."/"a2a." scope tool prefix
//	WARRANT_GATEWAY_FILTER_TOOLS_LIST "true" to filter MCP tools/list to permitted tools
//	WARRANT_GATEWAY_MAX_BODY_BYTES    request body cap (default 1048576)
func runGateway() {
	ctx := context.Background()
	proto := gateway.Protocol(os.Getenv("WARRANT_GATEWAY_PROTOCOL"))
	if proto != gateway.MCP && proto != gateway.A2A {
		log.Fatal(`WARRANT_GATEWAY_PROTOCOL must be "mcp" or "a2a"`)
	}
	upstream := os.Getenv("WARRANT_GATEWAY_UPSTREAM")
	if upstream == "" {
		log.Fatal("WARRANT_GATEWAY_UPSTREAM is required")
	}
	svc, closeLedger := buildService(ctx)
	defer closeLedger()

	gw := gateway.New(svc, proto, upstream)
	if p := os.Getenv("WARRANT_GATEWAY_TOOL_PREFIX"); p != "" {
		gw.ToolPrefix = p
	}
	if os.Getenv("WARRANT_GATEWAY_FILTER_TOOLS_LIST") == "true" {
		gw.FilterToolsList = true
	}
	if n, err := strconv.ParseInt(os.Getenv("WARRANT_GATEWAY_MAX_BODY_BYTES"), 10, 64); err == nil && n > 0 {
		gw.MaxBodyBytes = n
	}

	srv := &http.Server{Addr: env("WARRANT_GATEWAY_ADDR", ":8432"), Handler: gw, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("warrant gateway (%s) listening on %s -> %s", proto, srv.Addr, upstream)
	log.Fatal(srv.ListenAndServe())
}
