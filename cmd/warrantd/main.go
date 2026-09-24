// Command warrantd runs the Warrant broker API and the PEP gateway.
//
// Environment:
//
//	WARRANT_DATABASE_URL   Postgres URL (unset => in-memory store, dev only)
//	WARRANT_ADMIN_TOKEN    bearer token for admin endpoints (required)
//	WARRANT_SIGNING_KEY    base64 32-byte Ed25519 seed (unset => ephemeral key)
//	WARRANT_POLICY         path to JSON policy file (unset => default deny)
//	WARRANT_ROUTES         path to JSON PEP routes file
//	WARRANT_TRUST_DOMAIN   SPIFFE trust domain (default warrant.local)
//	WARRANT_MAX_DEPTH      default delegation depth cap (default 1)
//	WARRANT_ADDR           broker listen address (default :8430)
//	WARRANT_PEP_ADDR       PEP listen address (default :8431)
//	LEDGER_URL, LEDGER_TOKEN  Ledger connection (optional)
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
	"github.com/Celaris-dev1/Warrant/internal/ledger"
	"github.com/Celaris-dev1/Warrant/internal/pep"
	"github.com/Celaris-dev1/Warrant/internal/policy"
	"github.com/Celaris-dev1/Warrant/internal/store"
	"github.com/Celaris-dev1/Warrant/internal/token"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ctx := context.Background()
	adminTok := os.Getenv("WARRANT_ADMIN_TOKEN")
	if adminTok == "" {
		log.Fatal("WARRANT_ADMIN_TOKEN is required")
	}
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
	var routes []pep.Route
	if p := os.Getenv("WARRANT_ROUTES"); p != "" {
		if routes, err = pep.LoadRoutes(p); err != nil {
			log.Fatalf("routes: %v", err)
		}
	}
	depth, _ := strconv.Atoi(env("WARRANT_MAX_DEPTH", "1"))
	rec, closeLedger, err := ledger.FromEnvSpooling(os.Getenv("LEDGER_SPOOL_DIR"))
	if err != nil {
		log.Fatalf("ledger: %v", err)
	}
	defer closeLedger()
	svc := broker.New(broker.Config{TrustDomain: env("WARRANT_TRUST_DOMAIN", "warrant.local"), MaxDepth: depth},
		st, signer, pol, rec)

	pepSrv := &http.Server{Addr: env("WARRANT_PEP_ADDR", ":8431"), Handler: pep.New(svc, routes), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("warrant PEP listening on %s (%d routes)", pepSrv.Addr, len(routes))
		log.Fatal(pepSrv.ListenAndServe())
	}()
	srv := &http.Server{Addr: env("WARRANT_ADDR", ":8430"), Handler: svc.Handler(adminTok), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("warrantd broker listening on %s (kid %s)", srv.Addr, signer.KID)
	log.Fatal(srv.ListenAndServe())
}
