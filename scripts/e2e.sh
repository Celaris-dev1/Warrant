#!/usr/bin/env bash
# End-to-end smoke test: starts Postgres (if needed), builds and runs
# warrantd against it, mints a root token, delegates, calls the PEP, revokes,
# and confirms the descendant is denied. Exits non-zero on any failure.
#
# Usage: ./scripts/e2e.sh
#
# Env overrides:
#   WARRANT_TEST_DATABASE_URL  postgres URL (default matches the task's DB)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

DB_URL="${WARRANT_TEST_DATABASE_URL:-postgres://postgres:postgres@localhost:5432/warrant}"
DB_NAME="${DB_URL##*/}"
ADMIN_TOKEN="e2e-admin-$$"
# One signing key shared by the broker and the gateway process, so tokens
# the broker mints verify at the gateway (each process otherwise falls back
# to its own ephemeral key).
SIGNING_KEY="$(head -c32 /dev/urandom | base64)"
BROKER_ADDR="127.0.0.1:18430"
PEP_ADDR="127.0.0.1:18431"
GATEWAY_ADDR="127.0.0.1:18432"
UPSTREAM_ADDR="127.0.0.1:18499"
MCP_UPSTREAM_ADDR="127.0.0.1:18498"

log() { echo "[e2e] $*" >&2; }
fail() { echo "[e2e] FAIL: $*" >&2; exit 1; }

cleanup() {
	set +e
	[[ -n "${BROKER_PID:-}" ]] && kill "$BROKER_PID" 2>/dev/null
	[[ -n "${GATEWAY_PID:-}" ]] && kill "$GATEWAY_PID" 2>/dev/null
	[[ -n "${UPSTREAM_PID:-}" ]] && kill "$UPSTREAM_PID" 2>/dev/null
	[[ -n "${MCP_UPSTREAM_PID:-}" ]] && kill "$MCP_UPSTREAM_PID" 2>/dev/null
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

WORKDIR="$(mktemp -d)"

log "building warrantd"
# -tags licensedev: lets e2e exercise Enterprise-gated features (e.g. the gateway's
# tools/list filter) with a throwaway license signed by the repo's public dev key (see
# internal/license). A plain `go build` (no tags) never trusts that key.
go build -tags licensedev -o "$WORKDIR/warrantd" ./cmd/warrantd

log "checking Postgres is reachable..."
if ! psql "$DB_URL" -c 'select 1' >/dev/null 2>&1; then
	log "Postgres not reachable at $DB_URL; trying to start the local cluster"
	if command -v pg_ctlcluster >/dev/null 2>&1; then
		pg_ctlcluster 16 main start || true
	fi
	sleep 2
fi
if ! psql "$DB_URL" -c 'select 1' >/dev/null 2>&1; then
	# Database itself may not exist yet; connect to the default db and create it.
	BASE_URL="${DB_URL%/*}/postgres"
	if psql "$BASE_URL" -c 'select 1' >/dev/null 2>&1; then
		log "creating database $DB_NAME"
		psql "$BASE_URL" -c "CREATE DATABASE $DB_NAME" >/dev/null 2>&1 || true
	fi
fi
psql "$DB_URL" -c 'select 1' >/dev/null 2>&1 || fail "cannot reach Postgres at $DB_URL"
log "Postgres OK"

log "starting fake upstream tool server on $UPSTREAM_ADDR"
cat > "$WORKDIR/upstream.go" <<'GOEOF'
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/tool", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "subject": r.Header.Get("X-Warrant-Subject")})
	})
	log.Fatal(http.ListenAndServe(os.Args[1], nil))
}
GOEOF
go build -o "$WORKDIR/upstream" "$WORKDIR/upstream.go"
"$WORKDIR/upstream" "$UPSTREAM_ADDR" &
UPSTREAM_PID=$!
sleep 1

cat > "$WORKDIR/routes.json" <<EOF
[{"tool": "*", "upstream": "http://$UPSTREAM_ADDR/tool"}]
EOF

log "starting warrantd on $BROKER_ADDR / $PEP_ADDR"
WARRANT_ADMIN_TOKEN="$ADMIN_TOKEN" \
WARRANT_POLICY="examples/policy.json" \
WARRANT_ROUTES="$WORKDIR/routes.json" \
WARRANT_DATABASE_URL="$DB_URL" \
WARRANT_SIGNING_KEY="$SIGNING_KEY" \
WARRANT_ADDR=":${BROKER_ADDR##*:}" \
WARRANT_PEP_ADDR=":${PEP_ADDR##*:}" \
LEDGER_SPOOL_DIR="$WORKDIR/ledger-spool" \
"$WORKDIR/warrantd" &
BROKER_PID=$!

for i in $(seq 1 30); do
	curl -sf "http://$BROKER_ADDR/healthz" >/dev/null 2>&1 && break
	curl -sf "http://$BROKER_ADDR/" >/dev/null 2>&1 && break
	sleep 0.5
done

api() { curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' "$@"; }

log "registering workloads"
api -X POST "http://$BROKER_ADDR/v1/workloads" -d '{"name":"planner","secret":"planner-registration-secret-e2e"}' >/dev/null
api -X POST "http://$BROKER_ADDR/v1/workloads" -d '{"name":"worker","secret":"worker-registration-secret-e2e--"}' >/dev/null

log "attesting SVIDs"
PLANNER_SVID=$(curl -sf -X POST "http://$BROKER_ADDR/v1/identity" -H 'Content-Type: application/json' \
	-d '{"workload":"planner","secret":"planner-registration-secret-e2e","instance":"i1"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["svid"])')
WORKER_SVID=$(curl -sf -X POST "http://$BROKER_ADDR/v1/identity" -H 'Content-Type: application/json' \
	-d '{"workload":"worker","secret":"worker-registration-secret-e2e--","instance":"i1"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["svid"])')
[[ -n "$PLANNER_SVID" ]] || fail "no planner SVID"
[[ -n "$WORKER_SVID" ]] || fail "no worker SVID"

log "minting root token"
ROOT=$(api -X POST "http://$BROKER_ADDR/v1/tokens" -d "{\"svid\":\"$PLANNER_SVID\",\"human\":\"e2e@example.com\",\"scopes\":[{\"tool\":\"fs.read\",\"resources\":[\"repo/e2e/*\"],\"max_calls\":5}],\"goal_id\":\"e2e-goal\"}")
ROOT_TOKEN=$(echo "$ROOT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
ROOT_ID=$(echo "$ROOT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["claims"]["jti"])')
[[ -n "$ROOT_TOKEN" ]] || fail "no root token"

log "delegating to worker"
KID=$(api -X POST "http://$BROKER_ADDR/v1/tokens/delegate" -d "{\"parent_token\":\"$ROOT_TOKEN\",\"parent_svid\":\"$PLANNER_SVID\",\"child_svid\":\"$WORKER_SVID\",\"scopes\":[{\"tool\":\"fs.read\",\"resources\":[\"repo/e2e/docs/*\"],\"max_calls\":3}]}")
KID_TOKEN=$(echo "$KID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
KID_GOAL=$(echo "$KID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["claims"].get("goal_id",""))')
[[ "$KID_GOAL" == "e2e-goal" ]] || fail "goal_id not inherited by delegate (got '$KID_GOAL')"

log "calling through the PEP with the delegated token"
CALL=$(curl -sf -X POST "http://$PEP_ADDR/call/fs.read" \
	-H "Authorization: Bearer $KID_TOKEN" -H "X-Warrant-SVID: $WORKER_SVID" -H 'Content-Type: application/json' \
	-d '{"resource":"repo/e2e/docs/intro.md"}')
echo "$CALL" | grep -q '"ok":true' || fail "expected upstream call to succeed, got: $CALL"

log "calling out-of-scope resource must be denied"
DENY_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://$PEP_ADDR/call/fs.read" \
	-H "Authorization: Bearer $KID_TOKEN" -H "X-Warrant-SVID: $WORKER_SVID" -H 'Content-Type: application/json' \
	-d '{"resource":"repo/e2e/secrets/keys"}')
[[ "$DENY_STATUS" == "403" ]] || fail "out-of-scope call: status=$DENY_STATUS, want 403"

log "revoking root and confirming the delegate is also denied"
api -X POST "http://$BROKER_ADDR/v1/tokens/$ROOT_ID/revoke" -d '{"reason":"e2e revoke"}' >/dev/null
REV_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://$PEP_ADDR/call/fs.read" \
	-H "Authorization: Bearer $KID_TOKEN" -H "X-Warrant-SVID: $WORKER_SVID" -H 'Content-Type: application/json' \
	-d '{"resource":"repo/e2e/docs/intro.md"}')
[[ "$REV_STATUS" == "403" ]] || fail "revoked descendant: status=$REV_STATUS, want 403"

log "starting fake MCP upstream on $MCP_UPSTREAM_ADDR"
cat > "$WORKDIR/mcp_upstream.go" <<'GOEOF'
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("Content-Type", "application/json")
		switch m["method"] {
		case "tools/call":
			params, _ := m["params"].(map[string]any)
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"],
				"result": map[string]any{"ok": true, "name": params["name"]}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{}})
		}
	})
	log.Fatal(http.ListenAndServe(os.Args[1], nil))
}
GOEOF
go build -o "$WORKDIR/mcp_upstream" "$WORKDIR/mcp_upstream.go"
"$WORKDIR/mcp_upstream" "$MCP_UPSTREAM_ADDR" &
MCP_UPSTREAM_PID=$!
sleep 1

log "starting warrantd gateway (mcp) on $GATEWAY_ADDR -> $MCP_UPSTREAM_ADDR"
WARRANT_DATABASE_URL="$DB_URL" \
WARRANT_POLICY="examples/policy.json" \
WARRANT_SIGNING_KEY="$SIGNING_KEY" \
WARRANT_GATEWAY_PROTOCOL="mcp" \
WARRANT_GATEWAY_UPSTREAM="http://$MCP_UPSTREAM_ADDR/" \
WARRANT_GATEWAY_ADDR=":${GATEWAY_ADDR##*:}" \
LEDGER_SPOOL_DIR="$WORKDIR/gateway-ledger-spool" \
"$WORKDIR/warrantd" gateway &
GATEWAY_PID=$!

for i in $(seq 1 30); do
	curl -s -o /dev/null -X POST "http://$GATEWAY_ADDR" -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' && break
	sleep 0.5
done

log "minting an mcp-scoped root token"
GW_ROOT=$(api -X POST "http://$BROKER_ADDR/v1/tokens" -d "{\"svid\":\"$PLANNER_SVID\",\"human\":\"e2e@example.com\",\"scopes\":[{\"tool\":\"mcp.fs.read\",\"resources\":[\"*\"],\"max_calls\":5}]}")
GW_TOKEN=$(echo "$GW_ROOT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
[[ -n "$GW_TOKEN" ]] || fail "no gateway token"

log "gateway: passthrough initialize (no credentials needed)"
INIT=$(curl -sf -X POST "http://$GATEWAY_ADDR" -H 'Content-Type: application/json' \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize"}')
echo "$INIT" | grep -q '"result"' || fail "expected initialize to pass through, got: $INIT"

log "gateway: allowed tools/call"
GCALL=$(curl -sf -X POST "http://$GATEWAY_ADDR" \
	-H "Authorization: Bearer $GW_TOKEN" -H "X-Warrant-SVID: $PLANNER_SVID" -H 'Content-Type: application/json' \
	-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fs.read","arguments":{}}}')
echo "$GCALL" | grep -q '"ok":true' || fail "expected gateway tools/call to succeed, got: $GCALL"

log "gateway: denied tools/call keeps the JSON-RPC id and returns a structured error"
GDENY=$(curl -sf -X POST "http://$GATEWAY_ADDR" \
	-H "Authorization: Bearer $GW_TOKEN" -H "X-Warrant-SVID: $PLANNER_SVID" -H 'Content-Type: application/json' \
	-d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fs.write","arguments":{}}}')
echo "$GDENY" | grep -q '"id":3' || fail "denial must preserve id, got: $GDENY"
echo "$GDENY" | grep -q '"error"' || fail "expected a JSON-RPC error for a denied tools/call, got: $GDENY"

log "gateway: batch request"
GBATCH=$(curl -sf -X POST "http://$GATEWAY_ADDR" \
	-H "Authorization: Bearer $GW_TOKEN" -H "X-Warrant-SVID: $PLANNER_SVID" -H 'Content-Type: application/json' \
	-d '[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fs.read","arguments":{}}},{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fs.write","arguments":{}}}]')
echo "$GBATCH" | grep -q '"id":4' || fail "batch missing id 4: $GBATCH"
echo "$GBATCH" | grep -q '"id":5' || fail "batch missing id 5: $GBATCH"

log "ALL E2E CHECKS PASSED"
