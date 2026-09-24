# Warrant

A delegation and capability broker for AI agents. When one agent delegates to
another agent or a tool, Warrant mints a short-lived, attenuated,
workload-bound capability token. Every tool call goes through a Policy
Enforcement Point (PEP) that the model cannot reach or reason around.

The aim: "what's the worst a compromised sub-agent could do" becomes a small,
bounded number you can compute, not "everything the original credential could
do."

## Quickstart

```bash
docker compose up -d --build        # postgres + warrantd (broker :8430, PEP :8431)
# or locally:
WARRANT_ADMIN_TOKEN=dev WARRANT_POLICY=examples/policy.json WARRANT_ROUTES=examples/routes.json \
WARRANT_DATABASE_URL=postgres://postgres:postgres@localhost:5432/warrant go run ./cmd/warrantd
```

```python
from warrant import Admin, Agent, wrap_tool   # sdk/python, stdlib only

ad = Admin("http://localhost:8430", "dev")
ad.register_workload("planner", "planner-registration-secret")
ad.register_workload("worker", "worker-registration-secret-")

planner = Agent("http://localhost:8430", "http://localhost:8431")
planner.attest("planner", "planner-registration-secret")        # -> spiffe://warrant.local/workload/planner/<instance>
planner.mint_root("dev", "alice@example.com",
                  [{"tool": "fs.*", "resources": ["repo/acme/*"], "max_calls": 20}], ttl_seconds=300)

worker = Agent("http://localhost:8430", "http://localhost:8431")
worker.attest("worker", "worker-registration-secret-")
planner.delegate(worker, [{"tool": "fs.read", "resources": ["repo/acme/docs/*"], "max_calls": 5}])

@wrap_tool(worker, "fs.read", resource=lambda path: "repo/acme/docs/" + path)
def read_file(path): ...          # the body never runs in-process; the PEP forwards to the real tool

read_file("intro.md")
```

The Go SDK (`sdk/go/warrant`) has the same surface, with a generic
`WrapTool[In, Out](agent, tool, resourceOf)`.

## Architecture

```
 agent ──(token + SVID [+ approval])──▶ PEP :8431 ──authorize──▶ broker core ──▶ Postgres
                                        │  allow                    │              (tokens, revocations,
                                        ▼                           ▼               counters, approvals)
                                    real tool                    Ledger (optional)

 MCP/A2A client ──(JSON-RPC + token/chain + SVID)──▶ gateway :8432 ──authorize──▶ broker core (above)
                                                      │  allow
                                                      ▼
                                             upstream MCP server / A2A agent
```

| Package | Purpose |
|---|---|
| `internal/token` | Scopes, pattern subset/intersection, `Attenuate`, Ed25519 JWT (`alg: EdDSA`), canonical JSON + action hash |
| `internal/attenuate` | Offline, holder-side attenuation chains (Biscuit-style): signed blocks that only ever narrow a base token's scopes/expiry/holder key, verifiable against just the broker's public key |
| `internal/pop` | RFC 7800/9449-style holder-bound proof-of-possession for `cnf`-bound tokens, with replay protection |
| `internal/policy` | JSON Cedar-like rules (`permit`/`forbid` on `mint`/`delegate`/`call`, principal/human/tool/resource patterns, arg/depth/hour conditions), deny-overrides, default deny |
| `internal/store` | Postgres (pgx/v5) and in-memory stores; atomic lineage call budgets (`SELECT … FOR UPDATE`) |
| `internal/broker` | Workload identity, root mint, delegation, approvals, authorize (accepts a plain token OR an `internal/attenuate` chain), revoke, blast radius; HTTP API |
| `internal/pep` | Reverse-proxy gateway: `POST /call/{tool}` → authorize → forward to routed upstream |
| `internal/gateway` | Protocol-native gateway: speaks MCP (Streamable HTTP JSON-RPC) or A2A JSON-RPC to one upstream, gating `tools/call` / `message/send` / `tasks/*` while passing `initialize`/`tools/list`/notifications through |
| `internal/ledger` | Ledger `POST /v1/records` client (no-op when `LEDGER_URL` unset) |
| `adapters` | Framework-facing PEP wrappers: generic HTTP middleware, MCP/A2A/OpenAI/LangChain call gates |
| `sdk/go/warrant`, `sdk/python/warrant` | Client SDKs with `WrapTool` / `wrap_tool` |

### Tokens

Ed25519-signed JWTs. Claims: `jti`, `sub` (SPIFFE workload id of the holder),
`human` (originating human, never dropped), `iat`/`exp`, `parent`, `chain`
(all ancestor ids), `depth`, `max_depth`, `max_calls`, and `scopes`:

```json
{"tool": "db.exec", "resources": ["db/prod"], "max_calls": 5, "require_approval": true,
 "args": {"stmt": {"pattern": "SELECT*"}, "limit": {"max": 100}}}
```

Patterns are a literal or a prefix ending in `*`. That restriction is what
makes subset and intersection exact and decidable, so attenuation can be
computed structurally. Argument constraints: `enum`, `pattern`, `min`, `max`.
A constrained argument has to be present in the call.

### Guarantees

- **Workload identity.** A workload registers with a secret (admin). Each
  instance attests with it and gets a short-lived JWT-SVID
  `spiffe://<trust-domain>/workload/<name>/<instance>`. A capability token is
  bound to its `sub`, and the PEP requires an SVID with the same subject, so
  a stolen token alone is useless.
- **Attenuation.** `Delegate` intersects every requested scope with every
  parent scope (`token.Attenuate`). The child gets narrower-or-equal tools,
  resources, and args, per-scope `max_calls ≤ parent's`, `exp ≤ parent exp`
  (and ≤ the child SVID's exp), and a total budget ≤ the parent's *remaining*
  calls. Approval requirements are never dropped. The requester cannot widen
  anything: excess is silently intersected away, and an empty intersection is
  refused.
- **Offline attenuation.** A holder can narrow a token further, without the
  broker, by appending signed `internal/attenuate` blocks to it (a
  bearer-transmissible `Chain`). The broker/PEP/gateway verify the whole
  chain and enforce the call against `base ∩ every block`: tool, resource,
  args and expiry only ever shrink, and a block cannot widen or drop the
  narrowing (`ErrWidened`/`ErrEmpty`), nor detach from its predecessor
  (`ErrChainBroken`) or forge a signature (`ErrBlockSig`). Revoking the
  *base* token denies every chain built on it. A block may also rebind the
  chain's proof-of-possession holder key, but only if it is itself signed by
  the *current* holder key — otherwise a bearer of just the chain bytes
  could hijack PoP protection by rebinding to a key of their own.
- **Shared budgets.** A call charges the presenting token's scope counter
  and the total counter of *every ancestor*. N delegates therefore cannot
  multiply the root's budget. An attenuation chain shares its base token's
  budget too — offline blocks are never registered with the broker, so they
  cannot open a separate one.
- **Depth cap 1 by default.** Root is depth 0, its delegate is depth 1, and
  that delegate cannot sub-delegate. Deeper chains need a `mint` permit rule
  with `allow_depth` (or a raised `WARRANT_MAX_DEPTH`). Delegation also needs
  a `delegate` permit and proof (parent SVID) that the delegator holds the
  parent token.
- **Action-hash-bound approvals.** For `require_approval` scopes, an admin
  signs an approval over `sha256(canonical_json({tool, resource, args}))` for
  one token id. It is single-use and short-lived, and any change to the args
  invalidates it.
- **Policy, deny-overrides.** Any matching `forbid` wins, even over an
  approval. Otherwise a `permit` is required.
- **Revocation.** TTLs are short (default 5 min, max 15 min), so the normal
  kill switch is simply not minting again. There is also an explicit revoke
  list. Revoking a token kills its whole subtree, because every check looks
  at the full `chain`.
- **Blast radius.** `GET /v1/tokens/{id}/blast-radius` is computed from the
  real token and counters: live/revoked, expires-in, calls remaining
  (minimum over the lineage), per-scope remaining, whether it can delegate,
  applicable forbid rules, and a recursive list of live delegates.
- **Ledger.** Emits `warrant.token.issued` (for delegations it includes
  parent scopes, requested scopes, granted scopes and budgets, so the
  narrowing is auditable), `warrant.call.allowed`, `warrant.call.denied` and
  `warrant.token.revoked`. The actor chain is always `[human, agent…]`.

### HTTP API (broker, :8430)

| Method | Path | Auth |
|---|---|---|
| POST | `/v1/workloads` `{name, secret}` | admin |
| POST | `/v1/identity` `{workload, secret, instance?}` → `{svid, spiffe_id}` | registration secret |
| POST | `/v1/tokens` `{svid, human, scopes, ttl_seconds, max_calls, max_depth?, goal_id?}` | admin |
| POST | `/v1/tokens/delegate` `{parent_token, parent_svid, child_svid, scopes, ttl_seconds, max_calls}` | parent token + parent SVID |
| POST | `/v1/approvals` `{token_id, approver, call:{tool,resource,args}}` | admin |
| POST | `/v1/authorize` `{token, svid, approval?, call}` | token + SVID (in-process PEP use) |
| POST | `/v1/tokens/{id}/revoke` `{reason}` | admin |
| GET | `/v1/tokens/{id}/blast-radius` | admin, or a token in that lineage |
| GET | `/.well-known/jwks.json`, `/healthz` | none |

PEP (:8431): `POST /call/{tool}` with `Authorization: Bearer <token>`,
`X-Warrant-SVID`, optional `X-Warrant-Approval`, and body `{resource, args}`.
Routes come from `WARRANT_ROUTES` (`[{"tool":"fs.*","upstream":"http://…"}]`,
longest pattern wins). The caller's credentials are never forwarded; the
upstream receives `X-Warrant-Subject/-Human/-Token-ID/-Action-Hash`.

`Authorization: Bearer` on the PEP (and on the gateway below, and on
`POST /v1/authorize`) accepts either a plain compact JWT or a JSON-encoded
`internal/attenuate.Chain` (`{"base_token": "...", "blocks": [...]}`) —
detected by whether the value starts with `{`. A chain is verified end to
end (base signature, every block's signature and link, monotonic narrowing)
and the call is authorized against its *effective* (fully narrowed) scopes,
expiry and — if any block rebound it — holder key; the broker's own
per-scope call budget still comes from the base token, since offline blocks
are never registered with it.

### Gateway (MCP / A2A), `warrantd gateway`

`warrantd gateway` runs `internal/gateway` instead of the broker+PEP: a
JSON-RPC proxy in front of one upstream MCP server or A2A agent that speaks
the upstream's own wire protocol (no Warrant-specific request shape), gates
the calls that exercise authority, and passes protocol plumbing straight
through.

```bash
WARRANT_DATABASE_URL=postgres://postgres:postgres@localhost:5432/warrant \
WARRANT_SIGNING_KEY=<same key as the broker that mints your tokens> \
WARRANT_POLICY=examples/policy.json \
WARRANT_GATEWAY_PROTOCOL=mcp \
WARRANT_GATEWAY_UPSTREAM=http://localhost:9000/ \
go run ./cmd/warrantd gateway     # listens on :8432 by default
```

| Env var | Purpose |
|---|---|
| `WARRANT_GATEWAY_PROTOCOL` | `mcp` or `a2a` (required) |
| `WARRANT_GATEWAY_UPSTREAM` | upstream base URL (required) |
| `WARRANT_GATEWAY_ADDR` | listen address (default `:8432`) |
| `WARRANT_GATEWAY_TOOL_PREFIX` | overrides the default `mcp.`/`a2a.` scope tool prefix |
| `WARRANT_GATEWAY_FILTER_TOOLS_LIST` | `true` filters an MCP `tools/list` reply down to tools the credential's scopes structurally allow |
| `WARRANT_GATEWAY_MAX_BODY_BYTES` | request body cap (default 1 MiB) |

It shares every broker env var (`WARRANT_DATABASE_URL`,
`WARRANT_SIGNING_KEY`, `WARRANT_POLICY`, `LEDGER_SPOOL_DIR`, …) so a gateway
instance can be pointed at the same signing key and Postgres as the broker
minting the tokens it accepts; it does not run the broker's admin HTTP API,
so `WARRANT_ADMIN_TOKEN` is not required.

- **MCP** (Streamable HTTP JSON-RPC): `initialize`, `tools/list` and
  `notifications/*` pass straight through; `tools/call` is gated as
  `{tool_prefix}{params.name}`. With `WARRANT_GATEWAY_FILTER_TOOLS_LIST=true`,
  `tools/list`'s reply is filtered to tools the presented credential's
  scopes would allow by name (a best-effort check: no policy rules or
  argument constraints run at listing time, since there's no call yet).
- **A2A** (JSON-RPC): `message/send` is gated by its `skill` (or
  `message.skill`) field, falling back to the method name; every
  `tasks/*` method (`tasks/get`, `tasks/cancel`, …) is gated by method
  name. Anything else (e.g. agent-card discovery) passes through.
- Both accept a JSON-RPC batch (array) request, including a mix of gated,
  passthrough and notification messages; a fully-denied batch never reaches
  the upstream at all. A denial is a spec-shaped JSON-RPC error object
  (code `-32001`, the original request `id` preserved), never an HTTP-level
  failure — a well-behaved client can react to it like any other tool
  error. Every gated decision (allow or deny) goes through the same
  `broker.Service.Authorize` as the PEP, so it emits the same Ledger
  receipts.
- `Authorization: Bearer` accepts a plain token or an attenuation chain,
  exactly like the PEP; `X-Warrant-SVID`, `X-Warrant-Approval`,
  `X-Warrant-PoP` and `X-Warrant-PoP-Key` all mean the same thing they do
  there. PoP is checked once per HTTP request (method + this gateway's
  path), covering every gated JSON-RPC message the request carries.

The environment variables are documented in `cmd/warrantd/main.go`.

## Tests

```bash
go vet ./... && go test ./...
WARRANT_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/warrant go test -race ./...
cd sdk/python && python -m unittest discover -s tests
```

- `internal/token/scope_test.go` has the property tests (randomised, tens of
  thousands of cases). They check that attenuation never widens: whatever the
  child allows, the parent and the request also allow; the child is a
  structural subset of the parent; multi-hop stays within the root;
  `Intersect` is exact; `Subset` is sound; budgets never grow; approvals are
  never dropped.
- `internal/store`: lineage budget charging, and that concurrent consumption
  never overspends (memory and Postgres).
- `sdk/go/warrant/e2e_test.go`: the full HTTP flow through the broker and
  PEP. It covers attestation, scope denial, token replay with the wrong
  SVID, delegation intersection, depth cap, approval binding/replay,
  forbid-overrides, blast radius, subtree revocation and Ledger emission.
- `internal/attenuate/attenuate_test.go` and `internal/broker/attenuation_test.go`:
  narrowing, tampered/widened blocks, a broken chain link, a revoked base
  token denying every chain built on it, shared base budget accounting, and
  the current-holder-only cnf rebind.
- `internal/pep/pep_test.go`: PoP against a chain that rebinds the holder
  key — the original key stops working, the final one is required.
- `internal/gateway/gateway_test.go`: fake MCP and A2A upstreams —
  `tools/call`/`message/send`/`tasks/*` gating (allow/deny, id preserved),
  `initialize`/`tools/list`/notifications passthrough, `tools/list`
  filtering, a mixed-outcome JSON-RPC batch, an oversized body, and that a
  fully-denied request never reaches the upstream.
- `scripts/e2e.sh` also drives `warrantd gateway` end to end (a fake MCP
  upstream, an allowed call, a denied call, and a batch).

## Built vs roadmap

Built: everything above. The tokens are JWTs, not Biscuit, but
`internal/attenuate` layers a Biscuit-style offline attenuation chain on top
of one: delegation still happens at the broker, and a holder can
additionally narrow further without it.

Not yet built (the "fully built version"):
- X.509-SVIDs / real SPIFFE Workload API and node/process attestation.
  Attestation today is a per-workload registration secret.
- OIDC/SPIFFE federation and cross-org provenance for a partner's PEP.
- OPA/Cedar as the policy backend (a native JSON engine is used), policy
  hot-reload and a policy management UI.
- A live blast-radius dashboard UI (the endpoint exists).
- A token renewal endpoint. Renewal today means minting or delegating again.
- Signing-key rotation with multiple JWKS keys.
- Framework adapters (LangGraph, CrewAI, AutoGen). Only the generic Go and
  Python wrappers exist.
- Latency benchmarking beyond `internal/bench`'s verification-path numbers
  (see `docs/benchmarks.md`); the PEP separately reports
  `X-Warrant-Decision-Ms` per call.
- Streaming or non-JSON tool upstreams. The PEP forwards JSON POSTs only;
  the gateway speaks MCP/A2A JSON-RPC over Streamable HTTP, not SSE/stdio
  transports.
- Pruning of expired rows (tokens, counters, used approvals).
