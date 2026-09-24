# Security

Warrant is a capability broker sitting between agents (often LLM-driven,
and therefore subject to prompt injection) and the tools they can call. Its
job is to make "what could a compromised agent do" a small, computable
number. This document describes the threat model, the guarantees Warrant
actually provides, what it does not provide, and how to report a
vulnerability.

## Threat model

Warrant assumes:

- **The model can be adversarially steered.** Anything an LLM reads (tool
  output, a fetched web page, another agent's message) may contain text
  trying to make it ask for more authority, reuse a token outside its
  original context, or ignore its instructions. Warrant does not try to
  detect or filter this text — it assumes the model *will* try to do
  something it shouldn't, and makes sure it cannot regardless of what it
  asks for.
- **A sub-agent's process/environment may be compromised.** A stolen
  capability token should be useless without also stealing (a) the SVID of
  the workload it's bound to (`sub`) and, for holder-bound tokens, (b) the
  holder's private key (see `internal/pop`).
- **The broker and its signing key are trusted.** If an attacker has
  `WARRANT_SIGNING_KEY` or write access to the token/policy stores, all
  bets are off — protect these like any other root credential (see
  "Secrets" below).
- **Requesters are never trusted to self-limit.** Every attenuation step
  (delegation at the broker, or offline blocks via `internal/attenuate`) is
  verified structurally: the requester's own claim about what it wants is
  intersected with what its parent actually holds, so a widened or
  fabricated request is silently narrowed or rejected, never honored.

## Guarantees

- **Default deny.** No policy file, or no matching rule, denies. See
  `internal/policy`.
- **Structural attenuation.** `token.Attenuate`/`internal/attenuate` only
  ever *intersect* scopes; there is no code path that unions or widens
  authority when computing a child's or an attenuated block's scopes.
  Argument constraints, resource patterns, call budgets and expiry all
  narrow monotonically down a chain (`internal/token/scope_test.go`,
  `internal/attenuate/attenuate_test.go` cover this with property tests).
- **Workload binding.** A capability token's `sub` is checked against the
  presenting workload's SVID at every call (`internal/broker` `Authorize`);
  a token without the matching SVID is refused.
- **Holder-bound proof-of-possession.** A token minted/delegated with `cnf`
  set additionally requires a fresh (<=60s), single-use, audience- and
  request-bound Ed25519 proof signed by the holder's private key
  (`internal/pop`). Replay is rejected via `ReplayStore`.
- **Shared, atomic budgets.** A call charges the presenting token's scope
  counter and every ancestor's total counter atomically
  (`internal/store` `Consume`, `SELECT ... FOR UPDATE` on Postgres), so
  delegation cannot be used to multiply a root's budget.
- **Revocation cascades.** Revoking a token revokes its entire subtree:
  `Authorize`/`checkLive` check every id in a token's lineage against the
  revocation list, not just the token itself.
- **Ledger durability.** Ledger writes go through a local file spool and
  are retried until delivered, never silently dropped, even across a
  restart (`internal/ledger` `SpoolingClient`).
- **Bounded request size.** The broker HTTP API, the PEP and the gateway
  (`internal/gateway`) all cap request bodies (`http.MaxBytesReader`,
  1 MiB by default, configurable for the gateway via
  `WARRANT_GATEWAY_MAX_BODY_BYTES`) to bound memory use from a hostile or
  buggy client; an oversized body is rejected before any JSON is parsed.
- **Attenuation chains are a first-class credential, everywhere.** The
  broker (`Authorize`/`Peek`), the PEP and the gateway all accept either a
  plain capability token or a JSON-encoded `internal/attenuate.Chain` in
  `Authorization: Bearer`. A chain is fully verified (base signature and
  expiry, every block's signature, chain linkage, and that every block only
  narrows) before any call is authorized against its effective scopes; a
  revoked *base* token denies every chain built on it, since the base
  token's own lineage is what revocation checks. A chain never gets a
  budget of its own — it shares the base token's broker-tracked per-scope
  counters — so offline attenuation can restrict what a token can do but
  can never be used to obtain additional call budget.
- **PoP holder rebinding requires the current holder.** A chain block may
  rebind the effective proof-of-possession key (`Block.Cnf`), but `Verify`
  only accepts it when the block is signed by the key matching the *current*
  effective `cnf`. Without this, anyone who merely possesses the bearer
  chain bytes (not the original holder's private key) could rebind PoP
  protection to a key of their own and defeat it entirely; with it, a
  rebind is only possible with proof the previous holder authorized the
  handoff (`internal/attenuate` `TestAttenuationChainCnfRebindRequiresCurrentHolderKey`,
  `internal/pep` `TestPoPBindsToFinalHolderOfAttenuatedChain`).

## Gateway (`warrantd gateway`, `internal/gateway`)

- The gateway is a protocol-native PEP: it speaks the upstream MCP/A2A
  server's own JSON-RPC wire format instead of Warrant's `POST
  /call/{tool}` shape, but every gated message (MCP `tools/call`; A2A
  `message/send`, `tasks/*`) is authorized through the exact same
  `broker.Service.Authorize` the PEP uses, so it gets the same guarantees
  above (workload binding, PoP, shared budgets, policy, revocation,
  Ledger) — nothing about speaking JSON-RPC bypasses enforcement.
- A denied gated message is dropped before it ever reaches the upstream;
  in a batch request, only the allowed (and passthrough/notification)
  messages are forwarded, each denial coming back as its own spec-shaped
  JSON-RPC error with the original request `id` preserved. A fully-denied
  batch makes no upstream request at all.
- `initialize`, `tools/list` and notifications (MCP), and non-`tasks/*`
  methods (A2A, e.g. agent-card discovery) pass through **without**
  authorization, by design — they carry no authority of their own. Do not
  add a method to that passthrough set unless it is genuinely inert; a
  gated method accidentally reclassified as passthrough bypasses
  enforcement entirely.
- `WARRANT_GATEWAY_FILTER_TOOLS_LIST` is a UX filter, not an enforcement
  boundary: it checks a credential's scopes structurally (tool name/
  resource pattern only, via `broker.Service.Peek`, which consumes no
  budget and runs no policy rule or argument constraint). A tool hidden
  from the list is still denied for real by `Authorize` if called
  directly; conversely, a tool shown in a filtered list can still be
  denied by policy or argument constraints once actually called with
  arguments. Never rely on the filtered listing itself as an authorization
  decision.

## What Warrant does *not* do

- It does not sandbox the tool implementation itself. A permitted call
  still executes with whatever privileges the upstream tool has; Warrant
  only decides *whether* the call is forwarded, not what the tool does
  with it.
- It does not detect or block prompt injection content. It assumes the
  model may be fully compromised and relies entirely on capability scoping,
  not content filtering, to bound the damage
  (see `internal/pep` / `adapters` prompt-injection containment tests).
- It does not protect against a compromised broker process or a leaked
  signing key — see "Secrets" below.

## Secrets

- `WARRANT_SIGNING_KEY`, workload registration secrets, and
  `WARRANT_ADMIN_TOKEN` are root-equivalent. Never commit them; inject them
  via environment/secret manager only.
- Never commit `.env` files, real Postgres URLs with embedded credentials,
  or any test fixture containing a real signing seed.
- Ledger spool files (`LEDGER_SPOOL_DIR`) contain full audit records
  (including tool arguments); treat that directory with the same access
  controls as the database.

## Reporting a vulnerability

Please open a private security advisory on the repository (GitHub Security
Advisories) rather than a public issue. Include: the affected version/
commit, a minimal reproduction, and the impact you believe it has (e.g.
"lets a delegate exceed its parent's budget", "lets a revoked token keep
working"). We aim to acknowledge within a few business days.
