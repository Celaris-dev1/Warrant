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
- **Bounded request size.** Both the broker HTTP API and the PEP cap
  request bodies (`http.MaxBytesReader`, 1 MiB) to bound memory use from a
  hostile or buggy client.

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
