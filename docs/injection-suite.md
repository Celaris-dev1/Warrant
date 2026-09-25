# Prompt-injection containment suite

Source: `adapters/injection_test.go`. Run with:

```bash
go test ./adapters/... -run TestInjection -v
```

## What this suite is, and isn't

Warrant does not detect, filter or classify prompt injection. It cannot —
the injected text lives inside a model's context, not on the wire between a
tool call and the PEP. What Warrant *can* do is make sure that whatever a
compromised model is talked into asking for, the enforcement layer denies it
the same way it would deny an honest mistake: structurally, based on the
capability token's own scopes, budgets, chain of custody and proof of
possession, never based on inspecting or trusting the request's intent.

Every row below is a `t.Run` subtest in `adapters/injection_test.go`. Each
attack scenario asserts a denial (`errors.As(err, &Denied{})`, a JSON-RPC
`error` object, or the store rejecting a replay/reuse) unless marked
"documented limitation", where the point of the subtest is to show — rather
than hide — where the boundary of Warrant's guarantee actually sits, and
what the calling integration must do about it.

## Attack catalogue

| # | Category | Attack | Outcome |
|---|---|---|---|
| 1 | Tool-name smuggling | Requesting the raw wildcard pattern itself (`fs.*`), a sibling tool (`fs.write` against an `fs.read`-scoped token), NUL-byte suffix smuggling, path-style tool names, case variants, near-miss trailing characters, malformed wildcard placement, and a Cyrillic look-alike of `read` | Denied — `Scope.Allows`/`token.Match` is byte-exact outside the single allowed trailing-`*` wildcard form; nothing folds case, decodes escapes, or treats a lookalike codepoint as equal |
| 2 | Resource path traversal / encoding | `..`-escapes that leave the granted byte-prefix, sibling-tenant prefix collisions, percent-encoded slashes, absolute paths, backslash variants | Denied — same byte-prefix matching as above, over the resource string |
| 2b | Traversal / encoding inside the granted prefix | A resource that keeps the granted prefix but could escape it once a tool resolves it: `repo/acme/docs/../secrets`, `%2e%2e`, `..%2F`, backslashes, embedded NUL | **Denied.** A wildcard scope never matches a subject containing a `..` segment, a backslash, a NUL byte, or a percent-encoded dot, slash, backslash or NUL (`token.Match`). Legitimate deeper paths such as `repo/acme/docs/guide/intro.md` still match. Integrations should still canonicalize resources to their real syntax; Warrant no longer depends on it. |
| 3 | Argument injection | Enum bypass, pattern-constrained field carrying an injection payload, numeric bound bypass, omitting a constrained argument entirely (must not fall back to some unconstrained default) | Denied — `ArgConstraint.AllowsArg` requires the argument be present and satisfy every constraint set on it |
| 3b | *(documented limitation)* | An argument the scope's `Args` map says nothing about (e.g. a smuggled extra `note` field carrying a second instruction for a naive downstream tool) | **Allowed by Warrant.** Only arguments a scope author explicitly constrains are checked; an unconstrained argument passes through unexamined. **Mitigation:** constrain every argument a tool's implementation actually trusts, not just the ones an initial scope author thought of. |
| 4 | Delegation escalation | A depth-exhausted or narrowly-scoped delegate tries to mint a wider sub-delegation (broader tool/resource pattern, far larger call budget) | Denied outright once `Depth > MaxDepth`, or — since `Delegate` runs the request through `token.Attenuate` (structural intersection) rather than trusting the requested scopes — silently narrowed back down to a true subset of the parent's authority if depth still allows a hop at all |
| 5 | Replay | Resending an already-used PoP proof (same `jti`); resending an already-used single-use approval token for the identical action hash | Denied — `pop.ReplayStore.Seen` and `store.UseApproval` both refuse a second use |
| 6 | Token theft without PoP key | A stolen holder-bound (`cnf`) bearer token presented with no proof at all, or with a proof signed by an attacker-controlled key instead of the holder's | Denied by the gateway's PoP check (`pop.Verify` returns `ErrKeyMismatch`, or the request is rejected before reaching PoP verification for lacking a proof) — the bearer token alone is provably useless without the holder's private key |
| 7 | Confused deputy via A2A | A low-privilege agent, steered by an injected instruction embedded in a message it processed, tries to invoke a skill on another agent that it was never delegated (while claiming it's "on the planner's behalf") | Denied — `A2AGate` checks the declared `Tool` (which encodes the target agent + skill) against the caller's own delegated scopes, independent of anything in the message body |
| 8 | Oversized / batched JSON-RPC | An oversized request body attempting to exhaust the gateway; a JSON-RPC batch hiding one disallowed `tools/call` among many allowed ones, hoping only the batch as a whole is checked | The oversized body is rejected by `http.MaxBytesReader` before any authorization runs; every message in a batch is authorized **individually** — the disallowed call in the middle is denied while the other nine succeed, each keeping its own JSON-RPC `id` |

## Why the "documented limitation" row exists

A containment suite that only ever reports "denied" would be dishonest about
where Warrant's actual guarantee ends. Warrant's guarantee is: **given a
correctly-formed `(tool, resource, args)` triple, the token's scopes, budget,
chain of custody and (if bound) proof-of-possession are enforced correctly,
with no way for the presented credential alone to widen its own authority.**
It is not a promise that a resource string or an argument value contains, at
the byte level, exactly what a human reading it would assume. Constructing
that triple correctly — canonicalizing paths, constraining every trusted
argument name, choosing tight (non-wildcard, non-`"*"`-resource) scopes where
the underlying resource identifier can't be trusted to self-normalize — is
part of integrating Warrant into a given tool surface, the same way input
validation is part of using any authorization system. The suite calls this
out explicitly, with a passing test in each case, so it stays true as the
codebase changes rather than only living in a comment.
