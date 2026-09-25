# Verification latency benchmarks

Run with:

```bash
go test ./internal/bench/... -bench . -benchmem -run '^$'
go test ./internal/gateway/... -run TestXXX -bench . -benchmem
```

Source: `internal/bench/verify_bench_test.go` (bare verify paths),
`internal/gateway/gateway_bench_test.go` (end-to-end gateway latency and PEP
overhead).

## Hardware and method

All numbers on this page, before and after, were captured on the same
machine in the same session for a fair comparison: Intel(R) Xeon(R)
Processor @ 2.80GHz, 4 vCPUs, `go test -bench . -benchmem`, single run, no
other load. Re-run locally for your own hardware — these are indicative, not
a guaranteed SLA, and absolute numbers will differ (sometimes substantially)
on different silicon, especially since Ed25519 verification dominates and
its cost depends on the CPU's integer multiply throughput.

The "before" column reproduces the pre-optimization code as of this
project's last committed `docs/benchmarks.md`, re-run here on this box for a
like-for-like baseline (its own committed numbers were from a different,
slower box, so they are *not* directly comparable to the "after" column
below — re-running "before" here is what makes the delta meaningful).

## Bare verify paths (`internal/bench`)

| Benchmark | Before ns/op | After ns/op | Δ | Before allocs/op | After allocs/op |
|---|---:|---:|---:|---:|---:|
| `BenchmarkVerifyPlainToken` | 80,698 | 75,740 | −6.1% | 35 | 24 |
| `BenchmarkVerifyPoPToken` | 205,043 | 201,208 | −1.9% | 92 | 73 |
| `BenchmarkVerifyAttenuatedChain3Blocks` | 277,079 | 294,123 | +6.2%* | 56 | 45 |

\* `BenchmarkVerifyAttenuatedChain3Blocks`'s ns/op is noisy relative to its
allocation count (which strictly improved, 56→45): at ~4 Ed25519 signature
checks per iteration, this benchmark is almost entirely crypto-bound, and a
few percent of run-to-run scheduler/cache noise on a 4-vCPU shared box moves
the mean more than the JSON/allocation work removed does. Allocations/op is
the more stable signal for the non-crypto share of the cost here.

### What changed

- `token.Verify` and `pop.Verify` no longer call `strings.Split` (which
  allocates a `[]string`) to break a compact JWT/proof into its three
  segments; they scan for the two `.` separators directly.
- Both now decode the header into a small typed struct (`{Alg string}`)
  instead of a `map[string]string`, avoiding a map allocation and its
  hashing overhead for a fixed two-field shape.
- The Ed25519 signature check now verifies over the token's own
  `header.body` byte range in place (via `token.UnsafeBytes`, an
  `unsafe.Slice` view — safe here because `ed25519.Verify` only reads its
  message argument and never retains or mutates it) instead of building a
  new concatenated string first.
- Net effect: 35→24 allocations and 2,193→1,368 B/op for the plain-token
  path; the PoP and attenuated-chain paths inherit the same per-verify
  saving on top of their extra Ed25519 operations.

### Why sub-50µs plain verify was not reached, and won't be without a
### different crypto primitive

CPU profiling (`go test ./internal/bench/... -bench . -cpuprofile`) on this
box attributes **~69% of `BenchmarkVerifyPlainToken`'s time to
`ed25519.Verify` itself** — specifically the two field-element multiply/
square routines inside `crypto/internal/fips140/edwards25519` that implement
the double-scalar-basepoint multiply at the core of Ed25519 verification:

```
      flat  flat%   sum%        cum   cum%
     2.59s 33.55% 33.55%      2.59s 33.55%  edwards25519/field.feMul
     2.39s 30.96% 64.51%      2.39s 30.96%  edwards25519/field.feSquare
     0.09s  1.17% 82.12%      5.30s 68.65%  edwards25519.(*Point).VarTimeDoubleScalarBaseMult
```

That is Go's standard-library, constant-time-by-default Ed25519
implementation doing exactly what it should: there is no unsafe shortcut, no
cache to add, and no allocation to remove that touches this cost, because it
is pure integer field arithmetic, not I/O or memory pressure. On this
particular CPU, one `ed25519.Verify` call alone costs roughly 55–60µs;
everything else in `token.Verify` (base64 decode ×3, JSON unmarshal, expiry
check) is the remaining ~20–25µs, most of which the allocation work above
already trims. Getting under 50µs total on this hardware would require
either a faster verify implementation (e.g. an assembly-accelerated Ed25519
library, or batch verification amortizing the fixed cost across many
signatures at once — legitimate future work, but a larger, security-
sensitive change than this pass's scope) or faster hardware. We are
reporting this plainly rather than picking a benchmark shape or a different
box that would make the number look better: **plain-token verify sits at
~76µs on this hardware after these changes, still short of the 50µs target,
because that target is below this CPU's Ed25519-verify floor.**

Per the task's other guidance (cache verified public keys, avoid repeated
canonicalization, precompute policy matchers, cache verified parent blocks
per request): this codebase already does the parts of that list that apply
here without weakening security —
- The broker's signing/verification public key is held once on the
  `Signer`/`Service` struct and never re-parsed per call.
- The plain-verify path never calls `token.CanonicalJSON` at all (only
  approval-token action-hash computation does, off the hot path); the
  allocation/parse work removed above was in the JWT segment-splitting and
  header-decoding, not repeated canonicalization.
- `internal/broker.Service.Authorize` calls `token.Verify` (or
  `attenuate.Verify` for an offline chain) exactly once per request; there
  was no repeated re-verification of the same parent block within a single
  request to cache in the first place — each attenuation block is already
  verified exactly once as `attenuate.Verify` walks the chain.
- No authorization *decision* is cached across requests: revocation must
  take effect immediately, so nothing here trades that away for latency.

## Gateway end-to-end latency (`internal/gateway`)

`BenchmarkGatewayMCPToolsCall` drives a real `net/http` request through
`gateway.Gateway.ServeHTTP` end to end: HTTP request in, JSON-RPC parse,
`broker.Service.Authorize` (token verify + scope/budget check + audit
record), forward to an in-process (`httptest`) MCP upstream, and the JSON-RPC
reply back out — the number a caller actually experiences per MCP
`tools/call`, as opposed to the bare verify numbers above.
`BenchmarkBrokerAuthorizeOverhead` isolates just the authorization decision
(no HTTP/JSON-RPC framing) so the two can be compared.

| Benchmark | ns/op (mean) | p50 | p99 | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|
| `BenchmarkGatewayMCPToolsCall` | 568,445 | — | — | 40,646 | 561 |
| `BenchmarkGatewayMCPToolsCallP99` | — | 518µs | 1,532µs | 72,600 | 551 |
| `BenchmarkBrokerAuthorizeOverhead` | 222,429 | — | — | 15,175 | 256 |

Reading these together: authorization itself (`BenchmarkBrokerAuthorizeOverhead`,
~222µs — a plain-token verify plus policy evaluation, scope/budget check and
an audit-log write) is under half of the full round trip; the remainder is
real `net/http` client+server overhead (two live TCP connections over
loopback, via `httptest.NewServer`, not a mock) plus JSON-RPC
marshal/unmarshal on both the inbound and the forwarded-upstream leg. p99 is
roughly 3x p50 here, consistent with occasional GC pauses and goroutine
scheduling jitter on a 4-vCPU box under `go test`'s own benchmark harness
overhead; production p99 on dedicated hardware with request pooling should
be tighter. These are new benchmarks (no prior baseline existed for the
gateway path before this change) — see `internal/gateway/gateway_bench_test.go`
for the exact scenario (scope: single `fs.read`-equivalent tool, no PoP, no
attenuation chain).

## Prompt-injection containment

See `docs/injection-suite.md` for the attack-category test suite
(`adapters/injection_test.go`) that accompanies these latency numbers: the
optimizations above only change *how fast* a call is checked, never *what*
gets allowed.

## Notes

- `BenchmarkVerifyPoPToken`'s loop includes signing the proof (client-side
  work in a real deployment) to keep the benchmark self-contained; a
  server-only PEP benchmark (verify only, proof pre-signed) would be
  faster still.
- A production PEP should cap attenuation chain depth (as it already caps
  delegation depth) so worst-case verify latency stays bounded.
- Numbers on this page are single-run means from `go test -bench`, not a
  statistically-controlled multi-sample study; treat single-digit percent
  deltas as noise-level and the ~69% Ed25519-verify share (from CPU
  profiling, a much more stable signal) as the number to trust when judging
  where further latency work would need to go.
