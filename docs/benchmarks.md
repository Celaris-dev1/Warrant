# Verification latency benchmarks

Run with:

```bash
go test ./internal/bench/... -bench . -benchmem -run '^$'
```

Source: `internal/bench/verify_bench_test.go`.

## Results

Machine: Intel(R) Xeon(R) Processor @ 2.10GHz (CI/dev container, single run,
`go test -bench . -benchmem`). Re-run locally for your own hardware — these
numbers are indicative, not a guaranteed SLA.

| Benchmark | ns/op | ~ per verify | B/op | allocs/op |
|---|---:|---:|---:|---:|
| `BenchmarkVerifyPlainToken` | 65,391 | 0.065 ms | 2,160 | 35 |
| `BenchmarkVerifyPoPToken` | 178,579 | 0.179 ms | 7,642 | 92 |
| `BenchmarkVerifyAttenuatedChain3Blocks` | 264,813 | 0.265 ms | 3,985 | 52 |

All three are sub-millisecond, well within budget for a PEP sitting in the
hot path of every tool call:

- **Plain token**: one Ed25519 signature verification plus JSON unmarshal.
- **PoP token**: a plain verify, plus signing and verifying a second
  Ed25519 proof and a replay-store lookup — roughly 2.7x the plain cost,
  dominated by the extra signature operations (Ed25519 verify is the
  expensive step, not JSON or map work).
- **3-block attenuated chain**: a plain verify plus 3 more Ed25519
  signature checks and 3 structural scope intersections — roughly 4x the
  plain cost, scaling close to linearly with chain depth.

## Notes

- `BenchmarkVerifyPoPToken`'s loop includes signing the proof (client-side
  work in a real deployment) to keep the benchmark self-contained; a
  server-only PEP benchmark (verify only, proof pre-signed) would be
  faster still.
- A production PEP should cap attenuation chain depth (as it already caps
  delegation depth) so worst-case verify latency stays bounded.
