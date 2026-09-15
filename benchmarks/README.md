# Benchmarks

`aegis-mcp benchmark` reports three **micro-benchmarks** (mean µs/op over
thousands of iterations) plus a `pass` flag against the budgets in `targets`:

| metric | what it measures | budget |
|---|---|---|
| `parse_us` | `parse_message` on a `tools/call` line (5000 iters) | < 1000 µs |
| `policy_us` | `Engine::evaluate` single-rule match (5000 iters) | < 1000 µs |
| `fingerprint_us` | `fingerprint_tool` incl. BLAKE3 (2000 iters) | < 1000 µs |

## Run

```sh
./benchmarks/run.sh            # release build, writes benchmarks/results.json
```

Windows note: run the same pipeline in PowerShell
(`cargo run --release -p aegis-cli -- benchmark --json | Tee-Object benchmarks/results.json`)
or from WSL with a Linux cargo toolchain installed *inside* WSL (a Windows
`cargo.exe` on the interop PATH is not reliably resolved by bare `cargo` in
some WSL builds).

`benchmarks/baseline.json` is a real release run on the maintainer machine
(Windows 11, cargo 1.98.1, 2026-09-14): parse ~2.0 µs, policy ~0.2 µs,
fingerprint ~2.1 µs — all two orders of magnitude under budget. Re-run on
your hardware and diff `results.json` against `baseline.json`; investigate
any metric that regresses >2x.

## Full-pipeline latency (p50/p95/p99)

The CLI benchmark does not time the whole gateway pipeline
(detectors + policy + heuristic classifier + audit write). For that, use the
per-call latency returned by `Gateway::inspect_tool_call` (see
`crates/aegis-proxy/tests/gateway_e2e.rs`, which asserts it is reported).
Example: repeat the release benchmark N times and take percentiles of the
reported means, e.g. in PowerShell:

```powershell
$xs = 1..30 | ForEach-Object {
  (cargo run -q --release -p aegis-cli -- benchmark --json | ConvertFrom-Json).parse_us
}
$sorted = $xs | Sort-Object
"p50={0:N3} p95={1:N3} p99={2:N3}" -f $sorted[15], $sorted[28], $sorted[29]
```

No `criterion` harness is vendored on purpose: the CLI output above is the
source of truth and stays in sync with the shipped binary by construction.
