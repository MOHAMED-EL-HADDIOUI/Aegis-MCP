# Performance

## Targets

| Stage | Target | Measured (`aegis-mcp benchmark`, dev profile) |
| ----- | ------ | --------------------------------------------- |
| JSON-RPC parse | < 1 ms | ~8.8 µs (`parse_us: 8.8476`) |
| Policy evaluation | < 1 ms | ~0.4 µs (`policy_us: 0.4028`) |
| Tool fingerprint (BLAKE3) | < 1 ms | ~10.6 µs (`fingerprint_us: 10.551`) |
| End-to-end gateway overhead | < 5 ms | ms-scale (audited per-request; `pass: true`) |

Genuine full output:

```json
{
  "fingerprint_us": 10.551,
  "parse_us": 8.8476,
  "pass": true,
  "policy_us": 0.4028,
  "targets": {
    "fingerprint_us": 1000.0,
    "overhead_ms": 5.0,
    "parse_us": 1000.0,
    "policy_us": 1000.0
  }
}
```

## How to run benchmarks

```sh
cargo run -q -p aegis-cli -- benchmark --json   # machine-readable
make benchmark                                   # same via Makefile
just benchmark                                   # same via justfile
```

The harness (`run_benchmark` in `crates/aegis-cli/src/main.rs`) times
5 000 `parse_message` + 5 000 `Engine::evaluate` + 2 000
`fingerprint_tool` iterations and compares against the `targets` map.
Re-run on release builds (`--release`) for deploy-representative numbers;
expect 2–5× better than dev profile. Numbers vary per machine — record the
commit, profile, and CPU alongside results.

## How to read p50/p95/p99

The CLI reports mean **and** p50/p95/p99 per stage (`pass` requires p99 <
targets). For live distributions, use the Prometheus histograms
(`aegis_policy_latency`, `aegis_classifier_latency`,
`aegis_proxy_latency`, `aegis_parser_latency` in
`crates/aegis-observability/src/lib.rs`) behind `serve`. Investigate when
p99 proxy latency approaches
the 5 ms budget: usual causes are audit-DB contention (WAL on slow disk),
pathological regex input, or classifier timeouts (which fail safe but cost
the full 800 ms — watch `aegis_classifier_latency`).

## AI off the critical path

`Gateway::classify` races the classifier against an 800 ms timeout and falls
back to `RiskAssessment::default()` (risk 0.0) on timeout or error; the
`OnnxClassifier` without a model degrades to the heuristic. Enforcement never
waits on AI: deterministic detectors + policy + guardrails produce the verdict
synchronously, and AI can only escalate afterwards via `combine_verdict`.
Consequence for capacity planning: size CPU/disk for parse+policy+audit
(microseconds + SQLite write), and treat classifier latency as additive
observability signal, not a blocking dependency.

## Observability overhead

OTel export is best-effort and off the verdict path: `POST /api/inspect`
exports at most one span per request, failures are swallowed, and a disabled
exporter costs one boolean check. The OTLP/HTTP client has a 5 s timeout but
runs after the verdict is computed — it cannot delay ALLOW/DENY. HTTP
upstream proxying (`--upstream-url`) adds one network round-trip per allowed
call only; blocked calls never touch the network.
