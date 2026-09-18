# Integration tests

End-to-end tests live **in-crate** (compiled and run by
`cargo test --workspace`), not in this directory:

- `crates/aegis-proxy/tests/mvp_flow.rs` — the MVP proof (§30 of the build
  prompt): malicious content → taint → policy DENY → incident → verified
  audit chain, plus a benign control. The single test that must never break.
- `crates/aegis-proxy/tests/rest_api.rs` — dashboard/serve REST API over
  real HTTP (`/health`, `/api/*`, `/metrics`, traceparent round-trip).
- `crates/aegis-audit/tests/chain.rs` — hash-chain append/verify on temp DBs.

Live-proxy fixtures (manual runs, `proxy --server …`):

- `scripts/mock-mcp-server.py --mode good|malicious|poisoned|slow|broken|postgres|exfiltration`
- `scripts/demo.sh` (+ `demo_expected.txt`) — scripted attack demonstrations.
