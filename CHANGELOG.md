# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Approval grants: `REQUIRE_APPROVAL` mints/reuses a `PENDING` request (id in
  the block reason); approving unblocks the identical call via an expiring
  `approval-grant` verdict. Expiry enforced with lazy `sweep_expired()`;
  approving expired/unknown ids fails closed. Surfaced in CLI, dashboard,
  and `POST /api/approvals/:id`.
- Per-session token-bucket rate limiter (`RateLimiter`, 200 rps / 400 burst
  defaults, `AEGIS_RATE_RPS`/`AEGIS_RATE_BURST` overrides) with `RATE_LIMITED`
  audit events; whole-pipeline `request_timeout_ms` budget that always fails
  closed. Both covered by gateway tests.
- Ed25519 signed policy bundles: `generate_keypair`/`sign_bundle`/
  `verify_bundle` plus `policy keygen|sign|verify` CLI commands.
  `Engine::load_verified` + `Gateway::load_policy` enforce them at startup
  (`policy.bundle/public_key/require_signed` in `aegis.yaml`,
  `--bundle/--public-key/--require-signed-bundle` on `proxy`/`serve`,
  `AEGIS_POLICY_BUNDLE`/`AEGIS_POLICY_PUBLIC_KEY`/`AEGIS_REQUIRE_SIGNED`).
- `POST /api/inspect` verdict-over-HTTP endpoint; dashboard approvals page
  now acts on approvals (no longer read-only).
- `TAINT_PROPAGATED` audit events + per-kind `aegis_taint_events_total`
  metrics; new `aegis_parser_latency` and `aegis_approvals_total` metrics.
- Benchmark mean + p50/p95/p99 per stage (`pass` on p99); release baseline
  refreshed in `benchmarks/baseline.json`.
- Fourth fuzz target `fuzz-config` (config YAML, taint ops, classifier,
  bundle crypto paths); `make fuzz` runs the real harness. Protocol fuzz now
  also covers stdio framing, SSE parsing, and HTTP URL validation;
  config fuzz also covers traceparent parse and OTLP body building.
- Transport abstraction (`aegis-protocol::Transport`): stdio framing helpers
  + `HttpTransport` (HTTP JSON-RPC POST, SSE unwrap, `http://` only,
  `https://` fail-closed) + `proxy --upstream-url`; SSE blank-line dispatch,
  multi-line data, comment/CRLF handling (unit + live-axum tests).
- OpenTelemetry (`aegis-observability`): W3C `traceparent`
  (`TraceContext::new/from_traceparent/traceparent`), OTLP/HTTP JSON export
  (`otlp_body`/`export_otlp_span`, 5 s timeouts, best-effort), `POST
  /api/inspect` accepts/returns `traceparent`, `observability.otel_enabled`/
  `otlp_endpoint` config (`AEGIS_OTEL_ENABLED`/`AEGIS_OTLP_ENDPOINT`/
  `OTEL_EXPORTER_OTLP_ENDPOINT`).
- Local test MCP server `scripts/mock-mcp-server.py`
  (good/malicious/poisoned/slow/broken modes) for live proxy verification.
- Zero-trust MCP proxy gateway (`aegis-proxy`): stdio transport proxying
  with per-line JSON-RPC inspection (`proxy --client stdio --server "<cmd>"`).
- Deterministic detector suite (`aegis-security`): filesystem traversal +
  sensitive-file + workspace containment, shell pipe-to-shell/dangerous
  patterns via real tokenization, SQL destructive/mutation-without-WHERE/
  privilege/COPY/extension checks with comment normalization, network
  metadata/localhost/allowlist guards, secret patterns, tool-poisoning
  L1 lexical + L2 structural (base64, zero-width unicode, URL-encoded,
  embedded URLs, shell snippets, fs references) scoring.
- Ordered first-match policy engine (`aegis-policy`) with default-deny,
  wildcard/glob matching, `taint`/`destination`/`path_prefix`/`risk_gte`/
  `argument.<field>` conditions, and BLAKE3/ed25519 bundle digest helpers.
- Taint propagation store (`aegis-taint`): source classification, union
  propagation, sanitization, audited declassification, SECRET stickiness.
- Pluggable risk classifier (`aegis-classifier`): heuristic default plus
  ONNX-backed (`onnx` feature) fusion; timeout-guarded, escalate-only.
- Tamper-evident audit log (`aegis-audit`): BLAKE3 hash-chained SQLite WAL
  events, incident lifecycle, approval workflow, `correlate_incident`
  (injection + taint [+ egress] → PROMPT_INJECTION / DATA_EXFILTRATION).
- Tool fingerprint registry (`aegis-proxy`): BLAKE3 canonical-JSON schema
  and description hashes, `tool_id`, SCHEMA_CHANGE / PERMISSION_EXPANSION /
  DESCRIPTION_CHANGE drift detection (rug-pull defense).
- CLI (`aegis-cli` 0.1.0): `proxy`, `inspect`, `tools list|fingerprint`,
  `policy test|validate`, `audit list|verify`, `incidents list|set`,
  `approvals list|approve|deny`, `config validate`, `benchmark`, `serve`
  REST API (`/health`, `/api/events`, `/api/incidents`, `/api/approvals`).
- Sandboxing (`aegis-sandbox`): `RestrictedProcessSandbox` (env isolation,
  secret scrubbing, timeouts, output caps) with `SandboxExecutor` trait and
  `WasmtimeSandbox` experimental extension point.
- Observability (`aegis-observability`): Prometheus counters/histograms
  (`aegis_requests_total`, `aegis_blocks_total`, policy/classifier/proxy
  latency), JSON tracing with secret redaction.
- Shipped policy packs: `policy/base`, `policy/filesystem`,
  `policy/shell`, `policy/network`, `policy/postgres`, `policy/examples`.
- Default configuration `aegis.yaml` (fail-closed, heuristic classifier,
  SQLite audit, metadata-endpoint denial, 10 MiB / 5 s limits).

### Security

- Fail-closed defaults across parse, policy, classifier-timeout, and
  verdict-combination layers; AI advisory-only (escalate, never de-escalate).
- Signed-bundle enforcement at startup (`Gateway::load_policy` +
  `--require-signed-bundle`): missing/unverifiable bundles refuse to start;
  opportunistic verified-bundle preference otherwise. OTel spans carry only
  redacted verdict metadata (tool/decision/policy — never args/secrets).

### Fixed

- REST control-plane tests (`crates/aegis-proxy/tests/rest_api.rs`): fully
  async tokio client + direct `TcpListener::bind` (no `from_std`), absolute
  policy path — fixes Windows hang, 3/3 green in ~0.1 s.
- Docker runtime defaults to `serve --bind 0.0.0.0:8787` so plain
  `docker run` is reachable (K8s already overrode the bind explicitly).
- README workspace test count refreshed (92 tests green).

## [0.1.0] - 2026-09-14

### Added

- Initial workspace release: 12 crates (`aegis-core`, `aegis-config`,
  `aegis-protocol`, `aegis-policy`, `aegis-taint`, `aegis-security`,
  `aegis-classifier`, `aegis-audit`, `aegis-sandbox`,
  `aegis-observability`, `aegis-proxy`, `aegis-cli`).
- 40 unit tests green across the workspace (`cargo test --workspace`).
- Micro-benchmarks (`aegis-mcp benchmark`): parse ~8.8 µs, policy
  ~0.4 µs, fingerprint ~10.6 µs — all under the 1000 µs targets.
