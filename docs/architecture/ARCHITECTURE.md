# Aegis-MCP Architecture

## Crate responsibilities

| Crate | Role | Key API |
| ----- | ---- | ------- |
| `aegis-core` | Shared types: `Decision`, `TaintKind`/`TaintLabel`, `RiskAssessment`, `SecurityContext`, `PolicyOutcome`, `FinalVerdict`; `combine_verdict`; `redact_secrets` | `combine_verdict(&SecurityContext) -> FinalVerdict` |
| `aegis-config` | `aegis.yaml` parse/validate/env-overrides (`AEGIS_POLICY_PATH`, `AEGIS_AUDIT_DB`, `AEGIS_FAIL_CLOSED`, `AEGIS_CLASSIFIER`, `AEGIS_MAX_BYTES`, `AEGIS_RATE_RPS`, `AEGIS_RATE_BURST`, `AEGIS_POLICY_BUNDLE`, `AEGIS_POLICY_PUBLIC_KEY`, `AEGIS_REQUIRE_SIGNED`, `AEGIS_OTEL_ENABLED`, `AEGIS_OTLP_ENDPOINT`/`OTEL_EXPORTER_OTLP_ENDPOINT`) with safe defaults | `Config::from_file`, `Config::validate` |
| `aegis-protocol` | JSON-RPC 2.0 validation, MCP method registry, `tools/call` extraction, `tools/list` definition capture, canonical JSON, error responses, **transport abstraction** (`Transport`, stdio framing, HTTP/SSE) | `parse_message(raw, max_bytes)`, `HttpTransport::send`, `parse_sse_stream` |
| `aegis-policy` | Ordered first-match engine, condition matchers, ed25519 signed bundles + verified loading | `Engine::load_dir/load_yaml_str/load_verified/evaluate/validate`, `sign_bundle/verify_bundle/generate_keypair` |
| `aegis-taint` | `TaintStore`: source classification, union propagation, sanitize, audited declassify | `taint_value/propagate/sanitize/declassify/source_from_tool` |
| `aegis-security` | Deterministic detectors: filesystem, shell, SQL, network, secrets, tool-poisoning L1/L2 | `inspect_filesystem/shell/sql/network`, `contains_secret`, `inspect_tool_description` |
| `aegis-classifier` | `RiskClassifier` trait; `HeuristicClassifier` (default), `OnnxClassifier` (fail-safe fusion), `NoopClassifier` | `HeuristicClassifier.classify`, `score_text` |
| `aegis-audit` | Hash-chained SQLite WAL events, incidents, approvals with expiry + grants, correlation | `AuditLog::{append,verify,list_events,create_incident,…,create_approval,set_approval,sweep_expired,find_approved_grant}`, `correlate_incident` |
| `aegis-sandbox` | `SandboxExecutor` trait; `RestrictedProcessSandbox`; `WasmtimeSandbox` (experimental) | `RestrictedProcessSandbox::execute` |
| `aegis-observability` | Prometheus metrics + JSON tracing + OpenTelemetry (W3C traceparent, OTLP/HTTP export, redacted spans) | `Observability::init_with_config`, `TraceContext`, `export_otlp_span`, `render_prometheus` |
| `aegis-proxy` | `Gateway` pipeline, `ToolRegistry` fingerprinting, per-session rate limiter, approval grants, signed-bundle enforcement (`load_policy`), REST inspect shapes | `Gateway::{new,load_policy,inspect_tool_call,handle_line,with_components}`, `fingerprint_tool`, `RateLimiter` |
| `aegis-cli` | `aegis-mcp` binary: proxy (stdio + `--upstream-url` HTTP), inspect, tools, policy (+keygen/sign/verify), audit, incidents, approvals, config, benchmark, serve (+`--bundle/--public-key/--require-signed-bundle`) | `crates/aegis-cli/src/main.rs` |

## Pipeline

```
stdin line → per-session rate-limit check (token bucket; RATE_LIMITED + -32000 on excess)
  → parse_message (size + version + id checks; aegis_parser_latency observed)
  → tool definitions? → fingerprint_tool → ToolRegistry::observe
      → TOOL_DISCOVERED / TOOL_CHANGED audit events
  → tools/call? → whole-pipeline timeout (request_timeout_ms; timeouts always fail closed)
      → inspect_tool_call:
      1. detectors (fs/shell/sql/network/secrets/poison) → det_risk, taints, violations
      2. taint inheritance from referenced value_ids
      3. policy evaluate → PolicyOutcome
      4. classifier (800 ms timeout, fail-safe) → RiskAssessment
      5. combine_verdict + deterministic guardrail → FinalVerdict
      6. REQUIRE_APPROVAL? → grant lookup (APPROVED+live+identical → ALLOW/approval-grant)
         else mint/reuse PENDING request (id embedded in the block reason)
      7. audit POLICY_* + INJECTION_DETECTED + TAINT_PROPAGATED (+taint_events_total per kind)
         + incident correlation; metrics (requests/blocks/policy/classifier/proxy/approvals)
  → ALLOW/Warn → forward upstream transparently
  → DENY/RequireApproval/Sandbox → synthesized JSON-RPC error (-32000), never forwarded
```

Notifications (no `id`) and non-`tools/call` methods pass through after
definition fingerprinting — interception only blocks execution requests.

## Decision-combination logic

`combine_verdict` (`crates/aegis-core/src/lib.rs`):

1. No policy result → `DENY` (`fail-closed-no-policy`).
2. Policy `DENY` → `DENY`, unconditionally. AI score is ignored.
3. Policy `ALLOW` + AI ≥ 0.85 → `DENY` ("escalated … advisory").
4. Policy `ALLOW` + AI ≥ 0.6 → `REQUIRE_APPROVAL`.
5. Otherwise the policy decision stands.

The gateway adds the deterministic counterpart (`crates/aegis-proxy`):
`det_risk >= 0.85` forces `DENY` (`deterministic-injection-block`) even when a
permissive policy matched; `det_risk >= 0.5` forces at least
`REQUIRE_APPROVAL` (`deterministic-injection-review`). Net effect: **AI is
escalate-only; deterministic guardrails are enforce-only; policy is the only
source of ALLOW.**

## Data flow & stores

- In-memory per-gateway: `ToolRegistry` (server|name → `ToolRecord`),
  `TaintStore` (value_id → labels). Both die with the process; audit is the
  durable record.
- Durable: SQLite DB at `audit.database` (WAL mode) with `events`,
  `incidents`, `approvals` tables. `serve` exposes read endpoints over it.
- Secrets never persist: detectors flag presence (`SECRET` taint) without
  storing values; `redact_secrets` scrubs logs/traces.

## Audit hash-chain design

`append` builds a canonical string
`event_id|timestamp|session|tool|event_type|decision|policy|risk|request_hash|prev`
(BLAKE3 hex → `event_hash`), with `previous_event_hash` pointing at the prior
row (`GENESIS` for the first). `verify` re-reads rows in `rowid` order,
recomputes each link, and returns `(checked, ok)` — any edit, delete, or
reorder breaks the chain. Decision is serialized as JSON (`serde_json::to_string
(&Option<Decision>)`) identically on both sides so verification is
self-consistent. Chain writes hold a mutex; readers (`list_events`) take the
same lock briefly — throughput is audit-bound only on deny-heavy workloads,
which is the safe direction to be slow in.

## Transports (stdio + HTTP/SSE)

`aegis-protocol` exposes a `Transport` trait (`send(frame) -> Option<reply>`):

- **stdio**: newline-delimited frames (`encode_stdio_frame` /
  `decode_stdio_frames`). The CLI `proxy --server "<cmd>"` spawns the child
  and pumps stdin→inspect→child, child→client. Pure framing helpers are
  unit-tested, including hostile bytes (lossy decode, no panics).
- **HTTP/SSE**: `HttpTransport { base_url }` POSTs the frame to the base URL
  (`Accept: application/json, text/event-stream`). SSE bodies are unwrapped
  via `parse_sse_stream` / `sse_jsonrpc_frames` (blank-line dispatch,
  `event:`/`data:` fields, multi-line data, comment lines, CRLF). Only
  `http://` is supported by the built-in client (no TLS deps);
  `https://` fails closed with a descriptive error. The CLI
  `proxy --upstream-url http://host:port` reuses the exact same inspection
  pipeline — blocked calls never touch the network.

## Policy loading & signed-bundle enforcement

`Gateway::load_policy` (unit-tested):

1. `require_signed=true` → `bundle` + `public_key` required; the bundle is
   loaded with `Engine::load_verified` (digest + ed25519 checked). Any
   failure is a startup error — the gateway never serves traffic.
2. Otherwise, a configured `bundle` + `public_key` is tried
   opportunistically (success preferred, failure warns and falls back).
3. Otherwise the policy directory loads recursively in sorted path order;
   total failure yields an empty fail-closed engine (deny-all).

## Observability (Prometheus + OpenTelemetry)

- Prometheus (`/metrics`): `aegis_requests_total`, `aegis_blocks_total`,
  `aegis_policy_latency`, `aegis_classifier_latency`, `aegis_proxy_latency`,
  `aegis_parser_latency`, `aegis_taint_events_total`, `aegis_approvals_total`.
- Tracing: JSON `tracing-subscriber` logs with secret redaction.
- OpenTelemetry (`aegis-observability`): W3C `traceparent` (`TraceContext::new`
  / `from_traceparent` / `traceparent`), OTLP/HTTP JSON export
  (`otlp_body` + `export_otlp_span` → `POST <endpoint>/v1/traces`, 5 s
  timeouts, `http://` only). `POST /api/inspect` accepts/propagates
  `traceparent` and always returns one; export is best-effort after the
  verdict with redacted attributes (tool/decision/policy only — never args
  or secrets) and can never change ALLOW/DENY. Disabled by default
  (`observability.otel_enabled=false`); enable with `otlp_endpoint`
  (`AEGIS_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT`).
