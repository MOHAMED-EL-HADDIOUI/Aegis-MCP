# AGENTS.md — Aegis-MCP

Zero-trust MCP gateway (Rust workspace, 13 crates). Default-deny proxy: parse → detectors → taint → policy → advisory AI → authorize → hash-chained audit.

## Layout

- `crates/aegis-{core,config,protocol,policy,taint,security,classifier,audit,sandbox,observability,proxy,cli,fuzz}/` — dep direction: `core` ← `config/protocol/taint/security/classifier` ← `policy` ← `audit` ← `proxy` (+`observability`) ← `cli`. `sandbox` standalone.
- Pipeline wiring: `Gateway::inspect_tool_call` (`crates/aegis-proxy/src/lib.rs`); verdict: `combine_verdict` (`crates/aegis-core`); detectors: `inspect_*` (`crates/aegis-security/src/lib.rs`); policy match: `cond_matches` (`crates/aegis-policy/src/lib.rs`).
- Config: `aegis.yaml` (proxy mode, `./policy`, `./aegis.db`). Rules: `policy/{base,filesystem,shell,network,postgres}/`, examples in `policy/examples/`. Dashboard: `dashboard/` (Next.js, consumes `serve` REST API).

## Commands (`make` == `just`; prefer `make`)

```sh
cargo build --workspace
cargo test --workspace                       # full suite
cargo test -p aegis-proxy                    # single crate
cargo test -p aegis-proxy <test_name>        # single test
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings   # pre-push gate (CI order: fmt → clippy → test)
make security   # test + config validate + policy validate (dir + 5 files) + audit verify on :memory:
make fuzz       # stable harness: cargo test -p aegis-fuzz + 4 fuzz-* binaries (no nightly needed)
cargo run -q -p aegis-cli -- benchmark --json
cargo run -p aegis-cli -- serve --bind 127.0.0.1:8787   # dashboard backend (`make serve`; `make dashboard` alias)
```

Policy / config verification:

```sh
cargo run -q -p aegis-cli -- config validate
cargo run -q -p aegis-cli -- policy validate --policy ./policy            # dir: recurses sorted
cargo run -q -p aegis-cli -- policy validate --policy ./policy/<domain>/base.yaml
cargo run -q -p aegis-cli -- policy test --policy ./policy/<domain>/base.yaml --fixture ./case.json
```

Frontend (only if touching `dashboard/`): `cd dashboard && npm ci && npm run lint && npm run build` (Node 20+; Rust 1.78+).

## Rules that differ from defaults

- **Policy: ordered first-match wins, no match = DENY.** Put narrow `deny` before broad `allow`; never add a trailing `allow` catch-all. Condition keys: `tool server user environment branch path path_prefix url destination http_method sql_op operation taint risk_gte rate time resource argument.<field>`.
- **Guardrail thresholds are security boundaries:** `det_risk >= 0.85 → DENY` (overrides `combine_verdict`), `>= 0.5 → REQUIRE_APPROVAL`; classifier is **escalate-only** (`ALLOW → REQUIRE_APPROVAL → DENY`, never reverse; 0.6/0.85). Scope such edits as `security:`, add adversarial tests.
- **Detectors stay pure, sync, <1 ms each** on the critical path; AI classifier is off-path (800 ms timeout, fail-safe). New detector: `inspect_<domain>` in `aegis-security` → wire into `Gateway::inspect_tool_call` (bump `det_risk`, push `TaintLabel`, violation string) → tests: true positive + obfuscated variant + benign near-miss. Never weaken an existing test.
- **Audit `append`/`verify` canonical encoding must stay byte-identical** both sides; changing it breaks existing DBs (needs migration note). Never log raw tool args/prompts/secrets — use `redact_secrets`.
- **Side-effect safety:** `aegis.db*` is gitignored runtime state — never commit it. Use `AEGIS_AUDIT_DB=":memory:"` for `audit verify` demos (as `make security` does). CLI reads `--config ./aegis.yaml` by default; env overrides `AEGIS_POLICY_PATH _AUDIT_DB _FAIL_CLOSED _CLASSIFIER _MAX_BYTES _RATE_RPS/_RATE_BURST _POLICY_BUNDLE/_POLICY_PUBLIC_KEY/_REQUIRE_SIGNED`, OTLP via `AEGIS_OTEL_ENABLED`/`AEGIS_OTLP_ENDPOINT`/`OTEL_EXPORTER_OTLP_ENDPOINT` — endpoint must be `http://`, `https://` fails export.
- **Commits/PRs:** Conventional Commits (`feat|fix|docs|refactor|perf|test|chore|ci|security(<scope>): …`); policy changes need fixture + `policy test`/`validate` evidence; docs go in `docs/`, `README.md`, or `CHANGELOG.md [Unreleased]`. Report vulns per `SECURITY.md`, never in a public PR.
