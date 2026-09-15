# CLI Reference (`aegis-mcp 0.1.0`)

Global flags (every command): `--json` (pretty-print), `--verbose`,
`--quiet`, `--config <CONFIG>` (default `./aegis.yaml`). All outputs below
are genuine runs from this repo unless marked otherwise. Non-`--json` output
is compact single-line JSON; `--json` pretty-prints (same data).

## `proxy` — transparent stdio security proxy

```sh
aegis-mcp proxy [--client stdio] --server "<cmd args...>"
aegis-mcp proxy --upstream-url http://127.0.0.1:9000
aegis-mcp proxy --server "<cmd>" --bundle ./bundle.json --public-key <pub-hex> --require-signed-bundle
```

Forwards stdin→server with per-line inspection; blocked calls get a
synthesized `-32000` error and are never forwarded. Genuine session:

```sh
$ aegis-mcp --config aegis-demo.yaml proxy --server "cmd /C exit 0" < calls.jsonl
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Aegis Deny: [default-deny] no rule matched; failing closed"}}
{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Aegis Deny: [deterministic-injection-block] deterministic risk 0.85 forced DENY (injection: …); advisory policy was deterministic-injection-block"}}
```

(`--server` or `--upstream-url` is required; omitting both errors. The
trailing broken-pipe error when the server exits early is expected — the
ALLOWed line was forwarded to a dead process. `--upstream-url` forwards
allowed calls over HTTP JSON-RPC via `HttpTransport` — SSE `data:` frames
are unwrapped; blocked calls never touch the network; `https://` fails
closed. `--require-signed-bundle` (with `--bundle` + `--public-key`)
refuses to start unless the signed bundle verifies — fail-closed startup.)

## `inspect <FILE>` — poison/fingerprint report for tool definitions

```sh
$ aegis-mcp inspect tools.json
{"tools":[{"tool":"helper","tool_id":"e4fda54e1715cef7","schema_hash":"daab8763…","description_hash":"e85f756f…","poison_score":1.0,"poison_reasons":["lexical '…' ×3","1 embedded url(s)"],"urls":["http://evil.example.com"]}]}
```

(Hashes truncated here for readability; full values in README attack demo.
`FILE` holds either `{"result":{"tools":[…]}}` or a bare tool array.)

## `tools list` — tools seen in audit log

```sh
$ aegis-mcp --config tmp.yaml tools list
{"tools":[]}     # fresh DB; populated DBs return TOOL_DISCOVERED names
```

## `tools fingerprint <FILE>` — alias of `inspect`

Same input/output as `inspect` (calls `inspect_file` directly).

## `policy test --policy <P> --fixture <F>` — offline decision check

```sh
$ aegis-mcp policy test --policy ./policy/network/base.yaml --fixture exfil.json
{"decision":"DENY","policy":"block-private-file-exfiltration","reason":"rule 'block-private-file-exfiltration' matched"}
$ aegis-mcp policy test --policy ./policy/filesystem/base.yaml --fixture traversal.json
{"decision":"DENY","policy":"default-deny","reason":"no rule matched; failing closed"}
$ aegis-mcp policy test --policy ./policy/filesystem/base.yaml --fixture legit.json
{"decision":"ALLOW","policy":"allow-read-project","reason":"rule 'allow-read-project' matched"}
```

Fixture fields honored: `tool`, `server`, `path`, `url`, `taints[]`,
`risk`, `args`. (`--policy` accepts a file or a flat directory of YAML.)

## `policy validate --policy <P>` — schema/consistency check

```sh
$ aegis-mcp policy validate --policy ./policy/filesystem/base.yaml
{"ok":true}
```

On failure: `{"ok":false,"errors":[…]}` plus non-zero exit. Note:
`--policy ./policy` validates every file recursively across all domain
subdirectories (`make security` does the same).

## `audit list [--limit 20]` — recent events (newest first)

Genuine row (fields trimmed): `POLICY_DENY/filesystem_read/DENY/default-deny`,
`INJECTION_DETECTED/…/fs: sensitive file pattern '.ssh'`,
`POLICY_DENY/echo/deterministic-injection-block/risk 1.0`,
`POLICY_ALLOW/filesystem_read/allow-read-project`. Fresh DB: `{"events":[]}`.

## `audit verify` — hash-chain integrity

```sh
$ aegis-mcp --config demo.yaml audit verify
{"checked":5,"ok":true}
$ AEGIS_AUDIT_DB=":memory:" aegis-mcp audit verify
{"checked":0,"ok":true}
```

Non-zero exit + `{"checked":N,"ok":false}` on any tamper/reorder.

## `incidents list` / `incidents set <ID> <STATUS>`

```sh
$ aegis-mcp incidents list
{"incidents":[]}
$ aegis-mcp incidents set INC-001 ACKNOWLEDGED
{"ok":true}
```

Statuses: `OPEN ACKNOWLEDGED MITIGATED RESOLVED FALSE_POSITIVE`
(anything else → `invalid incident status` error).

## `approvals list` / `approvals approve <ID>` / `approvals deny <ID>`

```sh
$ aegis-mcp approvals list
{"approvals":[]}
$ aegis-mcp approvals approve 3f9c…
{"ok":true}    # appends APPROVAL_GRANTED (deny → APPROVAL_DENIED)
```

Approving mints an expiring (1 h) grant: the gateway converts a later
identical `REQUIRE_APPROVAL` call (same server/tool/canonical args) to
`ALLOW` with policy `approval-grant`. Approving an expired or unknown id
fails closed (`UNPROCESSABLE` over HTTP, non-zero exit in CLI). Overdue
`PENDING` rows auto-transition to `EXPIRED` on every approval read/write.

## `policy keygen` / `policy sign` / `policy verify` — signed bundles

```sh
$ aegis-mcp policy keygen
{"public_key":"…","secret_key":"…","warning":"store the secret key offline; …"}
$ aegis-mcp policy sign --policy ./policy --key <secret-hex> --out bundle.json
{"digest":"e3fc…","ok":true,"out":"bundle.json","rules":15}
$ aegis-mcp policy verify --bundle bundle.json --key <public-hex>
{"digest":"e3fc…","ok":true,"rules":15}
```

Ed25519 over the BLAKE3 digest of canonical `{version, rules}` JSON.
Verification fails closed on modified rules, wrong key, or malformed hex —
never panics on hostile input (fuzz-covered).

## `config validate` — validate `aegis.yaml`

```sh
$ aegis-mcp config validate
{"ok":true}
```

Checks `max_request_bytes` (1–256 MiB), `request_timeout_ms` (1–300 000 ms),
`rate_limit_rps` (0–100 000; 0 disables), `rate_limit_burst` (1–1 000 000),
non-empty `policy.path`, signed-bundle coherence (`require_signed` needs
`bundle` + `public_key`), OTel coherence (`otel_enabled` needs
`otlp_endpoint` with `http(s)://`). Env overrides: `AEGIS_POLICY_PATH`,
`AEGIS_AUDIT_DB`, `AEGIS_FAIL_CLOSED`, `AEGIS_CLASSIFIER`, `AEGIS_MAX_BYTES`,
`AEGIS_RATE_RPS`, `AEGIS_RATE_BURST`, `AEGIS_POLICY_BUNDLE`,
`AEGIS_POLICY_PUBLIC_KEY`, `AEGIS_REQUIRE_SIGNED`, `AEGIS_OTEL_ENABLED`,
`AEGIS_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT`.

## `benchmark` — micro-benchmarks vs targets

```sh
$ aegis-mcp benchmark --json
{"fingerprint_us":1.77,"parse_us":1.92,"pass":true,"policy_us":0.19,
 "parse":{"mean_us":1.92,"p50_us":1.8,"p95_us":2.5,"p99_us":3.2},
 "policy":{"mean_us":0.19,"p50_us":0.2,"p95_us":0.2,"p99_us":0.3},
 "fingerprint":{"mean_us":1.77,"p50_us":1.7,"p95_us":1.8,"p99_us":2.0},
 "targets":{"fingerprint_us":1000.0,"overhead_ms":5.0,"parse_us":1000.0,"policy_us":1000.0}}
```

`pass` requires **p99** < targets (release numbers above; dev is ~5× slower).

## `serve [--bind 127.0.0.1:8787]` — REST API for the dashboard

```sh
$ aegis-mcp serve --bind 127.0.0.1:8787
aegis-mcp api on http://127.0.0.1:8787
$ aegis-mcp serve --bind 0.0.0.0:8787 --bundle ./bundle.json --public-key <pub-hex> --require-signed-bundle
```

`GET /health` → `{"ok":true,"service":"aegis-mcp"}`; `GET /api/events`,
`/api/incidents`, `/api/approvals` → `{"events"|"incidents"|"approvals":[…]}`;
`GET /metrics` → Prometheus text (`aegis_requests_total`,
`aegis_blocks_total`, `aegis_policy_latency`, `aegis_classifier_latency`,
`aegis_proxy_latency`, `aegis_parser_latency`, `aegis_taint_events_total`,
`aegis_approvals_total`).

`POST /api/inspect` runs one call through the gateway pipeline without
forwarding — `{"tool","server","session","args"}` → `{"decision","policy",
"reason","risk_score","taints","latency_ms","traceparent"}`. A
`REQUIRE_APPROVAL` verdict mints a `PENDING` approval (id in `reason`).
W3C `traceparent` request header is accepted and propagated (invalid values
fall back to a fresh context, never an error); the response always carries
`traceparent`. When OTel export is enabled the redacted span (tool /
decision / policy only — never args or secrets) is exported best-effort.

`POST /api/approvals/:id` with `{"action":"approve"|"deny"}` decides it:
200 + `{"ok":true,"status":"APPROVED"|"DENIED"}`, 400 on bad action, 422 on
expired/unknown ids (fail-closed).

