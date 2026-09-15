# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest `0.1.x` release line receives security fixes. There is no
LTS branch yet; see [CHANGELOG.md](CHANGELOG.md) for release notes.

## Reporting a vulnerability

- Email: **security@aegis-mcp.example**
- Encrypt your report with our PGP key if it includes exploit detail or
  sensitive deployment information. State the key fingerprint you used in
  the message body so we can confirm it out of band. (Key distribution:
  request the current public key from the same address with subject
  `PGP KEY REQUEST`.)
- Include: affected version/commit, component/crate, reproduction steps
  (policy YAML + JSON-RPC fixture preferred), impact assessment, and any
  suggested mitigation.
- Do **not** open a public GitHub issue for a suspected vulnerability
  until it has been triaged.

### Response SLAs

| Step                                   | Target  |
| -------------------------------------- | ------- |
| Acknowledge receipt                    | 48 h    |
| Initial triage (valid / invalid, severity) | 5 days  |
| Fix + release for Critical issues      | 14 days |
| Fix + release for High issues          | 30 days |
| Public disclosure (after fix available)| coordinated with reporter |

We will keep the reporter informed at each step and credit them in the
advisory unless they ask to remain anonymous.

## Scope

In scope:

- Policy bypass (a `DENY` decision evaded through the proxy pipeline).
- Taint-tracking escapes (tainted tool output reaching a sink unlabeled).
- Audit-log tampering or hash-chain forgery (`crates/aegis-audit`).
- Tool-fingerprint / rug-pull detection bypass (`crates/aegis-proxy`).
- Detector bypasses with realistic payloads (path traversal, shell
  injection, SQL destructive statements, SSRF/metadata egress,
  prompt/tool poisoning) against `crates/aegis-security`.
- Secret leakage into logs, traces, metrics, or error responses.
- Authentication/authorization flaws in `serve` API endpoints.

Out of scope (see "What NOT to report") still welcome as regular issues
if framed as hardening ideas.

## Safe harbor

We consider in-good-faith security research against your own Aegis-MCP
deployments to be authorized. We will not pursue legal action for
research that stays within this policy, avoids data destruction and
service disruption, and follows coordinated disclosure. Never test
systems you do not own or have explicit permission to test.

## What NOT to report

- Findings that require a policy explicitly set to `allow` the action
  (that is operator intent, not a bypass — default is deny).
- The `WasmtimeSandbox` experimental backend returning "not yet enabled"
  (`crates/aegis-sandbox/src/lib.rs`): known extension point.
- Netns-level network isolation limits of `RestrictedProcessSandbox`,
  documented in code as advisory-only.
- Missing `cargo-fuzz`/`cargo-audit` tooling in a default checkout.
- Automated scanner output without a demonstrated Aegis-specific impact.
- Social engineering, physical attacks, or upstream-crate CVEs without a
  reachable path through Aegis code (report those upstream).

## Hardening defaults (summary)

Aegis-MCP ships fail-closed. The defaults in `aegis.yaml` and code are:

- **Fail-closed**: unknown methods, unmatched policy input, parse errors,
  and missing policy results all resolve to `DENY` (`security.fail_closed:
  true`, `Engine::evaluate` default-deny, `combine_verdict` no-policy
  deny in `crates/aegis-core/src/lib.rs`).
- **Hash-chained audit**: every event is BLAKE3-chained to its predecessor
  (`previous_event_hash` → `event_hash`) in SQLite WAL mode; verify with
  `aegis-mcp audit verify` (`crates/aegis-audit/src/lib.rs`).
- **Secret redaction**: `redact_secrets` (`aegis-core`) scrubs
  `api_key`/`secret`/`password`, `Bearer` tokens, `sk-…`, `xox…`,
  AWS secret patterns, and PEM private-key blocks before logs/traces.
- **AI is advisory-only**: the classifier can escalate `ALLOW → APPROVAL`
  (≥ 0.6) or `→ DENY` (≥ 0.85) but can never downgrade a deterministic
  `DENY`; deterministic risk ≥ 0.85 forces `DENY` regardless of policy.
- **Egress guardrails**: cloud metadata endpoints (`169.254.169.254`,
  `metadata.google.internal`) and non-allowlisted localhost/private
  ranges are denied by default (`network.deny_metadata_endpoints`).
- **Request limits**: 10 MiB max message, 5 s classifier/proxy budget
  (`limits` in `aegis.yaml`).

If you deploy with `fail_closed: false`, `sandbox.enabled: true` without
reviewing isolation limits, or a permissive `policy/` tree, note that in
your report — it affects severity triage.
