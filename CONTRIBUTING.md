# Contributing to Aegis-MCP

## Prerequisites

- **Rust 1.78+** (workspace `rust-version`; verified with 1.98.1).
  Install via [rustup](https://rustup.rs/): `rustup update stable`.
- **Node 20+** for the dashboard (`dashboard/`, Next.js). Verified with
  Node 24 / npm 12.
- Optional: `just` (mirrors `Makefile`), `cargo-fuzz`, `cargo-audit`,
  Docker 24+ with Compose v2.

## Workflow

1. Fork and clone, then verify a clean baseline:
   `cargo build --workspace` and `cargo test --workspace` (40 tests green).
2. Create a focused branch: `feat/<scope>`, `fix/<scope>`, `docs/<scope>`.
3. Make the smallest change that satisfies the task; keep detectors
   deterministic and the AI classifier advisory-only (see rules below).
4. Run before pushing:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

5. Open a PR against `main` using Conventional Commits (below) and fill
   in the PR checklist.

## Conventional Commits

Format: `<type>(<scope>): <short summary>` — e.g.
`feat(policy): add risk_gte condition`, `fix(proxy): fail closed on empty
policy dir`, `docs(security): document SSRF guardrails`.

Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `chore`,
`ci`, `security`. Breaking changes append `!` and describe migration
in the body.

## PR checklist

- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes (no regressions; new behavior has tests).
- [ ] Policy changes include a fixture + `policy test`/`policy validate` evidence.
- [ ] Detector changes include unit tests with bypass + benign cases.
- [ ] Docs updated (`docs/`, `README.md`, or `CHANGELOG.md` `[Unreleased]`).
- [ ] No secrets, private keys, or real credentials in diffs.
- [ ] No changes to `audit/` chain semantics without a migration note.

## Adding a policy

1. Pick the domain file under `policy/` (`filesystem/`, `shell/`,
   `network/`, `postgres/`, `base/`) or add `policy/<domain>/base.yaml`.
2. Rules are **ordered, first-match wins**; put narrow `deny` rules before
   broad `allow` rules. Unmatched input denies by default — do not add a
   trailing `allow` "catch-all".
3. Validate and exercise it (see `docs/policies/POLICY_GUIDE.md`):

   ```sh
   cargo run -q -p aegis-cli -- policy validate --policy ./policy/<domain>/base.yaml
   cargo run -q -p aegis-cli -- policy test --policy ./policy/<domain>/base.yaml --fixture ./tests/policy/<case>.json
   ```

4. Condition keys available: `tool`, `server`, `user`, `environment`,
   `branch`, `path`, `path_prefix`, `url`, `destination`, `http_method`,
   `sql_op`, `operation`, `taint`, `risk_gte`, `resource`,
   `argument.<field>` (see `cond_matches` in
   `crates/aegis-policy/src/lib.rs`).

## Adding a detector

1. Implement in `crates/aegis-security/src/lib.rs` next to the sibling
   detectors (`inspect_filesystem`, `inspect_shell`, `inspect_sql`,
   `inspect_network`, `contains_secret`, `inspect_tool_description`).
2. Keep it **pure, synchronous, and allocation-light** — detectors run on
   the critical path with a < 1 ms budget each (see
   `docs/operations/PERFORMANCE.md`).
3. Wire it into the gateway pipeline in `Gateway::inspect_tool_call`
   (`crates/aegis-proxy/src/lib.rs`): compute risk, push a `TaintLabel`,
   record a violation string — then let the deterministic-guardrail block
   (`det_risk >= 0.85 → DENY`) do the enforcement.
4. Add unit tests: true positive, obfuscated variant (comment-stripping,
   encoding, case), and benign near-miss. Never weaken an existing test
   to make a new detector pass.

## Security-sensitive change rules

- The AI classifier (`crates/aegis-classifier`) must stay **escalate-only**:
  it may raise `ALLOW → REQUIRE_APPROVAL → DENY`, never the reverse.
  Changes to thresholds (0.6 approval / 0.85 block) need explicit review.
- `combine_verdict` (`crates/aegis-core`) and the `det_risk >= 0.85`
  force-deny in `crates/aegis-proxy` are security boundaries — treat any
  edit as `security:`-scoped with adversarial tests.
- Audit event canonical encoding (`append`/`verify` in
  `crates/aegis-audit`) must stay byte-identical on both sides; changing
  the format breaks chain verification for existing databases.
- Never log raw tool arguments, prompts, or secrets; use `redact_secrets`.
- Report vulnerabilities privately per [SECURITY.md](SECURITY.md) — do not
  open a public issue or PR with exploit detail.
