# Development

## Workspace layout

```
aegis.yaml                 # default config (proxy mode, fail-closed, ./policy, ./aegis.db)
policy/{base,filesystem,shell,network,postgres}/  # shipped rule packs
policy/examples/           # minimal starting policy
crates/aegis-{core,config,protocol,policy,taint,security,classifier,
  audit,sandbox,observability,proxy,cli}/
docs/{architecture,development,operations,policies,protocol,threat-model}/
dashboard/src/app/         # Next.js console scaffold (overview, tools, policies,
                           # audit, incidents, approvals, events, taint, settings…)
deploy/{docker,compose,k8s,helm}/  # container/orchestration manifests
tests/{fixtures,fuzz,integration,policy,protocol,security,taint}/  # reserved
models/ benchmarks/ scripts/  # reserved (reference model, benches, helpers)
```

Crate dependency direction (no cycles):
`core` ← `config`, `protocol`, `taint`, `security`, `classifier` ← `policy`
← `audit` ← `proxy` (+ `observability`) ← `cli`. `sandbox` is standalone.

## Commands

```sh
cargo build --workspace
cargo test --workspace            # 40 tests green (3+3+3+3+1+6+6+3+2+7+3 per crate)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p aegis-cli -- benchmark --json
make dev|build|test|security|fuzz|benchmark|lint|format|docker|compose-up|dashboard|serve|clean
```

`make security` = `cargo test --workspace` + `config validate` + per-file
`policy validate` (filesystem, network, postgres, shell, base) +
`audit verify` against `:memory:` (side-effect free).

## Adding a detector

1. Add `inspect_<domain>` in `crates/aegis-security/src/lib.rs` returning a
   verdict struct (`allowed`/`dangerous` + `reason`); keep it pure and < 1 ms.
2. Call it from `Gateway::inspect_tool_call` (`crates/aegis-proxy/src/lib.rs`):
   raise `det_risk`, push a `TaintLabel`, append a violation string.
3. The existing guardrail enforces (`det_risk >= 0.85` → DENY,
   `>= 0.5` → REQUIRE_APPROVAL) — no new enforcement plumbing needed.
4. Unit tests: true positive, obfuscated variant, benign near-miss.

## Adding a policy / test

Edit or add YAML under `policy/<domain>/`, then:

```sh
cargo run -q -p aegis-cli -- policy validate --policy ./policy/<domain>/base.yaml
cargo run -q -p aegis-cli -- policy test --policy ./policy/<domain>/base.yaml \
  --fixture /tmp/case.json   # {"tool":…, "path"|"url":…, "taints":[…], "args":{…}}
```

Remember: ordered first-match, default-deny; `load_dir` recurses into subdirectories in sorted path order.

## Fuzzing (`cargo fuzz`)

Prerequisite: `cargo install cargo-fuzz` (not vendored). Suggested targets
under `tests/fuzz/` (scaffold reserved): `aegis_parser`
(`parse_message` over arbitrary bytes — must never panic, only return
`ProtocolError`), and detector round-trips (`inspect_shell/sql/network`
over adversarial strings). Run:

```sh
cargo fuzz run aegis_parser -- -max_total_time=60
```

`make fuzz` / `just fuzz` encode exactly this (`cargo fuzz --version` gate
first). Keep corpus inputs that find new coverage; file panics as bugs with
the reproducer attached.

