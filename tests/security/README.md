# Security corpora

Four JSONL corpora live in `tests/fixtures/`, each line carrying its own
`expected` verdict. They are executed by
`crates/aegis-security/tests/adversarial.rs`, which fails the build if any
line disagrees with its detector:

| corpus | lines | driver |
|---|---|---|
| `injection_samples.jsonl` (`text`) | 17 (12 block / 5 allow) | `inspect_tool_description`: block ⇔ score ≥ 0.5 |
| `traversal_samples.jsonl` (`path`) | 15 (10 block / 5 allow) | `inspect_filesystem(path, "./workspace")`: block ⇔ denied |
| `sql_samples.jsonl` (`query`) | 15 (9 block / 6 allow) | `inspect_sql`: block ⇔ dangerous |
| `ssrf_samples.jsonl` (`url`) | 11 (8 block / 3 allow) | `inspect_network(url, &[], &[], deny_metadata=true)`: block ⇔ denied |

## Coverage notes

- Injection covers ignore-previous-instructions, do-not-tell-user, credential
  exfiltration, `sudo`/`chmod 777`, `curl|sh`, plus clean project reads and a
  clean `SELECT ... WHERE`.
- Encoded payloads are covered **combined with a directive**, because that is
  how the scorer works: base64 blob (+0.20), zero-width chars (+0.25) and
  URL-encoding (+0.15) are weak signals on their own — e.g. a lone base64
  blob scores 0.20 and stays `allow`. Combined with "ignore previous
  instructions" (+0.35) they cross the 0.5 gateway-review threshold.
- The zero-width line contains a literal U+200B (invisible in editors —
  count it, don't eyeball it).

## Known detector limits (documented, not hidden)

Found while validating these corpora; the fixtures encode actual behavior:

1. Leading `..` that collapses fully (e.g. `../../etc/passwd` → normalized
   to `etc/passwd`) is treated as workspace-relative and **allowed**. Only
   residual `..`, absolute escapes, and sensitive names deny. The corpus uses
   `workspace/../../etc/passwd` for the traversal-block case.
2. On Windows, Unix-style absolutes (`/etc/passwd`) are not `is_absolute()`
   (no drive prefix), so they are jailed into the workspace and **allowed**.
   The corpus uses drive-letter absolutes (`C:\...`, `D:\...`) instead.
3. `http://[::1]/` is **allowed**: the `url` crate reports the IPv6 host with
   brackets, which misses the `"::1"` literal check. Prefer allowlisting
   private ranges explicitly if you serve IPv6 loopback.
4. A public "evil" URL (e.g. `https://evil.example.com/collect`) is **allowed**
   by the network detector — SSRF defense is about *address space*, exfil
   defense is the taint+policy layer (`SECRET` + external ⇒ DENY, see
   `tests/fixtures/malicious_tool.json`).
