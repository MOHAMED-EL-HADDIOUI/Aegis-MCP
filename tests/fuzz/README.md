# Fuzzing

`cargo-fuzz` needs nightly libfuzzer, so this repo ships a **stable-Rust
mini-harness** instead: crate `crates/aegis-fuzz` loops the seed corpus in
`tests/fuzz/corpus/` plus deterministic xorshift64 mutations (fixed seed, so
runs are reproducible) through four targets and asserts **no panics**
(errors are fine — panics are bugs).

## Run it

```sh
# fast property check (part of `cargo test --workspace`):
cargo test -p aegis-fuzz

# longer manual runs (default corpus tests/fuzz/corpus, 1000 iters/seed):
cargo run -p aegis-fuzz --bin fuzz-protocol [corpus_dir] [iters]
cargo run -p aegis-fuzz --bin fuzz-security [corpus_dir] [iters]
cargo run -p aegis-fuzz --bin fuzz-policy    [corpus_dir] [iters]
cargo run -p aegis-fuzz --bin fuzz-config    [corpus_dir] [iters]
```

A target exits non-zero and prints the first panicking input (truncated to
160 chars) if any input panics. Add interesting new seeds to
`tests/fuzz/corpus/` — file names sort alphabetically, any extension works.

## Targets

| binary | entry point | what it hammers |
|---|---|---|
| `fuzz-protocol` | `aegis_fuzz::target_protocol` | `parse_message`, `canonical_json`, `error_response`, tool-definition poisoning scan, stdio framing, SSE parsing, HTTP URL validation (no I/O) |
| `fuzz-security` | `aegis_fuzz::target_security` | `inspect_filesystem/shell/sql/network`, `contains_secret`, `inspect_tool_description` |
| `fuzz-policy` | `aegis_fuzz::target_policy` | `Engine::load_yaml_str` on arbitrary text + `evaluate` on hostile inputs |
| `fuzz-config` | `aegis_fuzz::target_config` | `Config::from_yaml_str`, taint store ops, `score_text`, bundle sign/verify hex paths, traceparent parse, OTLP body building |

## Migrating to cargo-fuzz (nightly, libfuzzer)

1. `rustup toolchain install nightly && cargo install cargo-fuzz`
2. `cargo fuzz init` at the repo root (creates `fuzz/` with its own workspace).
3. Add one `fuzz/fuzz_targets/<name>.rs` per target, e.g.:
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   fuzz_target!(|data: &[u8]| { aegis_fuzz::target_protocol(data); });
   ```
   and add `aegis-fuzz = { path = "../crates/aegis-fuzz" }` to
   `fuzz/Cargo.toml` dependencies.
4. Seed it: `cp tests/fuzz/corpus/* fuzz/corpus/<name>/`.
5. `cargo +nightly fuzz run <name> -- -max_len=4096`.

Keep the stable harness green regardless — it runs in CI on every push.
