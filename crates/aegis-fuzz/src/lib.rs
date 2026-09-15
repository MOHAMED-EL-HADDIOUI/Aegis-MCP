//! Mini in-repo fuzz harness (stable Rust, no libfuzzer required).
//!
//! Each target feeds arbitrary bytes into a fallible library entry point and
//! asserts the library never panics (errors are fine, panics are bugs).
//! Mutation is a deterministic xorshift64 stream, so runs are reproducible.
//! See `tests/fuzz/README.md` for the `cargo-fuzz`/libfuzzer migration path.
use once_cell::sync::Lazy;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Default)]
pub struct FuzzStats {
    pub inputs: usize,
    pub panics: usize,
    pub first_panic: Option<String>,
}

/// Deterministic xorshift64 PRNG. Fixed seed => reproducible runs.
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
        }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n.max(1) as u64)) as usize
    }
}

const INTERESTING: &[&[u8]] = &[
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b"\\",
    b":",
    b",",
    b"\x00",
    b"\n",
    b"../",
    b"..\\",
    b"http://",
    b"https://",
    b"%00",
    b"%3A%2F",
    b"'",
    b";",
    b"--",
    b"/*",
    b"*/",
    b"\x7f",
    b"\xff",
    b"\xfe",
    b"{{",
    b"null",
    b"true",
    b"99999999999999999999",
];

/// Structured mutation of one input. Output capped at `max_len` bytes.
pub fn mutate(rng: &mut XorShift64, input: &[u8], max_len: usize) -> Vec<u8> {
    let mut buf = input.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        match rng.below(6) {
            0 if !buf.is_empty() => {
                // byte flip
                let i = rng.below(buf.len());
                buf[i] ^= 1 << rng.below(8) as u8;
            }
            1 if !buf.is_empty() => {
                // delete a slice
                let i = rng.below(buf.len());
                let n = 1 + rng.below((buf.len() - i).min(16));
                buf.drain(i..(i + n).min(buf.len()));
            }
            2 => {
                // insert interesting token
                let tok = INTERESTING[rng.below(INTERESTING.len())];
                let i = rng.below(buf.len() + 1);
                buf.splice(i..i, tok.iter().cloned());
            }
            3 if !buf.is_empty() => {
                // duplicate a slice
                let i = rng.below(buf.len());
                let n = 1 + rng.below((buf.len() - i).min(16));
                let chunk = buf[i..(i + n).min(buf.len())].to_vec();
                buf.splice(i..i, chunk);
            }
            4 if !buf.is_empty() => {
                // truncate
                let n = rng.below(buf.len() + 1);
                buf.truncate(n);
            }
            _ => {
                // splice prefix of another position (keeps JSON-ish shape shifting)
                if !buf.is_empty() {
                    let i = rng.below(buf.len());
                    buf.insert(i, b' ');
                }
            }
        }
    }
    buf.truncate(max_len);
    buf
}

/// Run `target` over every seed plus `iters_per_seed` mutations each.
/// Panics inside the target are caught and counted (never propagated).
pub fn run_target(
    target: impl Fn(&[u8]),
    seeds: &[Vec<u8>],
    iters_per_seed: usize,
    seed: u64,
    max_len: usize,
) -> FuzzStats {
    let mut stats = FuzzStats::default();
    let mut rng = XorShift64::new(seed);
    for s in seeds {
        for mutated in std::iter::once(s.clone())
            .chain((0..iters_per_seed).map(|_| mutate(&mut rng, s, max_len)))
        {
            stats.inputs += 1;
            let r = std::panic::catch_unwind(AssertUnwindSafe(|| target(&mutated)));
            if let Err(e) = r {
                stats.panics += 1;
                if stats.first_panic.is_none() {
                    let preview: String =
                        String::from_utf8_lossy(&mutated[..mutated.len().min(160)]).into_owned();
                    let kind = if let Some(s) = e.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic payload".to_string()
                    };
                    stats.first_panic = Some(format!("{} | input: {}", kind, preview));
                }
            }
        }
    }
    stats
}

// ---------------- targets ----------------

/// JSON-RPC parsing + canonicalization + error rendering must not panic.
/// Also covers the transport pure functions (stdio framing, SSE parsing,
/// HTTP URL validation — no network in fuzz).
pub fn target_protocol(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    if let Ok(m) = aegis_protocol::parse_message(&s, 10 * 1024 * 1024) {
        let _ = aegis_protocol::canonical_json(&serde_json::json!({"method": m.method}));
        let _ = aegis_protocol::error_response(m.id.clone(), -32000, "fuzz");
        for d in &m.tool_definitions {
            let _ =
                aegis_security::inspect_tool_description(&d.name, &d.description, &d.input_schema);
        }
        if let Some(c) = m.tool_call {
            let _ = aegis_security::inspect_tool_description(
                &c.name,
                &c.arguments.to_string(),
                &c.arguments,
            );
        }
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
        let _ = aegis_protocol::canonical_json(&v);
    }
    // Transport pure functions: framing + SSE + URL validation (no I/O).
    let _ = aegis_protocol::encode_stdio_frame(&s);
    let _ = aegis_protocol::decode_stdio_frames(data);
    let _ = aegis_protocol::parse_sse_stream(&s);
    let _ = aegis_protocol::sse_jsonrpc_frames(&s);
    let _ = aegis_protocol::HttpTransport::new(s.chars().take(128).collect::<String>());
}

/// All deterministic detectors must not panic on arbitrary text.
pub fn target_security(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let _ = aegis_security::inspect_filesystem(&s, "./workspace");
    let _ = aegis_security::inspect_shell(&s);
    let _ = aegis_security::inspect_sql(&s);
    let _ = aegis_security::inspect_network(&s, &[], &[], true);
    let _ = aegis_security::contains_secret(&s);
    let _ = aegis_security::inspect_tool_description("fuzz", &s, &serde_json::json!({}));
    // also with a hostile schema value
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
        let _ = aegis_security::inspect_tool_description("fuzz", "plain", &v);
    }
}

static POLICY_ENGINE: Lazy<aegis_policy::Engine> = Lazy::new(|| {
    aegis_policy::Engine::load_yaml_str(
        "version: \"1\"\nrules:\n  - {name: allow-echo, action: allow, when: {tool: echo}}\n  - {name: block-exfil, action: deny, when: {taint: SECRET, destination: external_network}}\n",
    )
    .expect("static policy")
});

/// Policy YAML loading + evaluation must not panic.
pub fn target_policy(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    // Arbitrary YAML: errors ok, panics not.
    let _ = aegis_policy::Engine::load_yaml_str(&s);
    let args: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
    let input = aegis_policy::EvalInput {
        tool: s.chars().take(48).collect(),
        server: "fuzz".into(),
        path: s.chars().take(96).collect(),
        url: s.chars().take(96).collect(),
        taints: vec!["SECRET".into()],
        risk_score: (data.len() % 100) as f32 / 100.0,
        args,
        ..Default::default()
    };
    let _ = POLICY_ENGINE.evaluate(&input);
}

/// Config YAML, taint propagation, classifier scoring, bundle
/// sign/verify (hex-decode paths), and OTel trace/OTLP body building must
/// not panic on arbitrary bytes.
pub fn target_config(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    // Config parsing: errors ok, panics not. Env overrides read real env.
    let _ = aegis_config::Config::from_yaml_str(&s);
    // Taint store with attacker-controlled ids/labels.
    let mut store = aegis_taint::TaintStore::new();
    let id_a: String = s.chars().take(24).collect();
    let id_b: String = s.chars().skip(24).take(24).collect();
    store.taint_value(
        &id_a,
        aegis_core::TaintLabel::new(
            aegis_core::TaintKind::UntrustedWeb,
            s.chars().take(32).collect::<String>(),
            0.9,
        ),
    );
    store.taint_value(
        &id_a,
        aegis_core::TaintLabel::new(aegis_core::TaintKind::Secret, "fuzz", 1.0),
    );
    store.propagate(&[&id_a, &id_b], "out");
    store.sanitize("out", &[aegis_core::TaintKind::UntrustedWeb]);
    store.declassify("out");
    let _ = store.taints_of("out");
    let _ = store.has_kind("out", aegis_core::TaintKind::Secret);
    store.source_from_tool("r", &s.chars().take(16).collect::<String>(), "fuzz");
    // Classifier scoring on arbitrary text/tool names.
    let _ = aegis_classifier::score_text(&s, &s.chars().take(32).collect::<String>());
    // Bundle crypto paths with arbitrary hex / JSON.
    if let Ok(pf) = serde_yaml::from_str::<aegis_policy::PolicyFile>(&s) {
        let _ = aegis_policy::sign_bundle(&pf, &s);
    }
    if let Ok(bundle) = serde_json::from_str::<aegis_policy::SignedBundle>(&s) {
        let _ = aegis_policy::verify_bundle(&bundle, &s);
    }
    // OTel pure functions: traceparent parse/render + OTLP body (no I/O).
    let _ = aegis_observability::TraceContext::from_traceparent(&s);
    let trace = aegis_observability::TraceContext::new();
    let span = aegis_observability::OtelSpan::new(trace, "fuzz")
        .with_attr("k", s.chars().take(32).collect::<String>());
    let _ = aegis_observability::otlp_body("fuzz", &span);
}

/// Load seed files from a corpus dir; fall back to inline seeds when the dir
/// is missing (e.g. different CWD) so tests never depend on CWD alone.
pub fn load_seeds(corpus_dir: &str) -> Vec<Vec<u8>> {
    if let Ok(rd) = std::fs::read_dir(corpus_dir) {
        let mut files: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        files.sort();
        let mut out = vec![];
        for f in files {
            if f.is_file() {
                if let Ok(b) = std::fs::read(&f) {
                    out.push(b);
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    inline_seeds()
}

pub fn inline_seeds() -> Vec<Vec<u8>> {
    vec![
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"#.to_vec(),
        b"not json at all {{{".to_vec(),
        b"".to_vec(),
        b"\x00\xff\xfe\x00{{{{".to_vec(),
        br#"{"jsonrpc":"1.0","id":null,"method":"tools/destroy","params":{}}"#.to_vec(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERS: usize = 300;

    fn seeds() -> Vec<Vec<u8>> {
        // `cargo test -p aegis-fuzz` runs with CWD = crates/aegis-fuzz.
        load_seeds("../../tests/fuzz/corpus")
    }

    #[test]
    fn fuzz_protocol_no_panic() {
        let stats = run_target(target_protocol, &seeds(), ITERS, 0xAE615, 2048);
        assert_eq!(stats.panics, 0, "first panic: {:?}", stats.first_panic);
        assert!(stats.inputs >= ITERS);
    }

    #[test]
    fn fuzz_security_no_panic() {
        let stats = run_target(target_security, &seeds(), ITERS, 0x5EC07, 2048);
        assert_eq!(stats.panics, 0, "first panic: {:?}", stats.first_panic);
        assert!(stats.inputs >= ITERS);
    }

    #[test]
    fn fuzz_policy_no_panic() {
        let stats = run_target(target_policy, &seeds(), ITERS, 0x901C7, 2048);
        assert_eq!(stats.panics, 0, "first panic: {:?}", stats.first_panic);
        assert!(stats.inputs >= ITERS);
    }

    #[test]
    fn fuzz_config_no_panic() {
        let stats = run_target(target_config, &seeds(), ITERS, 0xC0F16, 2048);
        assert_eq!(stats.panics, 0, "first panic: {:?}", stats.first_panic);
        assert!(stats.inputs >= ITERS);
    }
}
