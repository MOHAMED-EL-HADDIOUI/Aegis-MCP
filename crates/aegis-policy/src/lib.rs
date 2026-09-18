//! Deterministic ordered policy engine with explanations + signed bundles.
use aegis_core::{Decision, PolicyOutcome};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default = "d_version")]
    pub version: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}
fn d_version() -> String {
    "1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    #[serde(default)]
    pub when: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Warn,
    RequireApproval,
    Sandbox,
}

impl From<Action> for Decision {
    fn from(a: Action) -> Decision {
        match a {
            Action::Allow => Decision::Allow,
            Action::Deny => Decision::Deny,
            Action::Warn => Decision::Warn,
            Action::RequireApproval => Decision::RequireApproval,
            Action::Sandbox => Decision::Sandbox,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvalInput {
    pub tool: String,
    pub server: String,
    pub user: String,
    pub environment: String,
    pub branch: String,
    pub path: String,
    pub url: String,
    pub http_method: String,
    pub sql_op: String,
    pub taints: Vec<String>,
    pub risk_score: f32,
    pub resource: String,
    pub args: serde_json::Value,
    /// Observed session request rate (requests/sec), populated by the
    /// gateway from per-session accounting. Drives the `rate` condition.
    /// Defaults to 0.0 (offline `policy test` fixtures can set `rate`).
    pub rate_rps: f32,
    /// Unix timestamp override for the `time` condition. `None` (default)
    /// means "use the real current UTC time"; `Some` pins the clock for
    /// deterministic tests and CLI fixtures (`"now"`).
    pub now_unix: Option<i64>,
}

impl EvalInput {
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "tool" => Some(self.tool.clone()),
            "server" => Some(self.server.clone()),
            "user" => Some(self.user.clone()),
            "environment" => Some(self.environment.clone()),
            "branch" => Some(self.branch.clone()),
            "path" => Some(self.path.clone()),
            "url" => Some(self.url.clone()),
            "http_method" => Some(self.http_method.clone()),
            "sql_op" => Some(self.sql_op.clone()),
            "resource" => Some(self.resource.clone()),
            _ => None,
        }
    }
}

pub struct Engine {
    rules: Vec<Rule>,
}

impl Engine {
    pub fn from_file(p: &PolicyFile) -> Self {
        Self {
            rules: p.rules.clone(),
        }
    }
    /// Build an engine directly from a verified signed bundle's rules.
    pub fn from_bundle(bundle: &SignedBundle) -> Self {
        Self {
            rules: bundle.rules.clone(),
        }
    }
    /// Load a signed bundle file, verify it against `public_key_hex`, and
    /// return the engine. Fails closed on any error (bad hex, digest
    /// mismatch, bad signature, unreadable file).
    pub fn load_verified(bundle_path: &str, public_key_hex: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(bundle_path)
            .map_err(|e| anyhow::anyhow!("read bundle {}: {}", bundle_path, e))?;
        let bundle: SignedBundle = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parse bundle {}: {}", bundle_path, e))?;
        verify_bundle(&bundle, public_key_hex)?;
        Ok(Self::from_bundle(&bundle))
    }
    pub fn load_yaml_str(s: &str) -> anyhow::Result<Self> {
        let pf: PolicyFile = serde_yaml::from_str(s)?;
        Ok(Self::from_file(&pf))
    }
    /// Load every `.yaml`/`.yml` policy file under `dir`, recursing into
    /// sub-directories (e.g. `policy/{base,filesystem,network,...}`).
    /// Files are applied in sorted path order so evaluation stays deterministic.
    pub fn load_dir(dir: &str) -> anyhow::Result<Self> {
        fn visit(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) -> anyhow::Result<()> {
            let mut entries: Vec<_> = std::fs::read_dir(dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            entries.sort();
            for e in entries {
                if e.is_dir() {
                    visit(&e, files)?;
                } else if e.extension().and_then(|x| x.to_str()) == Some("yaml")
                    || e.extension().and_then(|x| x.to_str()) == Some("yml")
                {
                    files.push(e);
                }
            }
            Ok(())
        }
        let mut files = vec![];
        visit(std::path::Path::new(dir), &mut files)?;
        let mut rules = vec![];
        for f in files {
            let s = std::fs::read_to_string(&f)?;
            let pf: PolicyFile =
                serde_yaml::from_str(&s).map_err(|e| anyhow::anyhow!("{}: {}", f.display(), e))?;
            rules.extend(pf.rules);
        }
        Ok(Self { rules })
    }
    /// Number of loaded rules (useful for startup diagnostics).
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
    /// Ordered first-match evaluation. No match => default deny (fail closed).
    pub fn evaluate(&self, input: &EvalInput) -> PolicyOutcome {
        for r in &self.rules {
            if rule_matches(r, input) {
                return PolicyOutcome {
                    decision: r.action.into(),
                    policy: r.name.clone(),
                    reason: format!("rule '{}' matched", r.name),
                };
            }
        }
        PolicyOutcome {
            decision: Decision::Deny,
            policy: "default-deny".into(),
            reason: "no rule matched; failing closed".into(),
        }
    }
    pub fn validate(pf: &PolicyFile) -> Vec<String> {
        let mut errs = vec![];
        let mut names = std::collections::HashSet::new();
        for r in &pf.rules {
            if r.name.is_empty() {
                errs.push("rule with empty name".into());
            }
            if !names.insert(r.name.clone()) {
                errs.push(format!("duplicate rule name '{}'", r.name));
            }
            if r.when.is_empty() {
                errs.push(format!("rule '{}' has empty conditions", r.name));
            }
        }
        errs
    }
}

fn cond_matches(key: &str, cond: &serde_json::Value, input: &EvalInput) -> bool {
    match key {
        "taint" => {
            let want = cond.as_str().unwrap_or("");
            input.taints.iter().any(|t| t == want)
        }
        "destination" => {
            // destination: external_network matches http urls
            if cond.as_str() == Some("external_network") {
                input.url.starts_with("http://") || input.url.starts_with("https://")
            } else {
                false
            }
        }
        "path_prefix" => {
            // Boundary-aware containment: "./workspace" matches the dir
            // itself and "./workspace/…" but NOT "./workspace-evil/…"
            // (naive starts_with would let a sibling squat the prefix).
            let prefix = cond.as_str().unwrap_or("");
            input.path == *prefix
                || input.path.starts_with(&format!("{prefix}/"))
                || (prefix.ends_with('/') && input.path.starts_with(prefix))
        }
        "risk_gte" => {
            let threshold = cond.as_f64().unwrap_or(1.0) as f32;
            input.risk_score >= threshold
        }
        "rate" => {
            // Session request-rate gate: `rate: 50` ⇔ observed rps >= 50.
            // Accepts a JSON number or a numeric string.
            let threshold = cond
                .as_f64()
                .or_else(|| cond.as_str().and_then(|s| s.trim().parse::<f64>().ok()));
            match threshold {
                Some(t) => input.rate_rps >= t as f32,
                None => false,
            }
        }
        "time" => {
            // UTC daily window `"HH:MM-HH:MM"` (24h clock, wrap-safe, so
            // `"22:00-06:00"` covers overnight). Malformed values never
            // match (fail-closed: an allow rule with a bad window denies).
            match cond.as_str().and_then(parse_hhmm_window) {
                Some((start, end)) => {
                    let now = input
                        .now_unix
                        .unwrap_or_else(|| chrono::Utc::now().timestamp());
                    time_in_window(now, start, end)
                }
                None => false,
            }
        }
        _ => {
            if let Some(actual) = input.get(key) {
                match cond {
                    serde_json::Value::String(want) => {
                        if want.ends_with('*') {
                            actual.starts_with(&want[..want.len() - 1])
                        } else {
                            &actual == want
                        }
                    }
                    _ => cond.to_string().trim_matches('"') == actual,
                }
            } else if key == "operation" {
                cond.as_str()
                    .map(|w| input.resource == w || input.sql_op == w)
                    .unwrap_or(false)
            } else {
                // generic arg match: argument.<field>
                if let Some(field) = key.strip_prefix("argument.") {
                    input
                        .args
                        .get(field)
                        .map(|v| {
                            v.as_str()
                                .map(|s| s == cond.as_str().unwrap_or(""))
                                .unwrap_or(false)
                                || v == cond
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }
}

fn rule_matches(rule: &Rule, input: &EvalInput) -> bool {
    rule.when.iter().all(|(k, v)| cond_matches(k, v, input))
}

/// Parse a `"HH:MM"` 24h time into seconds since midnight. Strict:
/// exactly 5 chars, valid hour 00-23, valid minute 00-59.
fn parse_hhmm(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() != 5 || s.as_bytes()[2] != b':' {
        return None;
    }
    let h: i64 = s[..2].parse().ok()?;
    let m: i64 = s[3..].parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return None;
    }
    Some(h * 3600 + m * 60)
}

/// Parse a `"HH:MM-HH:MM"` daily window into (start, end) seconds.
fn parse_hhmm_window(s: &str) -> Option<(i64, i64)> {
    let (a, b) = s.split_once('-')?;
    Some((parse_hhmm(a)?, parse_hhmm(b)?))
}

/// True when unix timestamp `now` falls inside the daily `[start, end)`
/// window (UTC). Wrap-safe: `start > end` means overnight (e.g.
/// `22:00-06:00`). Zero-width windows (`start == end`) never match.
fn time_in_window(now: i64, start: i64, end: i64) -> bool {
    if start == end {
        return false;
    }
    let tod = now.rem_euclid(86_400);
    if start < end {
        (start..end).contains(&tod)
    } else {
        tod >= start || tod < end
    }
}

/// Bundle signing: BLAKE3 digest + ed25519 verify helper.
pub fn digest_bundle(canonical: &str) -> String {
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

/// Canonical bytes of a policy file: sorted-key JSON of `{version, rules}`.
/// Both signing and verification digest exactly these bytes, so a bundle is
/// tamper-evident end to end.
pub fn canonical_bundle(policy: &PolicyFile) -> String {
    let v = serde_json::json!({"version": policy.version, "rules": policy.rules});
    canonical_json_value(&v)
}

fn canonical_json_value(value: &serde_json::Value) -> String {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_string(&sort(value)).unwrap_or_default()
}

/// A signed policy bundle: the rules, their digest, and an ed25519
/// signature over the digest. Distribute `bundle.json` + the public key;
/// keep the secret key offline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedBundle {
    pub version: String,
    pub digest: String,
    pub rules: Vec<Rule>,
    /// Hex-encoded 64-byte ed25519 signature over `digest`.
    pub signature: String,
}

/// Generate a fresh ed25519 keypair. Returns (secret_hex, public_hex).
pub fn generate_keypair() -> (String, String) {
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying = signing.verifying_key();
    (
        hex::encode(signing.to_bytes()),
        hex::encode(verifying.to_bytes()),
    )
}

/// Sign a policy file with a hex-encoded 32-byte ed25519 secret key.
pub fn sign_bundle(policy: &PolicyFile, secret_hex: &str) -> anyhow::Result<SignedBundle> {
    use ed25519_dalek::Signer as _;
    let bytes =
        hex::decode(secret_hex.trim()).map_err(|e| anyhow::anyhow!("bad secret key hex: {}", e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&arr);
    let digest = digest_bundle(&canonical_bundle(policy));
    let sig = signing.sign(digest.as_bytes());
    Ok(SignedBundle {
        version: policy.version.clone(),
        digest,
        rules: policy.rules.clone(),
        signature: hex::encode(sig.to_bytes()),
    })
}

/// Verify a bundle against a hex-encoded 32-byte ed25519 public key.
/// Checks the digest matches the embedded rules AND the signature is valid.
pub fn verify_bundle(bundle: &SignedBundle, public_hex: &str) -> anyhow::Result<()> {
    use ed25519_dalek::Verifier;
    let bytes =
        hex::decode(public_hex.trim()).map_err(|e| anyhow::anyhow!("bad public key hex: {}", e))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;
    let recomputed = digest_bundle(&canonical_bundle(&PolicyFile {
        version: bundle.version.clone(),
        rules: bundle.rules.clone(),
    }));
    if recomputed != bundle.digest {
        anyhow::bail!("bundle digest mismatch: rules were modified after signing");
    }
    let sig_bytes = hex::decode(bundle.signature.trim())
        .map_err(|e| anyhow::anyhow!("bad signature hex: {}", e))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    verifying
        .verify(
            bundle.digest.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_arr),
        )
        .map_err(|e| anyhow::anyhow!("signature invalid: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine() -> Engine {
        Engine::load_yaml_str(
            r#"
version: "1"
rules:
  - name: deny-main-branch-push
    action: deny
    when: {tool: git_push, branch: main}
  - name: block-private-file-exfiltration
    action: deny
    when: {taint: SECRET, destination: external_network}
  - name: allow-read-project
    action: allow
    when: {tool: filesystem_read, path_prefix: ./workspace}
  - name: approve-production-write
    action: require_approval
    when: {environment: production, operation: write}
"#,
        )
        .unwrap()
    }
    #[test]
    fn denies_main_push() {
        let e = engine();
        let i = EvalInput {
            tool: "git_push".into(),
            branch: "main".into(),
            ..Default::default()
        };
        let o = e.evaluate(&i);
        assert_eq!(o.decision, Decision::Deny);
    }
    #[test]
    fn blocks_secret_exfil() {
        let e = engine();
        let i = EvalInput {
            taints: vec!["SECRET".into()],
            url: "https://evil.example.com".into(),
            ..Default::default()
        };
        let o = e.evaluate(&i);
        assert_eq!(o.decision, Decision::Deny);
    }
    #[test]
    fn allows_project_read() {
        let e = engine();
        let i = EvalInput {
            tool: "filesystem_read".into(),
            path: "./workspace/src/main.rs".into(),
            ..Default::default()
        };
        // ensure earlier rules don't match
        let o = e.evaluate(&i);
        assert_eq!(o.decision, Decision::Allow);
    }
    #[test]
    fn default_deny_when_no_match() {
        let e = engine();
        let o = e.evaluate(&EvalInput::default());
        assert_eq!(o.decision, Decision::Deny);
    }
    #[test]
    fn ordered_first_match_wins() {
        let e = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: a, action: allow, when: {tool: t}}\n  - {name: b, action: deny, when: {tool: t}}\n",
        )
        .unwrap();
        let i = EvalInput {
            tool: "t".into(),
            ..Default::default()
        };
        assert_eq!(e.evaluate(&i).policy, "a");
    }
    #[test]
    fn validates_duplicates() {
        let pf: PolicyFile = serde_yaml::from_str(
            "version: \"1\"\nrules:\n  - {name: a, action: allow, when: {tool: t}}\n  - {name: a, action: deny, when: {tool: x}}\n",
        )
        .unwrap();
        assert!(!Engine::validate(&pf).is_empty());
    }
    #[test]
    fn sign_verify_roundtrip() {
        let pf: PolicyFile = serde_yaml::from_str(
            "version: \"1\"\nrules:\n  - {name: a, action: allow, when: {tool: t}}\n",
        )
        .unwrap();
        let (sk, pk) = generate_keypair();
        let bundle = sign_bundle(&pf, &sk).unwrap();
        verify_bundle(&bundle, &pk).unwrap();
        // Tampered rules fail verification.
        let mut evil = bundle.clone();
        evil.rules[0].name = "evil-allow-all".into();
        assert!(verify_bundle(&evil, &pk).is_err());
        // Wrong key fails verification.
        let (_, pk2) = generate_keypair();
        assert!(verify_bundle(&bundle, &pk2).is_err());
        // Malformed keys fail cleanly (no panic).
        assert!(sign_bundle(&pf, "zz").is_err());
        assert!(verify_bundle(&bundle, "zz").is_err());
    }
    #[test]
    fn load_verified_roundtrip_and_tamper() {
        let pf: PolicyFile = serde_yaml::from_str(
            "version: \"1\"\nrules:\n  - {name: a, action: allow, when: {tool: t}}\n",
        )
        .unwrap();
        let (sk, pk) = generate_keypair();
        let bundle = sign_bundle(&pf, &sk).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aegis-bundle-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
        let ps = path.to_string_lossy().to_string();
        let engine = Engine::load_verified(&ps, &pk).unwrap();
        assert_eq!(engine.rule_count(), 1);
        // Tampered file fails closed.
        let mut evil = bundle.clone();
        evil.rules[0].name = "evil".into();
        std::fs::write(&path, serde_json::to_string_pretty(&evil).unwrap()).unwrap();
        assert!(Engine::load_verified(&ps, &pk).is_err());
        // Wrong key fails closed.
        std::fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
        let (_, pk2) = generate_keypair();
        assert!(Engine::load_verified(&ps, &pk2).is_err());
        // Missing file fails closed (no panic).
        assert!(Engine::load_verified("/nonexistent/aegis-bundle.json", &pk).is_err());
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn rate_threshold_matches_observed_rps() {
        let e = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: throttle-burst, action: deny, when: {rate: 50}}\n",
        )
        .unwrap();
        let hot = EvalInput {
            rate_rps: 120.0,
            ..Default::default()
        };
        assert_eq!(e.evaluate(&hot).policy, "throttle-burst");
        let cool = EvalInput {
            rate_rps: 2.0,
            ..Default::default()
        };
        assert_eq!(e.evaluate(&cool).policy, "default-deny");
        // Numeric strings work; garbage never matches (fail-closed).
        let s = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: s, action: deny, when: {rate: \"50\"}}\n  - {name: g, action: deny, when: {rate: \"fast\"}}\n",
        )
        .unwrap();
        assert_eq!(s.evaluate(&hot).policy, "s");
        let g = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: g, action: allow, when: {rate: \"fast\"}}\n",
        )
        .unwrap();
        assert_eq!(g.evaluate(&hot).policy, "default-deny");
    }
    #[test]
    fn path_prefix_is_boundary_aware() {
        let e = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: allow-proj, action: allow, when: {tool: filesystem_read, path_prefix: ./workspace}}\n",
        )
        .unwrap();
        for ok in ["./workspace", "./workspace/src/main.rs", "./workspace/"] {
            let i = EvalInput {
                tool: "filesystem_read".into(),
                path: ok.into(),
                ..Default::default()
            };
            assert_eq!(e.evaluate(&i).policy, "allow-proj", "path={ok}");
        }
        // Sibling squat: shares the string prefix but is NOT contained.
        for bad in ["./workspace-evil/secret", "./workspace2/x", "./workspaces"] {
            let i = EvalInput {
                tool: "filesystem_read".into(),
                path: bad.into(),
                ..Default::default()
            };
            assert_eq!(e.evaluate(&i).policy, "default-deny", "path={bad}");
        }
    }
    #[test]
    fn time_window_matches_pinned_clock() {
        // 2026-01-02T10:30:00Z = 1767349800.
        let noonish = 1_767_349_800i64;
        let e = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: business-hours, action: allow, when: {time: \"09:00-17:00\"}}\n",
        )
        .unwrap();
        let inside = EvalInput {
            now_unix: Some(noonish),
            ..Default::default()
        };
        assert_eq!(e.evaluate(&inside).policy, "business-hours");
        // 03:00Z same day is outside 09:00-17:00.
        let outside = EvalInput {
            now_unix: Some(noonish - 27_000),
            ..Default::default()
        };
        assert_eq!(e.evaluate(&outside).policy, "default-deny");
        // Overnight window wraps: 23:00Z matches 22:00-06:00.
        let night = Engine::load_yaml_str(
            "version: \"1\"\nrules:\n  - {name: night-window, action: allow, when: {time: \"22:00-06:00\"}}\n",
        )
        .unwrap();
        let at_23 = EvalInput {
            now_unix: Some(1_767_394_800), // 2026-01-02T23:00:00Z
            ..Default::default()
        };
        assert_eq!(night.evaluate(&at_23).policy, "night-window");
        assert_eq!(night.evaluate(&inside).policy, "default-deny");
        // Malformed windows never match, even on allow rules.
        for bad in [
            "9-17",
            "09:00",
            "25:00-26:00",
            "09:60-10:00",
            "10:00-10:00",
            "nope",
        ] {
            let b = Engine::load_yaml_str(&format!(
                "version: \"1\"\nrules:\n  - {{name: b, action: allow, when: {{time: \"{bad}\"}}}}\n"
            ))
            .unwrap();
            assert_eq!(b.evaluate(&inside).policy, "default-deny", "bad={bad}");
        }
    }
}
