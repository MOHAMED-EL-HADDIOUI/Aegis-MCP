//! Configuration: aegis.yaml parse/validate/env-override with safe defaults.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub taint: TaintConfig,
    #[serde(default)]
    pub classifier: ClassifierConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

fn default_mode() -> ServerConfig {
    ServerConfig {
        mode: "proxy".into(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "d_proxy")]
    pub mode: String,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: "proxy".into(),
        }
    }
}
fn d_proxy() -> String {
    "proxy".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "d_true")]
    pub fail_closed: bool,
}
impl Default for SecurityConfig {
    fn default() -> Self {
        Self { fail_closed: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "d_policy_path")]
    pub path: String,
    /// Optional signed bundle file (JSON from `policy sign`). When
    /// `require_signed` is true the gateway verifies this bundle at startup
    /// and refuses to start on failure (fail-closed).
    #[serde(default)]
    pub bundle: Option<String>,
    /// Hex-encoded ed25519 public key for bundle verification.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub require_signed: bool,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            path: "./policy".into(),
            bundle: None,
            public_key: None,
            require_signed: false,
        }
    }
}
fn d_policy_path() -> String {
    "./policy".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
}
impl Default for TaintConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_onnx")]
    pub provider: String,
    #[serde(default)]
    pub model_path: Option<String>,
    #[serde(default = "d_threshold")]
    pub approval_threshold: f32,
    #[serde(default = "d_block_threshold")]
    pub block_threshold: f32,
}
impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "heuristic".into(),
            model_path: None,
            approval_threshold: 0.6,
            block_threshold: 0.85,
        }
    }
}
fn d_onnx() -> String {
    "heuristic".into()
}
fn d_threshold() -> f32 {
    0.6
}
fn d_block_threshold() -> f32 {
    0.85
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_db")]
    pub database: String,
}
impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database: "./aegis.db".into(),
        }
    }
}
fn d_db() -> String {
    "./aegis.db".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Master switch for the OpenTelemetry exporter. Metrics (Prometheus)
    /// and JSON tracing work regardless; this only controls OTLP export.
    #[serde(default)]
    pub otel_enabled: bool,
    /// OTLP/HTTP endpoint, e.g. `http://localhost:4318`. Only `http://`
    /// is supported by the built-in exporter (no new TLS deps); `https://`
    /// fails closed with a descriptive error.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    #[serde(default = "d_service_name")]
    pub service_name: String,
}
impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otel_enabled: false,
            otlp_endpoint: None,
            service_name: "aegis-mcp".into(),
        }
    }
}
fn d_service_name() -> String {
    "aegis-mcp".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "d_true")]
    pub deny_metadata_endpoints: bool,
}
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            deny_metadata_endpoints: d_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "d_max_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "d_timeout")]
    pub request_timeout_ms: u64,
    /// Sustained per-session throughput (requests/second). 0 disables limiting.
    #[serde(default = "d_rate_rps")]
    pub rate_limit_rps: f64,
    /// Token-bucket burst capacity per session.
    #[serde(default = "d_rate_burst")]
    pub rate_limit_burst: u32,
}
impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 10 * 1024 * 1024,
            request_timeout_ms: 5000,
            rate_limit_rps: d_rate_rps(),
            rate_limit_burst: d_rate_burst(),
        }
    }
}
fn d_max_bytes() -> usize {
    10 * 1024 * 1024
}
fn d_timeout() -> u64 {
    5000
}
fn d_rate_rps() -> f64 {
    200.0
}
fn d_rate_burst() -> u32 {
    400
}
fn d_true() -> bool {
    true
}

impl Config {
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = serde_yaml::from_str(s)?;
        cfg.apply_env_overrides();
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&s)
    }
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("AEGIS_POLICY_PATH") {
            self.policy.path = v;
        }
        if let Ok(v) = std::env::var("AEGIS_AUDIT_DB") {
            self.audit.database = v;
        }
        if let Ok(v) = std::env::var("AEGIS_FAIL_CLOSED") {
            self.security.fail_closed = v != "false" && v != "0";
        }
        if let Ok(v) = std::env::var("AEGIS_CLASSIFIER") {
            self.classifier.provider = v;
        }
        if let Ok(v) = std::env::var("AEGIS_MAX_BYTES") {
            if let Ok(n) = v.parse() {
                self.limits.max_request_bytes = n;
            }
        }
        if let Ok(v) = std::env::var("AEGIS_RATE_RPS") {
            if let Ok(n) = v.parse() {
                self.limits.rate_limit_rps = n;
            }
        }
        if let Ok(v) = std::env::var("AEGIS_RATE_BURST") {
            if let Ok(n) = v.parse() {
                self.limits.rate_limit_burst = n;
            }
        }
        if let Ok(v) = std::env::var("AEGIS_POLICY_BUNDLE") {
            self.policy.bundle = Some(v);
        }
        if let Ok(v) = std::env::var("AEGIS_POLICY_PUBLIC_KEY") {
            self.policy.public_key = Some(v);
        }
        if let Ok(v) = std::env::var("AEGIS_REQUIRE_SIGNED") {
            self.policy.require_signed = v != "false" && v != "0";
        }
        if let Ok(v) = std::env::var("AEGIS_OTEL_ENABLED") {
            self.observability.otel_enabled = v != "false" && v != "0";
        }
        if let Ok(v) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            self.observability.otlp_endpoint = Some(v);
        }
        if let Ok(v) = std::env::var("AEGIS_OTLP_ENDPOINT") {
            self.observability.otlp_endpoint = Some(v);
        }
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.limits.max_request_bytes == 0 || self.limits.max_request_bytes > 256 * 1024 * 1024 {
            anyhow::bail!("max_request_bytes out of range");
        }
        if self.limits.request_timeout_ms == 0 || self.limits.request_timeout_ms > 300_000 {
            anyhow::bail!("request_timeout_ms out of range");
        }
        if !(0.0..=100_000.0).contains(&self.limits.rate_limit_rps) {
            anyhow::bail!("rate_limit_rps out of range");
        }
        if self.limits.rate_limit_burst == 0 || self.limits.rate_limit_burst > 1_000_000 {
            anyhow::bail!("rate_limit_burst out of range");
        }
        if self.policy.path.is_empty() {
            anyhow::bail!("policy.path must not be empty");
        }
        if self.policy.require_signed {
            match (&self.policy.bundle, &self.policy.public_key) {
                (Some(b), Some(k)) if !b.is_empty() && !k.is_empty() => {}
                _ => anyhow::bail!(
                    "policy.require_signed is true but policy.bundle/public_key are not both set"
                ),
            }
        }
        if self.observability.otel_enabled
            && self
                .observability
                .otlp_endpoint
                .as_deref()
                .unwrap_or("")
                .is_empty()
        {
            anyhow::bail!("observability.otel_enabled is true but otlp_endpoint is not set");
        }
        if let Some(ep) = &self.observability.otlp_endpoint {
            if !(ep.starts_with("http://") || ep.starts_with("https://")) {
                anyhow::bail!("observability.otlp_endpoint must start with http:// or https://");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_fail_closed() {
        let c = Config::default();
        assert!(c.security.fail_closed);
        assert!(c.validate().is_ok());
    }
    #[test]
    fn parses_example() {
        let y = r#"server: {mode: proxy}
security: {fail_closed: true}
policy: {path: ./policy}
taint: {enabled: true}
classifier: {enabled: true, provider: heuristic}
audit: {enabled: true, database: ./aegis.db}
sandbox: {enabled: false}
network: {deny_metadata_endpoints: true}
limits: {max_request_bytes: 10485760, request_timeout_ms: 5000}
"#;
        let c = Config::from_yaml_str(y).unwrap();
        assert_eq!(c.policy.path, "./policy");
    }
    #[test]
    fn rejects_bad_limits() {
        let mut c = Config::default();
        c.limits.max_request_bytes = 0;
        assert!(c.validate().is_err());
    }
    #[test]
    fn require_signed_needs_bundle_and_key() {
        let mut c = Config::default();
        c.policy.require_signed = true;
        assert!(c.validate().is_err());
        c.policy.bundle = Some("bundle.json".into());
        assert!(c.validate().is_err());
        c.policy.public_key = Some("00".into());
        assert!(c.validate().is_ok());
    }
    #[test]
    fn otel_enabled_needs_endpoint() {
        let mut c = Config::default();
        c.observability.otel_enabled = true;
        assert!(c.validate().is_err());
        c.observability.otlp_endpoint = Some("not-a-url".into());
        assert!(c.validate().is_err());
        c.observability.otlp_endpoint = Some("http://localhost:4318".into());
        assert!(c.validate().is_ok());
    }
}
