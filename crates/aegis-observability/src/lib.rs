//! Observability: tracing setup + Prometheus metrics + redacted spans +
//! OpenTelemetry (W3C trace context + OTLP/HTTP export, no new deps).
use prometheus::{HistogramVec, IntCounterVec, Registry};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    pub requests: IntCounterVec,
    pub blocks: IntCounterVec,
    pub policy_latency: HistogramVec,
    pub classifier_latency: HistogramVec,
    pub proxy_latency: HistogramVec,
    pub parser_latency: HistogramVec,
    pub taint_events: IntCounterVec,
    pub approvals: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let requests = IntCounterVec::new(
            prometheus::Opts::new("aegis_requests_total", "total MCP requests"),
            &["method", "decision"],
        )?;
        let blocks = IntCounterVec::new(
            prometheus::Opts::new("aegis_blocks_total", "total blocked requests"),
            &["policy"],
        )?;
        let policy_latency = HistogramVec::new(
            prometheus::HistogramOpts::new("aegis_policy_latency", "policy eval latency seconds"),
            &["outcome"],
        )?;
        let classifier_latency = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "aegis_classifier_latency",
                "classifier latency seconds",
            ),
            &["provider"],
        )?;
        let proxy_latency = HistogramVec::new(
            prometheus::HistogramOpts::new("aegis_proxy_latency", "total gateway latency seconds"),
            &["decision"],
        )?;
        let taint_events = IntCounterVec::new(
            prometheus::Opts::new("aegis_taint_events_total", "taint events"),
            &["kind"],
        )?;
        let parser_latency = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "aegis_parser_latency",
                "JSON-RPC parse latency seconds",
            ),
            &["outcome"],
        )?;
        let approvals = IntCounterVec::new(
            prometheus::Opts::new("aegis_approvals_total", "approval lifecycle transitions"),
            &["transition"],
        )?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(blocks.clone()))?;
        registry.register(Box::new(policy_latency.clone()))?;
        registry.register(Box::new(classifier_latency.clone()))?;
        registry.register(Box::new(proxy_latency.clone()))?;
        registry.register(Box::new(parser_latency.clone()))?;
        registry.register(Box::new(taint_events.clone()))?;
        registry.register(Box::new(approvals.clone()))?;
        Ok(Self {
            requests,
            blocks,
            policy_latency,
            classifier_latency,
            proxy_latency,
            parser_latency,
            taint_events,
            approvals,
        })
    }
}

pub struct Observability {
    pub registry: Registry,
    pub metrics: Metrics,
    pub otel: OtelConfig,
}

#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub service_name: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "aegis-mcp".into(),
        }
    }
}

impl Observability {
    pub fn init() -> anyhow::Result<Arc<Self>> {
        Self::init_with_config(false, None, "aegis-mcp".into())
    }

    /// Initialize tracing + Prometheus, optionally enabling the OTLP/HTTP
    /// exporter. Never panics; OTel export failures are logged and the
    /// gateway continues (deterministic policy is unaffected).
    pub fn init_with_config(
        otel_enabled: bool,
        otlp_endpoint: Option<String>,
        service_name: String,
    ) -> anyhow::Result<Arc<Self>> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .json()
            .try_init()
            .ok();
        if otel_enabled {
            let ep = otlp_endpoint.as_deref().unwrap_or("");
            if ep.is_empty() {
                anyhow::bail!("otel_enabled but otlp_endpoint is not set");
            }
            if !(ep.starts_with("http://") || ep.starts_with("https://")) {
                anyhow::bail!("otlp_endpoint must start with http:// or https://");
            }
            if ep.starts_with("https://") {
                tracing::warn!(
                    "built-in OTLP exporter supports http:// only; https:// endpoints fail export with a descriptive error (use a local collector with http://)"
                );
            }
        }
        let registry = Registry::new();
        let metrics = Metrics::new(&registry)?;
        Ok(Arc::new(Self {
            registry,
            metrics,
            otel: OtelConfig {
                enabled: otel_enabled,
                endpoint: otlp_endpoint,
                service_name,
            },
        }))
    }

    /// Export one span via OTLP/HTTP JSON. `http://` only (no TLS deps);
    /// disabled exporter or `https://` returns a descriptive error and never
    /// panics. Attributes must already be redacted by the caller.
    pub async fn export_span(
        &self,
        span: &OtelSpan,
        extra_attrs: &[(&str, &str)],
    ) -> anyhow::Result<()> {
        if !self.otel.enabled {
            anyhow::bail!("otel exporter is disabled");
        }
        let ep = self.otel.endpoint.as_deref().unwrap_or("");
        export_otlp_span(ep, &self.otel.service_name, span, extra_attrs).await
    }
    pub fn render_prometheus(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = vec![];
        encoder.encode(&families, &mut buf).unwrap_or_default();
        String::from_utf8_lossy(&buf).to_string()
    }
}

/// W3C trace context (subset): 128-bit trace id + 64-bit span id.
/// Randomness uses a lightweight xorshift seeded from system time —
/// cryptographic strength is not required for trace ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub sampled: bool,
}

impl TraceContext {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        // xorshift64* mix + process id for cross-process uniqueness.
        seed ^= std::process::id() as u64;
        let mut next = || {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed = seed.wrapping_mul(0x2545F4914F6CDD1D);
            seed
        };
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        for b in trace_id.iter_mut().take(8) {
            *b = (next() >> 33) as u8;
        }
        for b in trace_id.iter_mut().skip(8) {
            *b = (next() >> 17) as u8;
        }
        for b in span_id.iter_mut() {
            *b = (next() >> 41) as u8;
        }
        // Zero ids are invalid per W3C; remap to 1.
        if trace_id.iter().all(|&b| b == 0) {
            trace_id[15] = 1;
        }
        if span_id.iter().all(|&b| b == 0) {
            span_id[7] = 1;
        }
        Self {
            trace_id,
            span_id,
            sampled: true,
        }
    }

    /// Render `traceparent: 00-<trace>-<span>-01|00`.
    pub fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{}",
            hex::encode(self.trace_id),
            hex::encode(self.span_id),
            if self.sampled { "01" } else { "00" }
        )
    }

    /// Parse a `traceparent` header. Rejects malformed/zero ids (fail-closed:
    /// callers must generate a fresh context on `None`).
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.trim().split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }
        let trace = hex::decode(parts[1]).ok()?;
        let span = hex::decode(parts[2]).ok()?;
        if trace.len() != 16 || span.len() != 8 {
            return None;
        }
        if trace.iter().all(|&b| b == 0) || span.iter().all(|&b| b == 0) {
            return None;
        }
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        trace_id.copy_from_slice(&trace);
        span_id.copy_from_slice(&span);
        let sampled = parts[3] == "01";
        Some(Self {
            trace_id,
            span_id,
            sampled,
        })
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// A single exportable span. `attributes` must already be redacted —
/// Lewton rule: never put tool arguments, secrets, or raw payloads here;
/// only low-cardinality verdict metadata (tool, decision, policy).
#[derive(Debug, Clone)]
pub struct OtelSpan {
    pub trace: TraceContext,
    pub name: String,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    pub attributes: Vec<(String, String)>,
}

impl OtelSpan {
    pub fn new(trace: TraceContext, name: impl Into<String>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            trace,
            name: name.into(),
            start_unix_nano: now,
            end_unix_nano: now,
            attributes: vec![],
        }
    }

    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.attributes.push((k.into(), v.into()));
        self
    }
}

/// Build the OTLP/HTTP JSON body for one span (spec: `resourceSpans[0]
/// .scopeSpans[0].spans[0]`). Pure function — unit-testable without network.
pub fn otlp_body(service_name: &str, span: &OtelSpan) -> serde_json::Value {
    let attrs: Vec<serde_json::Value> = span
        .attributes
        .iter()
        .map(|(k, v)| serde_json::json!({"key": k, "value": {"stringValue": v}}))
        .collect();
    serde_json::json!({
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": service_name}}
            ]},
            "scopeSpans": [{
                "scope": {"name": "aegis-mcp"},
                "spans": [{
                    "traceId": hex::encode(span.trace.trace_id),
                    "spanId": hex::encode(span.trace.span_id),
                    "name": span.name,
                    "startTimeUnixNano": span.start_unix_nano.to_string(),
                    "endTimeUnixNano": span.end_unix_nano.to_string(),
                    "attributes": attrs,
                    "status": {"code": 1}
                }]
            }]
        }]
    })
}

/// POST one span to `<endpoint>/v1/traces` over plain HTTP. Only `http://`
/// endpoints are supported (the crate has no TLS deps by design); `https://`
/// returns a descriptive error. Timeouts fail safe (5 s).
pub async fn export_otlp_span(
    endpoint: &str,
    service_name: &str,
    span: &OtelSpan,
    extra_attrs: &[(&str, &str)],
) -> anyhow::Result<()> {
    if endpoint.starts_with("https://") {
        anyhow::bail!(
            "built-in OTLP exporter supports http:// only (got https://); run a local collector with an http:// listener"
        );
    }
    if !endpoint.starts_with("http://") {
        anyhow::bail!("otlp_endpoint must start with http:// or https://");
    }
    let mut enriched = span.clone();
    for (k, v) in extra_attrs {
        enriched.attributes.push((k.to_string(), v.to_string()));
    }
    let body = otlp_body(service_name, &enriched).to_string();
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    http_post_json(&url, &body).await
}

async fn http_post_json(url: &str, body: &str) -> anyhow::Result<()> {
    // Minimal HTTP/1.1 client over tokio TcpStream (http:// only).
    // Parses status code; 2xx = ok, anything else = error (no panic paths).
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("bad url: {}", e))?;
    if parsed.scheme() != "http" {
        anyhow::bail!("only http:// URLs are supported by the built-in exporter");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("url has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let path = match parsed.query() {
        Some(q) => format!("{}?{}", path, q),
        None => path.to_string(),
    };
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("otlp connect timeout"))?
    .map_err(|e| anyhow::anyhow!("otlp connect failed: {}", e))?;
    let mut stream = stream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        body.len(),
        body
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.write_all(req.as_bytes()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("otlp write timeout"))?
    .map_err(|e| anyhow::anyhow!("otlp write failed: {}", e))?;
    let mut raw = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut raw),
    )
    .await
    .map_err(|_| anyhow::anyhow!("otlp read timeout"))?
    .map_err(|e| anyhow::anyhow!("otlp read failed: {}", e))?;
    let head = String::from_utf8_lossy(&raw);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        Ok(())
    } else {
        anyhow::bail!("otlp export failed with http status {}", status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metrics_register_and_render() {
        let reg = Registry::new();
        let m = Metrics::new(&reg).unwrap();
        m.requests.with_label_values(&["tools/call", "ALLOW"]).inc();
        m.blocks.with_label_values(&["p"]).inc();
        m.policy_latency
            .with_label_values(&["allow"])
            .observe(0.001);
        m.parser_latency.with_label_values(&["ok"]).observe(0.0005);
        m.approvals.with_label_values(&["requested"]).inc();
        let o = Observability {
            registry: reg,
            metrics: m,
            otel: OtelConfig::default(),
        };
        let text = o.render_prometheus();
        assert!(text.contains("aegis_requests_total"));
        assert!(text.contains("aegis_blocks_total"));
        assert!(text.contains("aegis_parser_latency"));
        assert!(text.contains("aegis_approvals_total"));
    }

    #[test]
    fn traceparent_roundtrip_and_rejects_bad() {
        let ctx = TraceContext::new();
        let header = ctx.traceparent();
        assert!(header.starts_with("00-"));
        let parsed = TraceContext::from_traceparent(&header).expect("roundtrip");
        assert_eq!(parsed, ctx);
        assert!(TraceContext::from_traceparent("bogus").is_none());
        assert!(TraceContext::from_traceparent(
            "00-00000000000000000000000000000000-0000000000000000-01"
        )
        .is_none());
        assert!(TraceContext::from_traceparent(
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01-extra"
        )
        .is_none());
    }

    #[test]
    fn otlp_body_shape_and_no_secrets_by_construction() {
        let trace = TraceContext::new();
        let span = OtelSpan::new(trace.clone(), "aegis.tools/call")
            .with_attr("tool", "filesystem_read")
            .with_attr("decision", "DENY");
        let body = otlp_body("aegis-mcp", &span);
        assert_eq!(
            body["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            serde_json::json!("aegis-mcp")
        );
        let wire = body.to_string();
        // Only low-cardinality verdict metadata is embedded — no args/secrets.
        assert!(wire.contains("filesystem_read"));
        assert!(!wire.contains("sk-"));
        assert_eq!(
            body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"],
            serde_json::json!(hex::encode(trace.trace_id))
        );
    }

    #[test]
    fn init_with_config_validates_otel() {
        assert!(Observability::init_with_config(false, None, "aegis-mcp".into()).is_ok());
        assert!(Observability::init_with_config(
            true,
            Some("http://localhost:4318".into()),
            "aegis-mcp".into()
        )
        .is_ok());
        assert!(Observability::init_with_config(true, None, "aegis-mcp".into()).is_err());
        assert!(Observability::init_with_config(
            true,
            Some("not-a-url".into()),
            "aegis-mcp".into()
        )
        .is_err());
    }

    #[tokio::test]
    async fn export_span_fails_safe_when_disabled_or_https() {
        let obs = Observability::init_with_config(false, None, "aegis-mcp".into()).unwrap();
        let span = OtelSpan::new(TraceContext::new(), "test");
        assert!(obs.export_span(&span, &[]).await.is_err());
        assert!(
            export_otlp_span("https://x.example.com", "aegis-mcp", &span, &[])
                .await
                .is_err()
        );
        assert!(export_otlp_span("not-a-url", "aegis-mcp", &span, &[])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn export_span_posts_to_local_collector() {
        // Tiny local OTLP stub: accept one POST /v1/traces, answer 200.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(raw.contains("POST /v1/traces"));
            assert!(raw.contains("aegis.tools/call"));
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            let _ = socket.write_all(resp.as_bytes()).await;
        });
        let obs = Observability::init_with_config(
            true,
            Some(format!("http://127.0.0.1:{}", port)),
            "aegis-mcp".into(),
        )
        .unwrap();
        let span = OtelSpan::new(TraceContext::new(), "aegis.tools/call")
            .with_attr("tool", "echo")
            .with_attr("decision", "ALLOW");
        obs.export_span(&span, &[]).await.expect("export ok");
        server.await.unwrap();
    }
}
