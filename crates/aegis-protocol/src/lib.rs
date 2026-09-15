//! JSON-RPC 2.0 + MCP normalization, validation, method registry.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const SUPPORTED_METHODS: &[&str] = &[
    "initialize",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub annotations: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    #[serde(default)]
    pub content: serde_json::Value,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptObject {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub raw: String,
    pub method: Option<String>,
    pub id: Option<serde_json::Value>,
    pub is_notification: bool,
    pub tool_call: Option<ToolCall>,
    pub tool_definitions: Vec<ToolDefinition>,
}

#[derive(Debug, Clone)]
pub struct MethodRegistry {
    known: HashSet<String>,
}

impl Default for MethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodRegistry {
    pub fn new() -> Self {
        Self {
            known: SUPPORTED_METHODS.iter().map(|s| s.to_string()).collect(),
        }
    }
    pub fn register(&mut self, method: impl Into<String>) {
        self.known.insert(method.into());
    }
    pub fn is_known(&self, method: &str) -> bool {
        self.known.contains(method)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid json: {0}")]
    InvalidJson(String),
    #[error("invalid jsonrpc version")]
    BadVersion,
    #[error("missing method")]
    MissingMethod,
    #[error("message too large: {0} > {1}")]
    TooLarge(usize, usize),
    #[error("invalid request id")]
    BadId,
}

pub fn parse_message(raw: &str, max_bytes: usize) -> Result<ParsedMessage, ProtocolError> {
    if raw.len() > max_bytes {
        return Err(ProtocolError::TooLarge(raw.len(), max_bytes));
    }
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| ProtocolError::InvalidJson(e.to_string()))?;
    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());
    let id = v.get("id").cloned();
    if let Some(i) = &id {
        if !(i.is_string() || i.is_number() || i.is_null()) {
            return Err(ProtocolError::BadId);
        }
    }
    if v.get("jsonrpc").and_then(|j| j.as_str()) != Some("2.0") {
        return Err(ProtocolError::BadVersion);
    }
    let is_notification = method.is_some() && id.is_none();
    let mut tool_call = None;
    if method.as_deref() == Some("tools/call") {
        let params = v.get("params").cloned().unwrap_or_default();
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        if !name.is_empty() {
            tool_call = Some(ToolCall { name, arguments });
        }
    }
    let mut tool_definitions = vec![];
    // tools/list responses carry definitions under result.tools
    if let Some(tools) = v.pointer("/result/tools").and_then(|t| t.as_array()) {
        for t in tools {
            if let Ok(d) = serde_json::from_value::<ToolDefinition>(t.clone()) {
                tool_definitions.push(d);
            }
        }
    }
    Ok(ParsedMessage {
        raw: raw.to_string(),
        method,
        id,
        is_notification,
        tool_call,
        tool_definitions,
    })
}

pub fn error_response(id: Option<serde_json::Value>, code: i32, message: &str) -> String {
    serde_json::to_string(&JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    })
    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal"}}"#.into())
}

/// Canonical JSON: sorted keys, compact. Used before hashing for fingerprints/audit.
pub fn canonical_json(value: &serde_json::Value) -> String {
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

pub fn method_params_map() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("initialize", "handshake"),
        ("tools/list", "discovery"),
        ("tools/call", "execution"),
        ("resources/list", "discovery"),
        ("resources/read", "read"),
        ("prompts/list", "discovery"),
        ("prompts/get", "read"),
    ])
}

// ---------------- transports ----------------

/// Common abstraction over MCP transports. Every transport moves whole
/// JSON-RPC text frames; framing/encoding details live in the impl.
/// `stdio` is the primary local transport; `http` covers remote MCP servers
/// speaking JSON-RPC over HTTP POST with optional SSE streaming.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, frame: String) -> anyhow::Result<Option<String>>;
    fn name(&self) -> &'static str;
}

/// Newline-delimited stdio framing helpers (pure functions so the child
/// process plumbing in `aegis-cli proxy` stays thin and testable).
pub fn encode_stdio_frame(body: &str) -> String {
    let mut s = body.trim_end_matches(['\n', '\r']).to_string();
    s.push('\n');
    s
}

/// Split a byte stream into complete lines; the remainder (partial line) is
/// returned for buffering. Never panics on arbitrary bytes (lossy decode).
pub fn decode_stdio_frames(chunk: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(chunk)
        .split('\n')
        .map(|l| l.trim_end_matches('\r').to_string())
        .filter(|l| !l.trim().is_empty())
        .collect()
}

/// One Server-Sent Event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Parse an SSE byte stream into events. Handles `event:` / `data:` fields,
/// multi-line `data:` (joined with `\n`), comments (`:`), and both `\n` and
/// `\r\n` endings. Incomplete trailing blocks without a blank-line
/// terminator are ignored (callers buffer more bytes).
pub fn parse_sse_stream(body: &str) -> Vec<SseEvent> {
    let mut out = vec![];
    let normalized = body.replace("\r\n", "\n");
    // Per SSE, an event is dispatched only on a blank-line terminator.
    // A trailing block without its blank line is an incomplete buffer:
    // ignore it so callers can append more bytes.
    let mut blocks: Vec<&str> = normalized.split("\n\n").collect();
    if !normalized.ends_with("\n\n") {
        blocks.pop();
    }
    for block in blocks {
        let mut event: Option<String> = None;
        let mut data_lines: Vec<String> = vec![];
        for line in block.split('\n') {
            if line.is_empty() || line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                // Per SSE spec only one leading space is stripped.
                let v = rest.strip_prefix(' ').unwrap_or(rest);
                data_lines.push(v.to_string());
            }
        }
        if !data_lines.is_empty() {
            out.push(SseEvent {
                event,
                data: data_lines.join("\n"),
            });
        }
    }
    out
}

/// Extract JSON-RPC frames from SSE events (MCP over SSE wraps each frame in
/// `data: {...}`). Non-JSON `data:` lines (e.g. pings) are skipped.
pub fn sse_jsonrpc_frames(body: &str) -> Vec<String> {
    parse_sse_stream(body)
        .into_iter()
        .map(|e| e.data.trim().to_string())
        .filter(|d| d.starts_with('{'))
        .collect()
}

/// Minimal HTTP JSON-RPC client over plain `http://` (no TLS deps by design).
/// Used to proxy to remote MCP servers. `https://` fails closed with a
/// descriptive error (run a local http:// sidecar or collector instead).
pub struct HttpTransport {
    pub base_url: String,
    pub timeout_ms: u64,
}

impl HttpTransport {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout_ms: 5000,
        }
    }

    async fn post(&self, path: &str, body: &str) -> anyhow::Result<(u16, String)> {
        let base = self.base_url.trim_end_matches('/');
        let url = format!("{}{}", base, path);
        http_post_raw(&url, body, self.timeout_ms).await
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn send(&self, frame: String) -> anyhow::Result<Option<String>> {
        // POST the frame to `/` (MCP HTTP servers accept the JSON-RPC body
        // at the base URL). SSE responses are unwrapped to the first frame.
        let (status, body) = self.post("", &frame).await?;
        if !(200..300).contains(&status) {
            anyhow::bail!("http transport: upstream status {}", status);
        }
        let trimmed = body.trim();
        if trimmed.contains("text/event-stream") || trimmed.contains("data:") {
            let frames = sse_jsonrpc_frames(&body);
            return Ok(frames.into_iter().next());
        }
        if trimmed.is_empty() {
            return Ok(None);
        }
        Ok(Some(body))
    }
    fn name(&self) -> &'static str {
        "http"
    }
}

async fn http_post_raw(url: &str, body: &str, timeout_ms: u64) -> anyhow::Result<(u16, String)> {
    let parsed = url::Url::parse(url).map_err(|e| anyhow::anyhow!("bad url: {}", e))?;
    if parsed.scheme() == "https" {
        anyhow::bail!("built-in http transport supports http:// only (got https://)");
    }
    if parsed.scheme() != "http" {
        anyhow::bail!("only http:// URLs are supported");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("url has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    let mut path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };
    if let Some(q) = parsed.query() {
        path = format!("{}?{}", path, q);
    }
    let addr = format!("{}:{}", host, port);
    let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
    let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("http connect timeout"))?
        .map_err(|e| anyhow::anyhow!("http connect failed: {}", e))?;
    let mut stream = stream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json, text/event-stream\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        body.len(),
        body
    );
    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("http write timeout"))?
        .map_err(|e| anyhow::anyhow!("http write failed: {}", e))?;
    let mut raw = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut raw))
        .await
        .map_err(|_| anyhow::anyhow!("http read timeout"))?
        .map_err(|e| anyhow::anyhow!("http read failed: {}", e))?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_tool_call() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fs_read","arguments":{"path":"a"}}}"#;
        let m = parse_message(raw, 1024 * 1024).unwrap();
        assert_eq!(m.tool_call.unwrap().name, "fs_read");
    }
    #[test]
    fn rejects_bad_version() {
        let raw = r#"{"jsonrpc":"1.0","id":1,"method":"tools/list","params":{}}"#;
        assert!(parse_message(raw, 1024).is_err());
    }
    #[test]
    fn rejects_oversize() {
        assert!(parse_message("{}", 1).is_err());
    }
    #[test]
    fn canonical_sorts_keys() {
        let a = serde_json::json!({"b":1,"a":2});
        let b = serde_json::json!({"a":2,"b":1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }
    #[test]
    fn registry_extensible() {
        let mut r = MethodRegistry::new();
        assert!(r.is_known("tools/call"));
        assert!(!r.is_known("future/method"));
        r.register("future/method");
        assert!(r.is_known("future/method"));
    }
    #[test]
    fn malformed_never_panics() {
        for raw in ["", "{", "null", "[]", "{\"jsonrpc\":\"2.0\"}"] {
            let _ = parse_message(raw, 1024 * 1024);
        }
    }
    #[test]
    fn stdio_framing_roundtrip() {
        assert_eq!(encode_stdio_frame("{\"a\":1}"), "{\"a\":1}\n");
        assert_eq!(encode_stdio_frame("{\"a\":1}\n\n"), "{\"a\":1}\n");
        let frames = decode_stdio_frames(b"{\"a\":1}\n\n{\"b\":2}\r\n");
        assert_eq!(frames, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert!(decode_stdio_frames(b"\n  \n").is_empty());
        // Arbitrary bytes never panic.
        assert!(decode_stdio_frames(b"\x00\xff\xfe{}\n").len() <= 1);
    }
    #[test]
    fn sse_parses_events_and_skips_pings() {
        let body =
            ": ping\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1}\n\ndata: {\"a\":1}\n\n";
        let evs = parse_sse_stream(body);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event.as_deref(), Some("message"));
        let frames = sse_jsonrpc_frames(body);
        assert_eq!(frames.len(), 2);
        // Multi-line data joins with newline; CRLF tolerated.
        let multi = "data: line1\r\ndata: line2\r\n\r\n";
        assert_eq!(parse_sse_stream(multi)[0].data, "line1\nline2");
        // Unterminated trailing block is ignored (buffer more).
        assert!(parse_sse_stream("data: partial").is_empty());
    }
    #[test]
    fn http_rejects_https_fail_closed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let t = HttpTransport::new("https://example.com/mcp");
            assert!(t.send("{\"jsonrpc\":\"2.0\"}".into()).await.is_err());
            assert!(http_post_raw("not-a-url", "{}", 200).await.is_err());
        });
    }
    #[tokio::test]
    async fn http_posts_to_local_server() {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/",
            post(|body: String| async move {
                assert!(body.contains("tools/call"));
                axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let t = HttpTransport::new(format!("http://127.0.0.1:{}/", port));
        let resp = t
            .send("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}".into())
            .await
            .expect("post ok")
            .expect("body");
        assert!(resp.contains("\"ok\":true"), "got: {}", resp);
        assert_eq!(t.name(), "http");
    }
    #[tokio::test]
    async fn http_unwraps_sse_response() {
        use axum::routing::post;
        let sse = ": ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"echo\":1}}\n\n";
        let app = axum::Router::new().route(
            "/",
            post(move || {
                let sse = sse.to_string();
                async move { ([("content-type", "text/event-stream")], sse) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let t = HttpTransport::new(format!("http://127.0.0.1:{}", port));
        let frame = t
            .send("{\"jsonrpc\":\"2.0\",\"id\":9}".into())
            .await
            .expect("send ok")
            .expect("sse frame");
        assert!(frame.contains("\"echo\":1"), "got: {}", frame);
    }
}
