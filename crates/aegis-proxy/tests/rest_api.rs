//! REST control-plane tests: real HTTP against `serve_rest_api` on an
//! ephemeral port. Fully async client (tokio TcpStream) so the tests work
//! on Windows where blocking std I/O would starve the 2-worker test runtime.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn db_path(tag: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("aegis-rest-test-{}-{}.db", tag, std::process::id()));
    let _ = std::fs::remove_file(&p);
    p.to_string_lossy().replace('\\', "/")
}

fn test_config(db: &str) -> aegis_config::Config {
    let mut cfg = aegis_config::Config::default();
    cfg.audit.database = db.to_string();
    // Absolute policy dir: robust regardless of test CWD.
    cfg.policy.path = format!("{}/../../policy", env!("CARGO_MANIFEST_DIR"));
    cfg.limits.rate_limit_rps = 0.0; // deterministic: no throttling here
    cfg
}

async fn request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    request_with_headers(port, method, path, body, &[]).await
}

async fn request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let body = body.unwrap_or("");
    let mut extra = String::new();
    for (k, v) in headers {
        extra.push_str(&format!("{}: {}\r\n", k, v));
    }
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
        method,
        path,
        extra,
        body.len(),
        body
    );
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .expect("connect timeout")
    .expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = String::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut raw))
        .await
        .expect("read timeout")
        .expect("read");
    let status: u16 = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let payload = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, payload)
}

async fn serve_on_ephemeral(db: &str) -> u16 {
    let cfg = test_config(db);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = aegis_proxy::serve_rest_api(cfg, listener).await;
    });
    port
}

async fn wait_ready(port: u16) {
    for _ in 0..100 {
        if let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            let _ = s
                .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await;
            let mut buf = [0u8; 64];
            if s.read(&mut buf).await.is_ok() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never became ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_health_and_metrics() {
    let db = db_path("health");
    let port = serve_on_ephemeral(&db).await;
    wait_ready(port).await;
    let (status, body) = request(port, "GET", "/health", None).await;
    assert_eq!(status, 200);
    assert!(body.contains("aegis-mcp"), "got: {}", body);
    // Generate one request so Prometheus series exist (counters only
    // appear after first observation — standard Prometheus behavior).
    let (status, _) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","args":{"text":"hi"}}"#),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = request(port, "GET", "/metrics", None).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("aegis_requests_total"),
        "got metrics head: {}",
        &body[..body.len().min(200)]
    );
    let _ = std::fs::remove_file(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_inspect_allow_and_deny() {
    let db = db_path("inspect");
    let port = serve_on_ephemeral(&db).await;
    wait_ready(port).await;
    let (status, body) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","args":{"text":"hi"}}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", body);
    assert!(body.contains("\"decision\":\"ALLOW\""), "got: {}", body);
    let (status, body) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"filesystem_read","args":{"path":"../../.ssh/id_rsa"}}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", body);
    assert!(body.contains("\"decision\":\"DENY\""), "got: {}", body);
    let (status, body) = request(port, "POST", "/api/inspect", Some(r#"{"args":{}}"#)).await;
    assert_eq!(status, 400, "missing tool must 400, got: {}", body);
    let _ = std::fs::remove_file(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_approval_loop_end_to_end() {
    let db = db_path("approvals");
    let port = serve_on_ephemeral(&db).await;
    wait_ready(port).await;
    // A SECRET-tainted echo is held for approval and mints a request.
    let (status, held) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","server":"web","args":{"text":"svc password: hunter2"}}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", held);
    assert!(held.contains("REQUIRE_APPROVAL"), "got: {}", held);
    let (status, list) = request(port, "GET", "/api/approvals", None).await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&list).expect("approvals json");
    let id = v["approvals"][0]["id"]
        .as_str()
        .expect("approval id")
        .to_string();
    // Bad action is rejected without state change.
    let (status, _) = request(
        port,
        "POST",
        &format!("/api/approvals/{}", id),
        Some(r#"{"action":"maybe"}"#),
    )
    .await;
    assert_eq!(status, 400);
    // Unknown ids fail closed.
    let (status, _) = request(
        port,
        "POST",
        "/api/approvals/does-not-exist",
        Some(r#"{"action":"approve"}"#),
    )
    .await;
    assert_eq!(status, 422);
    // Approve, then the identical call is granted.
    let (status, done) = request(
        port,
        "POST",
        &format!("/api/approvals/{}", id),
        Some(r#"{"action":"approve"}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", done);
    let (status, granted) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","server":"web","args":{"text":"svc password: hunter2"}}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", granted);
    assert!(
        granted.contains("\"decision\":\"ALLOW\""),
        "got: {}",
        granted
    );
    assert!(granted.contains("approval-grant"), "got: {}", granted);
    let _ = std::fs::remove_file(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_cors_allows_dashboard_origin() {
    let db = db_path("cors");
    let port = serve_on_ephemeral(&db).await;
    wait_ready(port).await;
    // Preflight from the dashboard origin answers with the CORS grant.
    let (status, _) = request_with_headers(
        port,
        "OPTIONS",
        "/api/events",
        None,
        &[
            ("Origin", "http://127.0.0.1:3000"),
            ("Access-Control-Request-Method", "GET"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    // Real responses carry ACAO so browser fetches from :3000 succeed.
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    stream
        .write_all(
            b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:3000\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.expect("read");
    let head = raw.split("\r\n\r\n").next().unwrap_or("").to_lowercase();
    assert!(
        head.contains("access-control-allow-origin: *"),
        "CORS header missing, got head: {}",
        &head[..head.len().min(400)]
    );
    let _ = std::fs::remove_file(db);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_inspect_returns_traceparent() {
    let db = db_path("trace");
    let port = serve_on_ephemeral(&db).await;
    wait_ready(port).await;
    // No incoming header: server mints a fresh traceparent.
    let (status, body) = request(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","args":{"text":"hi"}}"#),
    )
    .await;
    assert_eq!(status, 200, "got: {}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("inspect json");
    let tp = v["traceparent"].as_str().expect("traceparent field");
    assert!(tp.starts_with("00-"), "got: {}", tp);
    // Valid incoming header passes through (same trace id, fresh span ok).
    let incoming = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";
    let (status, body) = request_with_headers(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","args":{"text":"hi"}}"#),
        &[("traceparent", incoming)],
    )
    .await;
    assert_eq!(status, 200, "got: {}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("inspect json");
    let tp2 = v["traceparent"].as_str().expect("traceparent field");
    assert!(
        tp2.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "trace id propagates, got: {}",
        tp2
    );
    // Garbage header fails closed to a fresh context (still 200 + valid).
    let (status, body) = request_with_headers(
        port,
        "POST",
        "/api/inspect",
        Some(r#"{"tool":"echo","args":{"text":"hi"}}"#),
        &[("traceparent", "bogus")],
    )
    .await;
    assert_eq!(status, 200, "got: {}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("inspect json");
    assert!(v["traceparent"].as_str().unwrap().starts_with("00-"));
    let _ = std::fs::remove_file(db);
}
