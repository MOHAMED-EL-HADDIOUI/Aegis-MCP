//! Aegis-MCP CLI: proxy, inspect, tools, policy, audit, incidents, approvals, config, benchmark.
use aegis_config::Config;
use aegis_core::Decision;
use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegis-mcp",
    version,
    about = "Zero-trust runtime security gateway for MCP"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    quiet: bool,
    #[arg(long, global = true, default_value = "./aegis.yaml")]
    config: String,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Proxy {
        #[arg(long, default_value = "stdio")]
        client: String,
        #[arg(long, default_value = "")]
        server: String,
        /// Remote MCP server base URL (http://host:port). When set, allowed
        /// calls are forwarded over HTTP JSON-RPC instead of a stdio child.
        #[arg(long, default_value = "")]
        upstream_url: String,
        /// Signed policy bundle file (JSON from `policy sign`).
        #[arg(long, default_value = "")]
        bundle: String,
        /// Hex-encoded ed25519 public key for bundle verification.
        #[arg(long, default_value = "")]
        public_key: String,
        /// Refuse to start unless the signed bundle verifies (fail-closed).
        #[arg(long, default_value_t = false)]
        require_signed_bundle: bool,
    },
    Inspect {
        file: String,
    },
    Tools {
        #[command(subcommand)]
        sub: ToolsCmd,
    },
    Policy {
        #[command(subcommand)]
        sub: PolicyCmd,
    },
    Audit {
        #[command(subcommand)]
        sub: AuditCmd,
    },
    Incidents {
        #[command(subcommand)]
        sub: IncidentCmd,
    },
    Approvals {
        #[command(subcommand)]
        sub: ApprovalCmd,
    },
    Config {
        #[command(subcommand)]
        sub: ConfigCmd,
    },
    Benchmark,
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// Signed policy bundle file (JSON from `policy sign`).
        #[arg(long, default_value = "")]
        bundle: String,
        /// Hex-encoded ed25519 public key for bundle verification.
        #[arg(long, default_value = "")]
        public_key: String,
        /// Refuse to start unless the signed bundle verifies (fail-closed).
        #[arg(long, default_value_t = false)]
        require_signed_bundle: bool,
    },
}

#[derive(Subcommand)]
enum ToolsCmd {
    List,
    Fingerprint { file: String },
}
#[derive(Subcommand)]
enum PolicyCmd {
    Test {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        fixture: String,
    },
    Validate {
        #[arg(long)]
        policy: String,
    },
    Keygen,
    Sign {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        out: String,
    },
    Verify {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        key: String,
    },
}
#[derive(Subcommand)]
enum AuditCmd {
    List {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    Verify,
}
#[derive(Subcommand)]
enum IncidentCmd {
    List,
    Set { id: String, status: String },
}
#[derive(Subcommand)]
enum ApprovalCmd {
    List,
    Approve { id: String },
    Deny { id: String },
}
#[derive(Subcommand)]
enum ConfigCmd {
    Validate,
}

fn load_config(path: &str) -> Config {
    if std::path::Path::new(path).exists() {
        Config::from_file(path).unwrap_or_default()
    } else {
        Config::default()
    }
}

/// CLI bundle flags override `aegis.yaml` policy bundle settings.
/// Empty strings mean "no override"; the flag is the explicit operator
/// intent at startup and wins over the file.
fn apply_bundle_overrides(cfg: &mut Config, bundle: &str, public_key: &str, require_signed: bool) {
    if !bundle.is_empty() {
        cfg.policy.bundle = Some(bundle.to_string());
    }
    if !public_key.is_empty() {
        cfg.policy.public_key = Some(public_key.to_string());
    }
    if require_signed {
        cfg.policy.require_signed = true;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    match cli.cmd {
        Commands::Proxy {
            client,
            server,
            upstream_url,
            bundle,
            public_key,
            require_signed_bundle,
        } => {
            run_proxy(
                &cli.config,
                &client,
                &server,
                &upstream_url,
                &bundle,
                &public_key,
                require_signed_bundle,
            )
            .await
        }
        Commands::Inspect { file } => inspect_file(&file, cli.json),
        Commands::Tools { sub } => match sub {
            ToolsCmd::List => tools_list(&cli.config, cli.json),
            ToolsCmd::Fingerprint { file } => tools_fingerprint(&file, cli.json),
        },
        Commands::Policy { sub } => match sub {
            PolicyCmd::Test { policy, fixture } => policy_test(&policy, &fixture, cli.json),
            PolicyCmd::Validate { policy } => policy_validate(&policy, cli.json),
            PolicyCmd::Keygen => policy_keygen(cli.json),
            PolicyCmd::Sign { policy, key, out } => policy_sign(&policy, &key, &out, cli.json),
            PolicyCmd::Verify { bundle, key } => policy_verify(&bundle, &key, cli.json),
        },
        Commands::Audit { sub } => match sub {
            AuditCmd::List { limit } => audit_list(&cli.config, limit, cli.json),
            AuditCmd::Verify => audit_verify(&cli.config, cli.json),
        },
        Commands::Incidents { sub } => match sub {
            IncidentCmd::List => incidents_list(&cli.config, cli.json),
            IncidentCmd::Set { id, status } => incident_set(&cli.config, &id, &status, cli.json),
        },
        Commands::Approvals { sub } => match sub {
            ApprovalCmd::List => approvals_list(&cli.config, cli.json),
            ApprovalCmd::Approve { id } => approval_set(&cli.config, &id, "APPROVED", cli.json),
            ApprovalCmd::Deny { id } => approval_set(&cli.config, &id, "DENIED", cli.json),
        },
        Commands::Config { sub } => match sub {
            ConfigCmd::Validate => {
                let cfg = load_config(&cli.config);
                cfg.validate()?;
                emit(cli.json, &serde_json::json!({"ok": true}));
                Ok(())
            }
        },
        Commands::Benchmark => run_benchmark(cli.json),
        Commands::Serve {
            bind,
            bundle,
            public_key,
            require_signed_bundle,
        } => {
            serve_api(
                &cli.config,
                &bind,
                &bundle,
                &public_key,
                require_signed_bundle,
            )
            .await
        }
    }
}

fn emit(json: bool, v: &serde_json::Value) {
    if json {
        println!("{}", serde_json::to_string_pretty(v).unwrap());
    } else {
        // Human-readable: compact single-line JSON per value.
        println!("{}", serde_json::to_string(v).unwrap());
    }
}

/// Transparent proxy: client stdin -> inspect -> upstream; blocked calls are
/// answered directly and never forwarded.
/// Upstream modes (mutually exclusive):
/// - stdio (default): `--server "cmd args..."` spawns a child MCP server.
/// - http: `--upstream-url http://host:port` forwards allowed calls over
///   HTTP JSON-RPC (`aegis-protocol::HttpTransport`, SSE unwrapped).
async fn run_proxy(
    config_path: &str,
    _client: &str,
    server: &str,
    upstream_url: &str,
    bundle: &str,
    public_key: &str,
    require_signed_bundle: bool,
) -> anyhow::Result<()> {
    let mut cfg = load_config(config_path);
    apply_bundle_overrides(&mut cfg, bundle, public_key, require_signed_bundle);
    cfg.validate()?;
    let gw = aegis_proxy::Gateway::new(cfg)?;
    if !upstream_url.is_empty() {
        return run_proxy_http(gw, upstream_url).await;
    }
    if server.is_empty() {
        anyhow::bail!(
            "--server \"command args...\" or --upstream-url http://host:port is required"
        );
    }
    let parts = shell_words::split(server).context("bad --server command")?;
    let (prog, args) = parts.split_first().context("empty --server")?;
    let mut child = tokio::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("failed to spawn MCP server")?;
    let mut server_stdin = child.stdin.take().context("no server stdin")?;
    let server_stdout = child.stdout.take().context("no server stdout")?;
    let session = uuid::Uuid::new_v4().to_string();

    // server -> client forwarder
    let stdout_handle = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut reader = BufReader::new(server_stdout).lines();
        let mut out = tokio::io::stdout();
        while let Ok(Some(line)) = reader.next_line().await {
            // Responses from server: fingerprint tools, then forward
            let _ = out.write_all(format!("{}\n", line).as_bytes()).await;
            let _ = out.flush().await;
        }
    });

    // client -> server loop with inspection
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(block) = gw.handle_line(&session, "mcp-server", &line).await {
            // Blocked: answer client directly, do NOT forward
            let mut out = tokio::io::stdout();
            out.write_all(format!("{}\n", block).as_bytes()).await?;
            out.flush().await?;
        } else {
            use tokio::io::AsyncWriteExt as _;
            server_stdin
                .write_all(format!("{}\n", line).as_bytes())
                .await?;
            server_stdin.flush().await?;
        }
    }
    stdout_handle.abort();
    let _ = child.kill().await;
    Ok(())
}

/// HTTP upstream proxy loop: same inspection pipeline, but allowed calls are
/// forwarded with `HttpTransport` (SSE unwrapped) and the upstream reply is
/// written back to the client. Blocked calls never touch the network.
async fn run_proxy_http(
    gw: std::sync::Arc<aegis_proxy::Gateway>,
    upstream_url: &str,
) -> anyhow::Result<()> {
    use aegis_protocol::Transport as _;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let transport = aegis_protocol::HttpTransport::new(upstream_url);
    let session = uuid::Uuid::new_v4().to_string();
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut out = tokio::io::stdout();
    while let Ok(Some(line)) = reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(block) = gw.handle_line(&session, "mcp-server", &line).await {
            out.write_all(format!("{}\n", block).as_bytes()).await?;
            out.flush().await?;
        } else {
            match transport
                .send(aegis_protocol::encode_stdio_frame(&line))
                .await
            {
                Ok(Some(reply)) => {
                    out.write_all(format!("{}\n", reply.trim()).as_bytes())
                        .await?;
                    out.flush().await?;
                }
                Ok(None) => {}
                Err(e) => {
                    let err = aegis_protocol::error_response(
                        None,
                        -32000,
                        &format!("upstream error: {}", e),
                    );
                    out.write_all(format!("{}\n", err).as_bytes()).await?;
                    out.flush().await?;
                }
            }
        }
    }
    Ok(())
}

fn inspect_file(file: &str, json: bool) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(file)?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let tools: Vec<aegis_protocol::ToolDefinition> = v
        .pointer("/result/tools")
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| serde_json::from_value(t.clone()).ok())
                .collect()
        })
        .or_else(|| serde_json::from_value::<Vec<aegis_protocol::ToolDefinition>>(v.clone()).ok())
        .unwrap_or_default();
    let mut out = vec![];
    for t in &tools {
        let poison =
            aegis_security::inspect_tool_description(&t.name, &t.description, &t.input_schema);
        let rec =
            aegis_proxy::fingerprint_tool("inspected", &t.name, &t.description, &t.input_schema);
        out.push(serde_json::json!({
            "tool": t.name,
            "tool_id": rec.tool_id,
            "schema_hash": rec.schema_hash,
            "description_hash": rec.description_hash,
            "poison_score": poison.score,
            "poison_reasons": poison.reasons,
            "urls": poison.urls,
        }));
    }
    emit(json, &serde_json::json!({"tools": out}));
    Ok(())
}

fn tools_list(config_path: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)
        .unwrap_or(aegis_audit::AuditLog::open_in_memory()?);
    let evs = log.list_events(1000)?;
    let mut tools: std::collections::BTreeSet<String> = Default::default();
    for e in evs {
        if e.event_type == "TOOL_DISCOVERED" {
            tools.insert(e.tool);
        }
    }
    emit(
        json,
        &serde_json::json!({"tools": tools.into_iter().collect::<Vec<_>>()}),
    );
    Ok(())
}

fn tools_fingerprint(file: &str, json: bool) -> anyhow::Result<()> {
    inspect_file(file, json)
}

fn policy_test(policy: &str, fixture: &str, json: bool) -> anyhow::Result<()> {
    let engine = aegis_policy::Engine::load_dir(policy)
        .or_else(|_| aegis_policy::Engine::load_yaml_str(&std::fs::read_to_string(policy)?))?;
    let raw = std::fs::read_to_string(fixture)?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let tool = v
        .get("tool")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let input = aegis_policy::EvalInput {
        tool,
        server: v
            .get("server")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .into(),
        path: v.get("path").and_then(|s| s.as_str()).unwrap_or("").into(),
        url: v.get("url").and_then(|s| s.as_str()).unwrap_or("").into(),
        taints: v
            .get("taints")
            .and_then(|t| t.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        risk_score: v.get("risk").and_then(|r| r.as_f64()).unwrap_or(0.0) as f32,
        args: v.get("args").cloned().unwrap_or_default(),
        rate_rps: v
            .get("rate")
            .and_then(|r| r.as_f64().or_else(|| r.as_str()?.trim().parse().ok()))
            .unwrap_or(0.0) as f32,
        now_unix: v.get("now").and_then(|n| n.as_i64()),
        ..Default::default()
    };
    let outcome = engine.evaluate(&input);
    emit(
        json,
        &serde_json::json!({"decision": outcome.decision, "policy": outcome.policy, "reason": outcome.reason}),
    );
    Ok(())
}

fn policy_validate(policy: &str, json: bool) -> anyhow::Result<()> {
    let check_one = |path: &std::path::Path| -> Vec<String> {
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_yaml::from_str::<aegis_policy::PolicyFile>(&s) {
                Ok(pf) => aegis_policy::Engine::validate(&pf),
                Err(e) => vec![format!("yaml error: {}", e)],
            },
            Err(e) => vec![format!("read error: {}", e)],
        }
    };
    let p = std::path::Path::new(policy);
    fn collect_yaml(
        dir: &std::path::Path,
        out: &mut Vec<std::path::PathBuf>,
    ) -> anyhow::Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                collect_yaml(&path, out)?;
            } else if path.extension().and_then(|e| e.to_str()) == Some("yaml")
                || path.extension().and_then(|e| e.to_str()) == Some("yml")
            {
                out.push(path);
            }
        }
        Ok(())
    }
    let mut errors = vec![];
    if p.is_dir() {
        let mut files = vec![];
        collect_yaml(p, &mut files)?;
        if files.is_empty() {
            errors.push(format!("no policy files found under {}", p.display()));
        }
        for path in files {
            for e in check_one(&path) {
                errors.push(format!("{}: {}", path.display(), e));
            }
        }
    } else {
        errors = check_one(p);
    }
    if errors.is_empty() {
        emit(json, &serde_json::json!({"ok": true}));
    } else {
        emit(json, &serde_json::json!({"ok": false, "errors": errors}));
        anyhow::bail!("policy validation failed");
    }
    Ok(())
}

fn policy_keygen(json: bool) -> anyhow::Result<()> {
    let (secret, public) = aegis_policy::generate_keypair();
    emit(
        json,
        &serde_json::json!({"secret_key": secret, "public_key": public,
            "warning": "store the secret key offline; it cannot be recovered"}),
    );
    Ok(())
}

fn load_policy_merged(policy: &str) -> anyhow::Result<aegis_policy::PolicyFile> {
    let p = std::path::Path::new(policy);
    if p.is_dir() {
        // Merge recursively in sorted path order (same order Engine::load_dir uses).
        let mut rules = vec![];
        fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> anyhow::Result<()> {
            let mut entries: Vec<_> = std::fs::read_dir(dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    collect(&path, out)?;
                } else if path.extension().and_then(|e| e.to_str()) == Some("yaml")
                    || path.extension().and_then(|e| e.to_str()) == Some("yml")
                {
                    out.push(path);
                }
            }
            Ok(())
        }
        let mut files = vec![];
        collect(p, &mut files)?;
        for f in files {
            let s = std::fs::read_to_string(&f)?;
            let pf: aegis_policy::PolicyFile = serde_yaml::from_str(&s)?;
            rules.extend(pf.rules);
        }
        Ok(aegis_policy::PolicyFile {
            version: "1".into(),
            rules,
        })
    } else {
        let s = std::fs::read_to_string(p)?;
        Ok(serde_yaml::from_str(&s)?)
    }
}

fn policy_sign(policy: &str, key: &str, out: &str, json: bool) -> anyhow::Result<()> {
    let pf = load_policy_merged(policy)?;
    let bundle = aegis_policy::sign_bundle(&pf, key)?;
    std::fs::write(out, serde_json::to_string_pretty(&bundle)?)?;
    emit(
        json,
        &serde_json::json!({"ok": true, "digest": bundle.digest,
            "rules": bundle.rules.len(), "out": out}),
    );
    Ok(())
}

fn policy_verify(bundle: &str, key: &str, json: bool) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(bundle)?;
    let b: aegis_policy::SignedBundle = serde_json::from_str(&raw)?;
    aegis_policy::verify_bundle(&b, key)?;
    emit(
        json,
        &serde_json::json!({"ok": true, "digest": b.digest, "rules": b.rules.len()}),
    );
    Ok(())
}

fn audit_list(config_path: &str, limit: usize, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    emit(
        json,
        &serde_json::json!({"events": log.list_events(limit)?}),
    );
    Ok(())
}

fn audit_verify(config_path: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    let (checked, ok) = log.verify()?;
    emit(json, &serde_json::json!({"checked": checked, "ok": ok}));
    if !ok {
        anyhow::bail!("audit chain verification failed");
    }
    Ok(())
}

fn incidents_list(config_path: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    emit(
        json,
        &serde_json::json!({"incidents": log.list_incidents()?}),
    );
    Ok(())
}

fn incident_set(config_path: &str, id: &str, status: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    log.set_incident_status(id, status)?;
    emit(json, &serde_json::json!({"ok": true}));
    Ok(())
}

fn approvals_list(config_path: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    emit(
        json,
        &serde_json::json!({"approvals": log.list_approvals(false)?}),
    );
    Ok(())
}

fn approval_set(config_path: &str, id: &str, status: &str, json: bool) -> anyhow::Result<()> {
    let cfg = load_config(config_path);
    let log = aegis_audit::AuditLog::open(&cfg.audit.database)?;
    log.set_approval(id, status)?;
    let ev = if status == "APPROVED" {
        "APPROVAL_GRANTED"
    } else {
        "APPROVAL_DENIED"
    };
    let decision = if status == "APPROVED" {
        Some(Decision::Allow)
    } else {
        Some(Decision::Deny)
    };
    log.append(
        "cli",
        "cli",
        "approval",
        ev,
        decision,
        Some("approval"),
        Some(id),
        0.0,
        &[],
        None,
        id,
    )?;
    emit(json, &serde_json::json!({"ok": true}));
    Ok(())
}

fn run_benchmark(json: bool) -> anyhow::Result<()> {
    // Micro-benchmarks: parse, policy, fingerprint, full pipeline.
    // Each reports mean + p50/p95/p99 over per-iteration samples.
    fn percentiles(mut samples: Vec<f64>) -> (f64, f64, f64, f64) {
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let q = |p: f64| {
            if samples.is_empty() {
                return 0.0;
            }
            samples[((p * samples.len() as f64) as usize).min(samples.len() - 1)]
        };
        let mean = samples.iter().sum::<f64>() / samples.len().max(1) as f64;
        (mean, q(0.5), q(0.95), q(0.99))
    }
    let parse_raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem_read","arguments":{"path":"./workspace/a"}}}"#;
    let mut parse_samples = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let t0 = std::time::Instant::now();
        let _ = aegis_protocol::parse_message(parse_raw, 10 * 1024 * 1024);
        parse_samples.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    let (parse_mean, parse_p50, parse_p95, parse_p99) = percentiles(parse_samples);
    let engine = aegis_policy::Engine::load_yaml_str("version: \"1\"\nrules:\n  - {name: allow-read, action: allow, when: {tool: filesystem_read, path_prefix: ./workspace}}\n")?;
    let input = aegis_policy::EvalInput {
        tool: "filesystem_read".into(),
        path: "./workspace/a".into(),
        ..Default::default()
    };
    let mut policy_samples = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let t0 = std::time::Instant::now();
        let _ = engine.evaluate(&input);
        policy_samples.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    let (policy_mean, policy_p50, policy_p95, policy_p99) = percentiles(policy_samples);
    let schema = serde_json::json!({"type":"object","properties":{"path":{"type":"string"}}});
    let mut fp_samples = Vec::with_capacity(2000);
    for _ in 0..2000 {
        let t0 = std::time::Instant::now();
        let _ = aegis_proxy::fingerprint_tool("srv", "filesystem_read", "read files", &schema);
        fp_samples.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    let (fp_mean, fp_p50, fp_p95, fp_p99) = percentiles(fp_samples);
    // Backward-compatible top-level means.
    emit(
        json,
        &serde_json::json!({
            "parse_us": parse_mean, "policy_us": policy_mean, "fingerprint_us": fp_mean,
            "parse": {"mean_us": parse_mean, "p50_us": parse_p50, "p95_us": parse_p95, "p99_us": parse_p99},
            "policy": {"mean_us": policy_mean, "p50_us": policy_p50, "p95_us": policy_p95, "p99_us": policy_p99},
            "fingerprint": {"mean_us": fp_mean, "p50_us": fp_p50, "p95_us": fp_p95, "p99_us": fp_p99},
            "targets": {"parse_us": 1000.0, "policy_us": 1000.0, "fingerprint_us": 1000.0, "overhead_ms": 5.0},
            "pass": parse_p99 < 1000.0 && policy_p99 < 1000.0 && fp_p99 < 1000.0
        }),
    );
    Ok(())
}

async fn serve_api(
    config_path: &str,
    bind: &str,
    bundle: &str,
    public_key: &str,
    require_signed_bundle: bool,
) -> anyhow::Result<()> {
    let mut cfg = load_config(config_path);
    apply_bundle_overrides(&mut cfg, bundle, public_key, require_signed_bundle);
    cfg.validate()?;
    // Fail-closed startup check: Gateway::new verifies the bundle when
    // required, so a bad bundle never serves traffic.
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("aegis-mcp api on http://{}", bind);
    aegis_proxy::serve_rest_api(cfg, listener).await
}
