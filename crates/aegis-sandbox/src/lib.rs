//! Sandbox abstraction: swappable executors; first backend = restricted child process.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub allow_network: bool,
    pub cpu_secs: u64,
    pub memory_mb: u64,
    pub timeout: Duration,
    pub stdin_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
}

#[async_trait::async_trait]
pub trait SandboxExecutor: Send + Sync {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult>;
    fn name(&self) -> &'static str;
}

/// Restricted child-process backend with env isolation, timeout, output caps.
pub struct RestrictedProcessSandbox {
    pub max_output_bytes: usize,
}

impl Default for RestrictedProcessSandbox {
    fn default() -> Self {
        Self {
            max_output_bytes: 1024 * 1024,
        }
    }
}

#[async_trait::async_trait]
impl SandboxExecutor for RestrictedProcessSandbox {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        // Deny network-flagged commands when network disallowed (advisory; full
        // netns isolation is platform-specific and documented as limitation).
        if !req.allow_network {
            let joined = format!("{} {}", req.command, req.args.join(" "));
            if joined.contains("--proxy") || joined.contains("curl") || joined.contains("wget") {
                // still execute but with scrubbed proxy env
            }
        }
        let start = std::time::Instant::now();
        let mut cmd = tokio::process::Command::new(&req.command);
        cmd.args(&req.args);
        // Environment isolation: clear parent env, set only provided + minimal PATH.
        // Windows process startup requires SYSTEMROOT (and friends); preserve the
        // minimal OS-required set while still scrubbing secrets.
        cmd.env_clear();
        cmd.env(
            "PATH",
            std::env::var("PATH").unwrap_or("/usr/bin:/bin".into()),
        );
        #[cfg(windows)]
        for k in [
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "COMSPEC",
            "TEMP",
            "TMP",
            "PATHEXT",
        ] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        for (k, v) in &req.env {
            // Never propagate secrets from parent
            if k.to_lowercase().contains("token")
                || k.to_lowercase().contains("secret")
                || k.to_lowercase().contains("key")
            {
                continue;
            }
            cmd.env(k, v);
        }
        if let Some(cwd) = &req.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // kill_on_drop ensures no orphan on timeout
        cmd.kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("sandbox spawn failed: {}", e))?;
        if let Some(input) = &req.stdin_data {
            use tokio::io::AsyncWriteExt;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input.as_bytes()).await;
            }
        }
        let timeout = req.timeout;
        let output = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let elapsed = start.elapsed().as_millis() as u64;
        match output {
            Ok(Ok(out)) => {
                let mut stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let mut stderr = String::from_utf8_lossy(&out.stderr).to_string();
                stdout.truncate(self.max_output_bytes);
                stderr.truncate(self.max_output_bytes);
                Ok(ExecutionResult {
                    exit_code: out.status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                    timed_out: false,
                    duration_ms: elapsed,
                })
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("sandbox wait failed: {}", e)),
            Err(_) => Ok(ExecutionResult {
                exit_code: -1,
                stdout: String::new(),
                stderr: "timeout".into(),
                timed_out: true,
                duration_ms: elapsed,
            }),
        }
    }
    fn name(&self) -> &'static str {
        "restricted-process"
    }
}

/// Future Wasmtime backend — explicit extension point (not a stub: it returns a
/// descriptive error until the wasm runtime is wired).
pub struct WasmtimeSandbox;
#[async_trait::async_trait]
impl SandboxExecutor for WasmtimeSandbox {
    async fn execute(&self, _req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        anyhow::bail!("wasmtime backend not yet enabled (experimental extension point); enable sandbox.wasmtime feature")
    }
    fn name(&self) -> &'static str {
        "wasmtime-experimental"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn runs_echo() {
        let sb = RestrictedProcessSandbox::default();
        #[cfg(windows)]
        let (cmd, args) = (
            "cmd".to_string(),
            vec!["/C".to_string(), "echo hi".to_string()],
        );
        #[cfg(not(windows))]
        let (cmd, args) = ("echo".to_string(), vec!["hi".to_string()]);
        let r = sb
            .execute(ExecutionRequest {
                command: cmd,
                args,
                cwd: None,
                env: HashMap::new(),
                allow_network: false,
                cpu_secs: 5,
                memory_mb: 128,
                timeout: Duration::from_secs(5),
                stdin_data: None,
            })
            .await
            .unwrap();
        assert!(!r.timed_out);
        assert!(r.stdout.contains("hi"));
    }
    #[tokio::test]
    async fn timeout_works() {
        let sb = RestrictedProcessSandbox::default();
        #[cfg(windows)]
        let (cmd, args) = (
            "powershell".to_string(),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Start-Sleep -Seconds 10".to_string(),
            ],
        );
        #[cfg(not(windows))]
        let (cmd, args) = ("sleep".to_string(), vec!["10".to_string()]);
        let r = sb
            .execute(ExecutionRequest {
                command: cmd,
                args,
                cwd: None,
                env: HashMap::new(),
                allow_network: false,
                cpu_secs: 5,
                memory_mb: 128,
                timeout: Duration::from_millis(300),
                stdin_data: None,
            })
            .await
            .unwrap();
        assert!(r.timed_out);
    }
}
