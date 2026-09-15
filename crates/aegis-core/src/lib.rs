//! Aegis core types: decisions, security context, risk, taint labels.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    Warn,
    RequireApproval,
    Sandbox,
}

impl Decision {
    pub fn is_terminal_deny(&self) -> bool {
        matches!(self, Decision::Deny)
    }
    pub fn allows_execution(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaintKind {
    UntrustedWeb,
    UntrustedUser,
    ExternalApi,
    McpServer,
    Unknown,
    Secret,
    PersonalData,
    SensitiveData,
    Trusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintLabel {
    pub kind: TaintKind,
    pub source: String,
    pub confidence: f32,
}

impl TaintLabel {
    pub fn new(kind: TaintKind, source: impl Into<String>, confidence: f32) -> Self {
        Self {
            kind,
            source: source.into(),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_score: f32,
    pub categories: Vec<String>,
    pub confidence: f32,
    pub explanation: String,
    pub injection_risk: f32,
    pub exfiltration_risk: f32,
    pub privilege_risk: f32,
}

impl Default for RiskAssessment {
    fn default() -> Self {
        Self {
            risk_score: 0.0,
            categories: vec![],
            confidence: 1.0,
            explanation: "no risk detected".into(),
            injection_risk: 0.0,
            exfiltration_risk: 0.0,
            privilege_risk: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub session_id: String,
    pub server_id: String,
    pub tool: String,
    pub args: serde_json::Value,
    pub taints: Vec<TaintLabel>,
    pub deterministic_risk: f32,
    pub policy_result: Option<PolicyOutcome>,
    pub ai_risk: Option<RiskAssessment>,
    pub timestamp: DateTime<Utc>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub decision: Decision,
    pub policy: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalVerdict {
    pub decision: Decision,
    pub policy: String,
    pub reason: String,
    pub risk_score: f32,
    pub taints: Vec<TaintLabel>,
}

/// Combine signals deterministically. AI can only escalate, never de-escalate
/// a deterministic DENY, and can never turn a policy DENY into ALLOW.
pub fn combine_verdict(ctx: &SecurityContext) -> FinalVerdict {
    let base = ctx.policy_result.clone().unwrap_or(PolicyOutcome {
        decision: Decision::Deny,
        policy: "fail-closed-no-policy".into(),
        reason: "no policy evaluated; failing closed".into(),
    });
    if base.decision == Decision::Deny {
        return FinalVerdict {
            decision: Decision::Deny,
            policy: base.policy,
            reason: base.reason,
            risk_score: combined_risk(ctx),
            taints: ctx.taints.clone(),
        };
    }
    // AI escalation: high AI risk upgrades Allow/Warn -> RequireApproval or Deny
    let ai_score = ctx.ai_risk.as_ref().map(|r| r.risk_score).unwrap_or(0.0);
    let risk = combined_risk(ctx);
    if ai_score >= 0.85 && base.decision == Decision::Allow {
        return FinalVerdict {
            decision: Decision::Deny,
            policy: base.policy,
            reason: format!("escalated to DENY by AI risk {:.2} (advisory)", ai_score),
            risk_score: risk,
            taints: ctx.taints.clone(),
        };
    }
    if ai_score >= 0.6 && base.decision == Decision::Allow {
        return FinalVerdict {
            decision: Decision::RequireApproval,
            policy: base.policy,
            reason: format!(
                "escalated to approval by AI risk {:.2} (advisory)",
                ai_score
            ),
            risk_score: risk,
            taints: ctx.taints.clone(),
        };
    }
    FinalVerdict {
        decision: base.decision,
        policy: base.policy,
        reason: base.reason,
        risk_score: risk,
        taints: ctx.taints.clone(),
    }
}

fn combined_risk(ctx: &SecurityContext) -> f32 {
    let ai = ctx.ai_risk.as_ref().map(|r| r.risk_score).unwrap_or(0.0);
    let taint_bonus = if ctx
        .taints
        .iter()
        .any(|t| matches!(t.kind, TaintKind::Secret | TaintKind::UntrustedWeb))
    {
        0.2
    } else if ctx.taints.is_empty() {
        0.0
    } else {
        0.1
    };
    (ctx.deterministic_risk.max(ai) + taint_bonus).clamp(0.0, 1.0)
}

/// Redact secrets from arbitrary text for logs/traces.
pub fn redact_secrets(input: &str) -> String {
    let mut out = input.to_string();
    // API keys / tokens / passwords in key=value or json form
    let patterns = [
        r#"(?i)(api[_-]?key["']?\s*[:=]\s*['"]?)[^'"\s,}]+(['"]?)"#,
        r#"(?i)(secret["']?\s*[:=]\s*['"]?)[^'"\s,}]+(['"]?)"#,
        r#"(?i)(password["']?\s*[:=]\s*['"]?)[^'"\s,}]+(['"]?)"#,
        r#"(?i)(bearer\s+)[A-Za-z0-9\-._~+/=]+"#,
        r#"sk-[A-Za-z0-9]{8,}"#,
        r#"xox[bpas]-[A-Za-z0-9-]{6,}"#,
        r#"(?i)(aws_secret[^'"\s]*['"\s:=]+)[A-Za-z0-9/+=]{8,}"#,
    ];
    for p in patterns {
        if let Ok(re) = regex::Regex::new(p) {
            out = re.replace_all(&out, "${1}***REDACTED***${2}").to_string();
        }
    }
    // PEM blocks
    if let Ok(re) = regex::Regex::new(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ) {
        out = re
            .replace_all(
                &out,
                "-----BEGIN PRIVATE KEY-----***REDACTED***-----END PRIVATE KEY-----",
            )
            .to_string();
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum AegisError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("security violation: {0}")]
    Security(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("audit error: {0}")]
    Audit(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(policy: Decision, ai: f32) -> SecurityContext {
        SecurityContext {
            session_id: "s".into(),
            server_id: "srv".into(),
            tool: "t".into(),
            args: serde_json::json!({}),
            taints: vec![],
            deterministic_risk: 0.1,
            policy_result: Some(PolicyOutcome {
                decision: policy,
                policy: "p".into(),
                reason: "r".into(),
            }),
            ai_risk: Some(RiskAssessment {
                risk_score: ai,
                ..Default::default()
            }),
            timestamp: Utc::now(),
            extra: HashMap::new(),
        }
    }

    #[test]
    fn ai_cannot_override_deny() {
        let v = combine_verdict(&ctx_with(Decision::Deny, 0.0));
        assert_eq!(v.decision, Decision::Deny);
    }

    #[test]
    fn ai_escalates_allow_to_approval_and_deny() {
        assert_eq!(
            combine_verdict(&ctx_with(Decision::Allow, 0.7)).decision,
            Decision::RequireApproval
        );
        assert_eq!(
            combine_verdict(&ctx_with(Decision::Allow, 0.9)).decision,
            Decision::Deny
        );
    }

    #[test]
    fn redact_does_not_leak() {
        let s = redact_secrets(r#"{"api_key": "sk-abcdefgh12345678", "password": "hunter2"}"#);
        assert!(!s.contains("abcdefgh"));
        assert!(!s.contains("hunter2"));
    }
}
