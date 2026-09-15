//! Tamper-evident audit log (hash-chained SQLite WAL) + incidents + approvals.
use aegis_core::Decision;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub session_id: String,
    pub server_id: String,
    pub tool: String,
    pub event_type: String,
    pub decision: Option<Decision>,
    pub policy: Option<String>,
    pub reason: Option<String>,
    pub risk_score: f32,
    pub taints: Vec<String>,
    pub schema_hash: Option<String>,
    pub request_hash: String,
    pub previous_event_hash: String,
    pub event_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub severity: String,
    pub incident_type: String,
    pub source: String,
    pub target: String,
    pub status: String,
    pub event_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub tool: String,
    pub server: String,
    pub args: serde_json::Value,
    pub taints: Vec<String>,
    pub policies: Vec<String>,
    pub risk_score: f32,
    pub proposed_action: String,
    pub expires_at: DateTime<Utc>,
    pub status: String,
}

pub struct AuditLog {
    conn: Mutex<Connection>,
}

impl AuditLog {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS events(
            event_id TEXT PRIMARY KEY, timestamp TEXT, session_id TEXT, server_id TEXT,
            tool TEXT, event_type TEXT, decision TEXT, policy TEXT, reason TEXT,
            risk_score REAL, taints TEXT, schema_hash TEXT, request_hash TEXT,
            previous_event_hash TEXT, event_hash TEXT);
            CREATE TABLE IF NOT EXISTS incidents(
            incident_id TEXT PRIMARY KEY, severity TEXT, type TEXT, source TEXT,
            target TEXT, status TEXT, event_ids TEXT);
            CREATE TABLE IF NOT EXISTS approvals(
            id TEXT PRIMARY KEY, tool TEXT, server TEXT, args TEXT, taints TEXT,
            policies TEXT, risk_score REAL, proposed_action TEXT, expires_at TEXT, status TEXT);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE events(
            event_id TEXT PRIMARY KEY, timestamp TEXT, session_id TEXT, server_id TEXT,
            tool TEXT, event_type TEXT, decision TEXT, policy TEXT, reason TEXT,
            risk_score REAL, taints TEXT, schema_hash TEXT, request_hash TEXT,
            previous_event_hash TEXT, event_hash TEXT);
            CREATE TABLE incidents(
            incident_id TEXT PRIMARY KEY, severity TEXT, type TEXT, source TEXT,
            target TEXT, status TEXT, event_ids TEXT);
            CREATE TABLE approvals(
            id TEXT PRIMARY KEY, tool TEXT, server TEXT, args TEXT, taints TEXT,
            policies TEXT, risk_score REAL, proposed_action TEXT, expires_at TEXT, status TEXT);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn last_hash(&self) -> String {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or("GENESIS".to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        session: &str,
        server: &str,
        tool: &str,
        event_type: &str,
        decision: Option<Decision>,
        policy: Option<&str>,
        reason: Option<&str>,
        risk_score: f32,
        taints: &[String],
        schema_hash: Option<&str>,
        request_hash: &str,
    ) -> anyhow::Result<AuditEvent> {
        let prev = self.last_hash();
        let event_id = uuid::Uuid::new_v4().to_string();
        let ts = Utc::now();
        // Canonical encoding: decision as JSON string (same representation used
        // by `verify` and `list_events`). This keeps the chain self-consistent.
        let decision_str = serde_json::to_string(&decision).unwrap_or_default();
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            event_id,
            ts.to_rfc3339(),
            session,
            tool,
            event_type,
            decision_str,
            policy.unwrap_or(""),
            risk_score,
            request_hash,
            prev
        );
        let hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();
        let ev = AuditEvent {
            event_id: event_id.clone(),
            timestamp: ts,
            session_id: session.into(),
            server_id: server.into(),
            tool: tool.into(),
            event_type: event_type.into(),
            decision,
            policy: policy.map(|s| s.to_string()),
            reason: reason.map(|s| s.to_string()),
            risk_score,
            taints: taints.to_vec(),
            schema_hash: schema_hash.map(|s| s.to_string()),
            request_hash: request_hash.into(),
            previous_event_hash: prev,
            event_hash: hash.clone(),
        };
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                ev.event_id,
                ev.timestamp.to_rfc3339(),
                ev.session_id,
                ev.server_id,
                ev.tool,
                ev.event_type,
                serde_json::to_string(&ev.decision).unwrap_or_default(),
                ev.policy.clone().unwrap_or_default(),
                ev.reason.clone().unwrap_or_default(),
                ev.risk_score,
                serde_json::to_string(&ev.taints).unwrap_or_default(),
                ev.schema_hash.clone().unwrap_or_default(),
                ev.request_hash,
                ev.previous_event_hash,
                ev.event_hash
            ],
        )?;
        Ok(ev)
    }

    /// Verify hash chain integrity. Returns (checked, ok).
    pub fn verify(&self) -> anyhow::Result<(usize, bool)> {
        /// One audit-chain row: (id, ts, session, tool, type, decision, policy,
        /// risk, req_hash, prev_hash, hash).
        type AuditRow = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            f32,
            String,
            String,
            String,
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT event_id,timestamp,session_id,tool,event_type,decision,policy,risk_score,request_hash,previous_event_hash,event_hash FROM events ORDER BY rowid")?;
        let rows: Vec<AuditRow> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut prev = "GENESIS".to_string();
        for (
            id,
            ts,
            session,
            tool,
            etype,
            decision,
            policy,
            risk,
            req_hash,
            stored_prev,
            stored_hash,
        ) in &rows
        {
            if stored_prev != &prev {
                return Ok((rows.len(), false));
            }
            // Must match `append` canonical encoding exactly.
            let canonical = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                id, ts, session, tool, etype, decision, policy, risk, req_hash, prev
            );
            let recomputed = blake3::hash(canonical.as_bytes()).to_hex().to_string();
            if &recomputed != stored_hash {
                return Ok((rows.len(), false));
            }
            prev = stored_hash.clone();
        }
        Ok((rows.len(), true))
    }

    pub fn list_events(&self, limit: usize) -> anyhow::Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT event_id,timestamp,session_id,server_id,tool,event_type,decision,policy,reason,risk_score,taints,schema_hash,request_hash,previous_event_hash,event_hash FROM events ORDER BY rowid DESC LIMIT ?")?;
        let rows = stmt
            .query_map(params![limit as i64], |r| {
                let decision_str: String = r.get(6)?;
                let decision: Option<Decision> =
                    serde_json::from_str(&decision_str).unwrap_or(None);
                let taints: Vec<String> =
                    serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default();
                Ok(AuditEvent {
                    event_id: r.get(0)?,
                    timestamp: r
                        .get::<_, String>(1)?
                        .parse()
                        .unwrap_or_else(|_| Utc::now()),
                    session_id: r.get(2)?,
                    server_id: r.get(3)?,
                    tool: r.get(4)?,
                    event_type: r.get(5)?,
                    decision,
                    policy: Some(r.get(7)?),
                    reason: Some(r.get(8)?),
                    risk_score: r.get(9)?,
                    taints,
                    schema_hash: Some(r.get(11)?),
                    request_hash: r.get(12)?,
                    previous_event_hash: r.get(13)?,
                    event_hash: r.get(14)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn create_incident(
        &self,
        severity: &str,
        itype: &str,
        source: &str,
        target: &str,
        event_ids: &[String],
    ) -> anyhow::Result<Incident> {
        let count: i64 = self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM incidents", [], |r| r.get(0))
            .unwrap_or(0);
        let inc = Incident {
            incident_id: format!("INC-{:03}", count + 1),
            severity: severity.into(),
            incident_type: itype.into(),
            source: source.into(),
            target: target.into(),
            status: "OPEN".into(),
            event_ids: event_ids.to_vec(),
        };
        self.conn.lock().unwrap().execute(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?)",
            params![
                inc.incident_id,
                inc.severity,
                inc.incident_type,
                inc.source,
                inc.target,
                inc.status,
                serde_json::to_string(&inc.event_ids).unwrap()
            ],
        )?;
        Ok(inc)
    }

    pub fn list_incidents(&self) -> anyhow::Result<Vec<Incident>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT incident_id,severity,type,source,target,status,event_ids FROM incidents",
        )?;
        let x: Vec<Incident> = stmt
            .query_map([], |r| {
                Ok(Incident {
                    incident_id: r.get(0)?,
                    severity: r.get(1)?,
                    incident_type: r.get(2)?,
                    source: r.get(3)?,
                    target: r.get(4)?,
                    status: r.get(5)?,
                    event_ids: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(x)
    }

    pub fn set_incident_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        if ![
            "OPEN",
            "ACKNOWLEDGED",
            "MITIGATED",
            "RESOLVED",
            "FALSE_POSITIVE",
        ]
        .contains(&status)
        {
            anyhow::bail!("invalid incident status");
        }
        self.conn.lock().unwrap().execute(
            "UPDATE incidents SET status=? WHERE incident_id=?",
            params![status, id],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_approval(
        &self,
        tool: &str,
        server: &str,
        args: &serde_json::Value,
        taints: &[String],
        policies: &[String],
        risk: f32,
        action: &str,
    ) -> anyhow::Result<Approval> {
        let ap = Approval {
            id: uuid::Uuid::new_v4().to_string(),
            tool: tool.into(),
            server: server.into(),
            args: args.clone(),
            taints: taints.to_vec(),
            policies: policies.to_vec(),
            risk_score: risk,
            proposed_action: action.into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            status: "PENDING".into(),
        };
        self.conn.lock().unwrap().execute(
            "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?)",
            params![
                ap.id,
                ap.tool,
                ap.server,
                ap.args.to_string(),
                serde_json::to_string(&ap.taints).unwrap(),
                serde_json::to_string(&ap.policies).unwrap(),
                ap.risk_score,
                ap.proposed_action,
                ap.expires_at.to_rfc3339(),
                ap.status
            ],
        )?;
        Ok(ap)
    }

    pub fn set_approval(&self, id: &str, status: &str) -> anyhow::Result<()> {
        if !["APPROVED", "DENIED", "PENDING", "EXPIRED"].contains(&status) {
            anyhow::bail!("invalid approval status");
        }
        self.sweep_expired()?;
        if status == "APPROVED" {
            // Approving an expired (or missing) request must fail closed.
            let current: Option<Approval> =
                self.list_approvals(false)?.into_iter().find(|a| a.id == id);
            match current {
                Some(a) if a.status == "PENDING" && a.expires_at > Utc::now() => {}
                Some(a) => anyhow::bail!(
                    "approval {} is {} (expired at {})",
                    id,
                    a.status,
                    a.expires_at.to_rfc3339()
                ),
                None => anyhow::bail!("approval {} not found", id),
            }
        }
        let changed = self.conn.lock().unwrap().execute(
            "UPDATE approvals SET status=? WHERE id=?",
            params![status, id],
        )?;
        if changed == 0 {
            anyhow::bail!("approval {} not found", id);
        }
        Ok(())
    }

    /// Mark overdue PENDING approvals EXPIRED. Runs lazily on every
    /// approval read/write so expiry is enforced without a background task.
    /// Returns the number of rows transitioned.
    pub fn sweep_expired(&self) -> anyhow::Result<usize> {
        let now = Utc::now().to_rfc3339();
        let n = self.conn.lock().unwrap().execute(
            "UPDATE approvals SET status='EXPIRED' WHERE status='PENDING' AND expires_at < ?",
            params![now],
        )?;
        Ok(n)
    }

    /// Find a live APPROVED grant for an identical tool call (same server,
    /// tool, and canonical arguments). Returns the grant, if any.
    pub fn find_approved_grant(
        &self,
        server: &str,
        tool: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<Option<Approval>> {
        self.sweep_expired()?;
        let want = canonical_args(args);
        Ok(self.list_approvals(false)?.into_iter().find(|a| {
            a.status == "APPROVED"
                && a.expires_at > Utc::now()
                && a.server == server
                && a.tool == tool
                && canonical_args(&a.args) == want
        }))
    }

    /// Find a live PENDING request for an identical tool call, so the gateway
    /// reuses one approval ID instead of spamming duplicates.
    pub fn find_pending_request(
        &self,
        server: &str,
        tool: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<Option<Approval>> {
        self.sweep_expired()?;
        let want = canonical_args(args);
        Ok(self
            .list_approvals(true)?
            .into_iter()
            .find(|a| a.server == server && a.tool == tool && canonical_args(&a.args) == want))
    }

    pub fn list_approvals(&self, pending_only: bool) -> anyhow::Result<Vec<Approval>> {
        let conn = self.conn.lock().unwrap();
        let sql = if pending_only {
            "SELECT id,tool,server,args,taints,policies,risk_score,proposed_action,expires_at,status FROM approvals WHERE status='PENDING'"
        } else {
            "SELECT id,tool,server,args,taints,policies,risk_score,proposed_action,expires_at,status FROM approvals"
        };
        let mut stmt = conn.prepare(sql)?;
        let x: Vec<Approval> = stmt
            .query_map([], |r| {
                Ok(Approval {
                    id: r.get(0)?,
                    tool: r.get(1)?,
                    server: r.get(2)?,
                    args: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
                    taints: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                    policies: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
                    risk_score: r.get(6)?,
                    proposed_action: r.get(7)?,
                    expires_at: r
                        .get::<_, String>(8)?
                        .parse()
                        .unwrap_or_else(|_| Utc::now()),
                    status: r.get(9)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(x)
    }
}

/// Canonical JSON for argument comparison (sorted keys, compact).
fn canonical_args(value: &serde_json::Value) -> String {
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

/// Correlate events into an incident: injection + tainted input + external egress.
pub fn correlate_incident(events: &[AuditEvent]) -> Option<(String, String, String, String)> {
    let has_injection = events.iter().any(|e| e.event_type == "INJECTION_DETECTED");
    let has_taint = events.iter().any(|e| !e.taints.is_empty());
    let has_egress = events
        .iter()
        .any(|e| e.tool.contains("http") || e.tool.contains("fetch") || e.tool.contains("upload"));
    if has_injection && has_taint && has_egress {
        Some((
            "CRITICAL".into(),
            "DATA_EXFILTRATION".into(),
            "web_scrape".into(),
            "external_network".into(),
        ))
    } else if has_injection && has_taint {
        Some((
            "HIGH".into(),
            "PROMPT_INJECTION".into(),
            "untrusted_content".into(),
            "tool_call".into(),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chain_links_and_lists() {
        let log = AuditLog::open_in_memory().unwrap();
        log.append(
            "s",
            "srv",
            "t",
            "TOOL_CALL",
            Some(Decision::Allow),
            Some("p"),
            Some("ok"),
            0.1,
            &[],
            None,
            "h1",
        )
        .unwrap();
        log.append(
            "s",
            "srv",
            "t",
            "POLICY_ALLOW",
            Some(Decision::Allow),
            Some("p"),
            Some("ok"),
            0.1,
            &[],
            None,
            "h2",
        )
        .unwrap();
        let evs = log.list_events(10).unwrap();
        assert_eq!(evs.len(), 2);
        assert_ne!(evs[0].previous_event_hash, evs[0].event_hash);
        let (checked, ok) = log.verify().unwrap();
        assert_eq!(checked, 2);
        assert!(ok, "hash chain must verify");
    }
    #[test]
    fn incidents_and_approvals() {
        let log = AuditLog::open_in_memory().unwrap();
        let inc = log
            .create_incident(
                "CRITICAL",
                "DATA_EXFILTRATION",
                "web_scrape",
                "postgres_write",
                &[],
            )
            .unwrap();
        assert_eq!(inc.incident_id, "INC-001");
        log.set_incident_status(&inc.incident_id, "ACKNOWLEDGED")
            .unwrap();
        let ap = log
            .create_approval(
                "db_write",
                "srv",
                &serde_json::json!({}),
                &[],
                &["p".into()],
                0.9,
                "write",
            )
            .unwrap();
        assert_eq!(ap.status, "PENDING");
        log.set_approval(&ap.id, "APPROVED").unwrap();
        assert_eq!(log.list_approvals(false).unwrap().len(), 1);
        // Grant lookup matches identical calls only.
        let grant = log
            .find_approved_grant("srv", "db_write", &serde_json::json!({}))
            .unwrap();
        assert!(grant.is_some());
        assert!(log
            .find_approved_grant("srv", "other_tool", &serde_json::json!({}))
            .unwrap()
            .is_none());
    }
    #[test]
    fn expired_approvals_cannot_be_approved() {
        let log = AuditLog::open_in_memory().unwrap();
        let ap = log
            .create_approval("t", "srv", &serde_json::json!({"a": 1}), &[], &[], 0.5, "x")
            .unwrap();
        // Force expiry with direct SQL (simulates wall-clock passage).
        log.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE approvals SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                rusqlite::params![ap.id],
            )
            .unwrap();
        assert_eq!(log.sweep_expired().unwrap(), 1);
        assert!(log.set_approval(&ap.id, "APPROVED").is_err());
        assert!(log.set_approval(&ap.id, "NOPE").is_err());
        assert!(log.set_approval("does-not-exist", "DENIED").is_err());
    }
    #[test]
    fn correlate_detects_exfil() {
        let mk = |t: &str, tool: &str, taints: Vec<String>| AuditEvent {
            event_id: "x".into(),
            timestamp: Utc::now(),
            session_id: "s".into(),
            server_id: "srv".into(),
            tool: tool.into(),
            event_type: t.into(),
            decision: None,
            policy: None,
            reason: None,
            risk_score: 0.9,
            taints,
            schema_hash: None,
            request_hash: "h".into(),
            previous_event_hash: "p".into(),
            event_hash: "e".into(),
        };
        let evs = vec![
            mk("INJECTION_DETECTED", "web_scrape", vec![]),
            mk("TAINT_PROPAGATED", "llm", vec!["UNTRUSTED_WEB".into()]),
            mk("TOOL_CALL", "http_fetch", vec!["UNTRUSTED_WEB".into()]),
        ];
        let c = correlate_incident(&evs).unwrap();
        assert_eq!(c.1, "DATA_EXFILTRATION");
    }
}
