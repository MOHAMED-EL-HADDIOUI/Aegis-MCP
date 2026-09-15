//! Audit hash-chain tests: happy-path verification over 20 events plus a
//! tamper test that rewrites one link through a second SQLite connection
//! (rusqlite is already a dependency of `aegis-audit`, so no dev-deps needed)
//! and asserts `verify()` reports a broken chain.
use aegis_audit::AuditLog;
use aegis_core::Decision;

fn tmp_db(tag: &str) -> String {
    let p = std::env::temp_dir().join(format!("aegis-chain-{}-{}.db", std::process::id(), tag));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(p.with_extension("db-wal"));
    let _ = std::fs::remove_file(p.with_extension("db-shm"));
    p.to_string_lossy().to_string()
}

fn append_traffic(log: &AuditLog, n: usize) {
    for i in 0..n {
        let (tool, etype, decision) = if i % 4 == 3 {
            ("filesystem_read", "POLICY_DENY", Some(Decision::Deny))
        } else {
            ("filesystem_read", "POLICY_ALLOW", Some(Decision::Allow))
        };
        log.append(
            "sess-chain",
            "srv",
            tool,
            etype,
            decision,
            Some("allow-read-project"),
            Some("chain test"),
            0.1 + i as f32 * 0.01,
            &[],
            None,
            &format!("req-{}", i),
        )
        .unwrap();
    }
}

#[test]
fn chain_of_20_verifies() {
    let path = tmp_db("ok");
    let log = AuditLog::open(&path).unwrap();
    append_traffic(&log, 20);
    assert_eq!(log.list_events(100).unwrap().len(), 20);
    let (checked, ok) = log.verify().unwrap();
    assert_eq!(checked, 20);
    assert!(ok, "hash chain must verify");
}

#[test]
fn tampered_link_is_detected() {
    let path = tmp_db("tamper");
    let log = AuditLog::open(&path).unwrap();
    append_traffic(&log, 20);
    let (_, ok) = log.verify().unwrap();
    assert!(ok, "chain must verify before tampering");

    // Attacker rewrites one link out-of-band.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let n = conn
        .execute(
            "UPDATE events SET previous_event_hash='TAMPERED' WHERE rowid=5",
            [],
        )
        .unwrap();
    assert_eq!(n, 1);
    drop(conn);

    let (checked, ok) = log.verify().unwrap();
    assert_eq!(checked, 20);
    assert!(!ok, "verify must fail after tampering");
}
