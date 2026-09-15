//! Adversarial corpus tests: every line of each `.jsonl` fixture in
//! `tests/fixtures/` must produce the detector outcome in its `expected`
//! field. Thresholds mirror the gateway pipeline:
//! - injection: `inspect_tool_description` score >= 0.5 means the gateway
//!   flags the call (deterministic guardrail at det_risk >= 0.5 forces at
//!   least REQUIRE_APPROVAL).
//! - traversal: `inspect_filesystem(.., "./workspace")` must deny.
//! - sql: `inspect_sql` must flag dangerous.
//! - ssrf: `inspect_network(.., &[], &[], true)` must deny.
use aegis_security::{inspect_filesystem, inspect_network, inspect_sql, inspect_tool_description};

fn corpus_lines(name: &str) -> Vec<serde_json::Value> {
    let path = format!("../../tests/fixtures/{}", name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("bad json in {}: {}: {}", name, l, e))
        })
        .collect()
}

#[test]
fn injection_corpus_matches_detector() {
    let rows = corpus_lines("injection_samples.jsonl");
    assert!(rows.len() >= 15, "need 15+ samples, got {}", rows.len());
    let mut blocked = 0;
    let mut allowed = 0;
    for r in &rows {
        let text = r.get("text").and_then(|v| v.as_str()).unwrap();
        let expected = r.get("expected").and_then(|v| v.as_str()).unwrap();
        let v = inspect_tool_description("tool", text, &serde_json::json!({}));
        match expected {
            "block" => {
                blocked += 1;
                assert!(
                    v.score >= 0.5,
                    "expected BLOCK (score>=0.5) for {:?}, got {:.2} ({:?})",
                    text,
                    v.score,
                    v.reasons
                );
            }
            "allow" => {
                allowed += 1;
                assert!(
                    v.score < 0.5,
                    "expected ALLOW (score<0.5) for {:?}, got {:.2} ({:?})",
                    text,
                    v.score,
                    v.reasons
                );
            }
            other => panic!("bad expected value {:?}", other),
        }
    }
    assert!(
        blocked >= 8 && allowed >= 3,
        "need both classes (block={}, allow={})",
        blocked,
        allowed
    );
}

#[test]
fn traversal_corpus_matches_detector() {
    let rows = corpus_lines("traversal_samples.jsonl");
    assert!(!rows.is_empty());
    for r in &rows {
        let path = r.get("path").and_then(|v| v.as_str()).unwrap();
        let expected = r.get("expected").and_then(|v| v.as_str()).unwrap();
        let v = inspect_filesystem(path, "./workspace");
        match expected {
            "block" => assert!(!v.allowed, "expected BLOCK for {:?} ({})", path, v.reason),
            "allow" => assert!(v.allowed, "expected ALLOW for {:?} ({})", path, v.reason),
            other => panic!("bad expected value {:?}", other),
        }
    }
}

#[test]
fn sql_corpus_matches_detector() {
    let rows = corpus_lines("sql_samples.jsonl");
    assert!(!rows.is_empty());
    for r in &rows {
        let query = r.get("query").and_then(|v| v.as_str()).unwrap();
        let expected = r.get("expected").and_then(|v| v.as_str()).unwrap();
        let v = inspect_sql(query);
        match expected {
            "block" => assert!(v.dangerous, "expected BLOCK for {:?} ({})", query, v.reason),
            "allow" => assert!(
                !v.dangerous,
                "expected ALLOW for {:?} ({})",
                query, v.reason
            ),
            other => panic!("bad expected value {:?}", other),
        }
    }
}

#[test]
fn ssrf_corpus_matches_detector() {
    let rows = corpus_lines("ssrf_samples.jsonl");
    assert!(!rows.is_empty());
    for r in &rows {
        let url = r.get("url").and_then(|v| v.as_str()).unwrap();
        let expected = r.get("expected").and_then(|v| v.as_str()).unwrap();
        let v = inspect_network(url, &[], &[], true);
        match expected {
            "block" => assert!(!v.allowed, "expected BLOCK for {:?} ({})", url, v.reason),
            "allow" => assert!(v.allowed, "expected ALLOW for {:?} ({})", url, v.reason),
            other => panic!("bad expected value {:?}", other),
        }
    }
}
