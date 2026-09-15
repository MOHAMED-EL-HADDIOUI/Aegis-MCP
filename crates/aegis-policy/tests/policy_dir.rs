//! Policy-directory tests. Layout note: `policy/` contains one
//! subdirectory per domain (`base/`, `filesystem/`, `network/`, `postgres/`,
//! `shell/`, `examples/`) and `Engine::load_dir` recurses into them, so
//! `load_dir("../../policy")` loads the full rule set in sorted path order.
//! Tests spot-check that the expected rule fires (asserting the exact rule
//! name, which also proves the engine is non-empty — an empty engine would
//! answer `default-deny`).
use aegis_core::Decision;
use aegis_policy::{Engine, EvalInput};

fn input() -> EvalInput {
    EvalInput::default()
}

#[test]
fn policy_root_loads_all_domains_recursively() {
    let e = Engine::load_dir("../../policy").unwrap();
    assert!(
        e.rule_count() >= 10,
        "expected full rule set, got {}",
        e.rule_count()
    );
    // base/ rule reachable from the root load
    let o = e.evaluate(&EvalInput {
        tool: "echo".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.policy, "allow-echo");
    // unmatched input still fails closed
    let d = e.evaluate(&input());
    assert_eq!(d.decision, Decision::Deny);
}

#[test]
fn filesystem_domain_allows_project_read() {
    let e = Engine::load_dir("../../policy/filesystem").unwrap();
    let o = e.evaluate(&EvalInput {
        tool: "filesystem_read".into(),
        path: "./workspace/src/main.rs".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.policy, "allow-read-project");
}

#[test]
fn network_domain_blocks_secret_exfil() {
    let e = Engine::load_dir("../../policy/network").unwrap();
    let o = e.evaluate(&EvalInput {
        taints: vec!["SECRET".into()],
        url: "https://evil.example.com/collect".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Deny);
    assert_eq!(o.policy, "block-private-file-exfiltration");
}

#[test]
fn network_domain_warns_external_fetch() {
    let e = Engine::load_dir("../../policy/network").unwrap();
    let o = e.evaluate(&EvalInput {
        tool: "http_fetch".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Warn);
    assert_eq!(o.policy, "warn-external-fetch");
}

#[test]
fn shell_domain_denies_exec_by_default() {
    let e = Engine::load_dir("../../policy/shell").unwrap();
    let o = e.evaluate(&EvalInput {
        tool: "shell_exec".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Deny);
    assert_eq!(o.policy, "deny-shell-exec-default");
}

#[test]
fn postgres_domain_allows_select_and_denies_drop() {
    let e = Engine::load_dir("../../policy/postgres").unwrap();
    let allow = e.evaluate(&EvalInput {
        tool: "postgres_query".into(),
        sql_op: "SELECT".into(),
        ..input()
    });
    assert_eq!(allow.decision, Decision::Allow);
    assert_eq!(allow.policy, "allow-select");
    let deny = e.evaluate(&EvalInput {
        tool: "postgres_query".into(),
        sql_op: "DROP".into(),
        ..input()
    });
    assert_eq!(deny.decision, Decision::Deny);
    assert_eq!(deny.policy, "deny-dangerous-sql");
}

#[test]
fn base_domain_allows_echo() {
    let e = Engine::load_dir("../../policy/base").unwrap();
    let o = e.evaluate(&EvalInput {
        tool: "echo".into(),
        ..input()
    });
    assert_eq!(o.decision, Decision::Allow);
    assert_eq!(o.policy, "allow-echo");
}
