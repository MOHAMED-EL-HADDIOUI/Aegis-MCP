//! Taint propagation: sources, transforms, sanitization, declassification, provenance.
use aegis_core::{TaintKind, TaintLabel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedValue {
    pub value_id: String,
    pub taints: Vec<TaintLabel>,
}

#[derive(Debug, Clone, Default)]
pub struct TaintStore {
    values: HashMap<String, Vec<TaintLabel>>,
}

impl TaintStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn taint_value(&mut self, value_id: &str, label: TaintLabel) {
        self.values
            .entry(value_id.to_string())
            .or_default()
            .push(label);
    }
    pub fn taints_of(&self, value_id: &str) -> Vec<TaintLabel> {
        self.values.get(value_id).cloned().unwrap_or_default()
    }
    /// Propagate taint from inputs to output (union, max confidence per kind).
    pub fn propagate(&mut self, inputs: &[&str], output: &str) {
        let mut merged: HashMap<String, TaintLabel> = HashMap::new();
        for i in inputs {
            for t in self.taints_of(i) {
                let key = format!("{:?}|{}", t.kind, t.source);
                merged
                    .entry(key)
                    .and_modify(|e| {
                        e.confidence = e.confidence.max(t.confidence);
                    })
                    .or_insert(t);
            }
        }
        // SECRET is sticky: never dropped by plain propagation
        self.values
            .insert(output.to_string(), merged.into_values().collect());
    }
    /// Sanitization removes the given kinds (e.g. validated web content).
    pub fn sanitize(&mut self, value_id: &str, remove: &[TaintKind]) {
        if let Some(v) = self.values.get_mut(value_id) {
            v.retain(|t| !remove.contains(&t.kind));
        }
    }
    /// Declassify SECRET with explicit reason (audited by caller).
    pub fn declassify(&mut self, value_id: &str) {
        self.sanitize(value_id, &[TaintKind::Secret]);
    }
    /// Classify a tool result as a new taint source.
    pub fn source_from_tool(&mut self, value_id: &str, tool: &str, source: &str) {
        let kind = match tool {
            t if t.contains("web") || t.contains("scrape") || t.contains("fetch") => {
                TaintKind::UntrustedWeb
            }
            t if t.contains("user") => TaintKind::UntrustedUser,
            t if t.contains("http") || t.contains("api") => TaintKind::ExternalApi,
            _ => TaintKind::McpServer,
        };
        self.taint_value(value_id, TaintLabel::new(kind, source, 0.95));
    }
    pub fn has_kind(&self, value_id: &str, kind: TaintKind) -> bool {
        self.taints_of(value_id).iter().any(|t| t.kind == kind)
    }
}

pub fn taint_kind_rank(k: TaintKind) -> u8 {
    match k {
        TaintKind::Trusted => 0,
        TaintKind::Unknown => 1,
        TaintKind::McpServer => 2,
        TaintKind::ExternalApi => 3,
        TaintKind::UntrustedUser => 4,
        TaintKind::UntrustedWeb => 5,
        TaintKind::PersonalData => 6,
        TaintKind::SensitiveData => 7,
        TaintKind::Secret => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn web_result_flows_to_db_write() {
        let mut s = TaintStore::new();
        s.source_from_tool("scrape#1", "web_scrape", "https://example.com");
        s.propagate(&["scrape#1"], "llm-arg#2");
        s.propagate(&["llm-arg#2"], "db-write#3");
        assert!(s.has_kind("db-write#3", TaintKind::UntrustedWeb));
    }
    #[test]
    fn sanitize_removes_web_but_secret_sticky_without_declassify() {
        let mut s = TaintStore::new();
        s.taint_value("v", TaintLabel::new(TaintKind::UntrustedWeb, "web", 0.9));
        s.taint_value("v", TaintLabel::new(TaintKind::Secret, "file", 1.0));
        s.sanitize("v", &[TaintKind::UntrustedWeb]);
        assert!(!s.has_kind("v", TaintKind::UntrustedWeb));
        assert!(s.has_kind("v", TaintKind::Secret));
        s.declassify("v");
        assert!(!s.has_kind("v", TaintKind::Secret));
    }
    #[test]
    fn propagation_unions() {
        let mut s = TaintStore::new();
        s.taint_value("a", TaintLabel::new(TaintKind::UntrustedWeb, "w", 0.9));
        s.taint_value("b", TaintLabel::new(TaintKind::Secret, "s", 1.0));
        s.propagate(&["a", "b"], "c");
        assert!(s.has_kind("c", TaintKind::UntrustedWeb));
        assert!(s.has_kind("c", TaintKind::Secret));
    }
}
