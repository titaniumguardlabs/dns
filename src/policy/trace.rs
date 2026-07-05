use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExplainTrace {
    pub decision: Option<String>,
    pub matched_rule_id: Option<String>,
    pub matched_rule_set_id: Option<String>,
    pub reason: Option<String>,
    pub status_code: Option<u16>,
    pub evaluated: Vec<EvaluatedRule>,
    pub extracted_facts: Option<Map<String, Value>>,
}

impl ExplainTrace {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluatedRule {
    pub rule_id: String,
    pub matched: bool,
    pub short_circuit_reason: Option<String>,
}
