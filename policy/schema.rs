use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyDocument {
    pub version: String,
    #[serde(default)]
    pub metadata: PolicyMetadata,
    pub defaults: Defaults,
    pub evaluation: Evaluation,
    pub dimensions: BTreeMap<String, DimensionDef>,
    pub operators: BTreeMap<String, OperatorDef>,
    #[serde(default)]
    pub schemas: Value,
    #[serde(default)]
    pub evaluation_semantics: Value,
    #[serde(default)]
    pub specificity: Value,
    pub rule_sets: Vec<RuleSet>,
    #[serde(default)]
    pub examples: Value,
    #[serde(default)]
    pub explain_trace: Value,
    #[serde(default)]
    pub implementation_notes: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyMetadata {
    pub name: Option<String>,
    pub revision: Option<String>,
    pub author: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Defaults {
    pub action: ActionType,
    pub log_level: String,
    #[serde(default)]
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Evaluation {
    pub mode: EvaluationMode,
    pub first_match_wins: bool,
    #[serde(default)]
    pub tie_breakers: Vec<String>,
    #[serde(default)]
    pub merge_rule_sets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvaluationMode {
    Ordered,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DimensionDef {
    #[serde(rename = "type")]
    pub value_type: DimensionType,
    pub source_stage: SourceStage,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DimensionType {
    String,
    Int,
    Bool,
    StringList,
    Ip,
    CidrList,
    Map,
    StringOrNull,
    IntOrNull,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceStage {
    Connection,
    Tls,
    Request,
    Response,
    Flow,
    Time,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperatorDef {
    pub applicable_types: Vec<DimensionType>,
    pub value_schema: Value,
    pub semantics: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    pub id: String,
    pub scope: RuleSetScope,
    pub enabled: bool,
    #[serde(default)]
    pub selectors: Option<RuleSetSelectors>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleSetScope {
    Global,
    Org,
    Team,
    User,
    Custom,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuleSetSelectors {
    pub org_id: Option<String>,
    pub team: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub priority: i64,
    pub description: String,
    pub when: BoolExpr,
    pub action: RuleAction,
    #[serde(default)]
    pub effects: Option<RuleEffects>,
    pub provenance: RuleProvenance,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleAction {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(default)]
    pub deny: Option<DenyPayload>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DenyPayload {
    pub reason: String,
    pub status_code: u16,
    pub body: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RuleEffects {
    #[serde(default)]
    pub log: Option<String>,
    #[serde(default)]
    pub metrics_tag: Option<String>,
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(default)]
    pub redirect: Option<RedirectEffect>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitEffect>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedirectEffect {
    pub status_code: u16,
    pub location: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitEffect {
    pub key: String,
    pub requests_per_minute: u64,
    #[serde(default)]
    pub burst: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleProvenance {
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoolExpr {
    #[serde(default)]
    pub all: Vec<ExprNode>,
    #[serde(default)]
    pub any: Vec<ExprNode>,
    #[serde(default)]
    pub not: Vec<ExprNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExprNode {
    Predicate(Predicate),
    Nested(BoolExpr),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Predicate {
    pub field: String,
    pub op: String,
    #[serde(default)]
    pub value: Value,
}
