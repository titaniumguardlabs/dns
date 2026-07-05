pub mod compile;
pub mod eval;
pub mod facts;
pub mod schema;
pub mod trace;

use compile::{CompiledPolicy, compile_policy};
use eval::{EvalResult, evaluate_policy};
use schema::PolicyDocument;
use serde::Deserialize;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tracing::warn;

pub type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleEngineConfig {
    #[serde(default = "default_max_trace_facts")]
    pub max_trace_facts: u32,
    #[serde(default = "default_enable_explain_logs")]
    pub enable_explain_logs: bool,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            max_trace_facts: default_max_trace_facts(),
            enable_explain_logs: default_enable_explain_logs(),
        }
    }
}

fn default_max_trace_facts() -> u32 {
    64
}

fn default_enable_explain_logs() -> bool {
    true
}

#[derive(Clone)]
pub struct PolicyRuntime {
    compiled: Arc<std::sync::RwLock<Arc<CompiledPolicy>>>,
    config: Arc<std::sync::RwLock<RuleEngineConfig>>,
}

impl PolicyRuntime {
    pub async fn from_file_or_default(
        policy_file_path: Option<&str>,
        config: RuleEngineConfig,
    ) -> DynResult<Self> {
        let compiled = if let Some(path) = policy_file_path {
            compile_from_path(Path::new(path)).await?
        } else {
            compile_policy(default_policy_document())
                .map_err(|err| other_error(format!("failed to compile default policy: {err}")))?
        };

        Ok(Self {
            compiled: Arc::new(std::sync::RwLock::new(Arc::new(compiled))),
            config: Arc::new(std::sync::RwLock::new(config)),
        })
    }

    pub async fn reload_if_configured(
        &self,
        policy_file_path: Option<&str>,
        config: RuleEngineConfig,
    ) -> DynResult<()> {
        let compiled = if let Some(path) = policy_file_path {
            compile_from_path(Path::new(path)).await?
        } else {
            compile_policy(default_policy_document())
                .map_err(|err| other_error(format!("failed to compile default policy: {err}")))?
        };

        let mut guard = self.compiled.write().expect("lock poisoned");
        *guard = Arc::new(compiled);

        let mut engine_cfg = self.config.write().expect("lock poisoned");
        *engine_cfg = config;
        Ok(())
    }

    pub fn evaluate_repo_dns(&self, request: &crate::dns::DnsRequest) -> EvalResult {
        let facts = crate::policy::facts::from_repo_dns_request(request);
        self.evaluate_facts(facts)
    }

    fn evaluate_facts(&self, facts: crate::policy::facts::RuntimeFacts) -> EvalResult {
        let compiled = self.compiled.read().expect("lock poisoned");
        let config = self.config.read().expect("lock poisoned").clone();

        let mut result = evaluate_policy(&compiled, &facts, config.max_trace_facts as usize);
        result.trace.decision = Some(format!("{:?}", result.decision).to_uppercase());
        result.trace.matched_rule_id = result.matched_rule_id.clone();
        result.trace.matched_rule_set_id = result.matched_rule_set_id.clone();
        result.trace.reason = Some(result.reason.clone());

        if config.enable_explain_logs {
            warn!(
                policy_decision = %result.trace.decision.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
                matched_rule_id = ?result.matched_rule_id,
                matched_rule_set_id = ?result.matched_rule_set_id,
                reason = %result.reason,
                "dns policy evaluation trace"
            );
        }

        result
    }
}

async fn compile_from_path(path: &Path) -> DynResult<CompiledPolicy> {
    let content = fs::read_to_string(path).await.map_err(|err| {
        other_error(format!(
            "failed to read policy file {}: {err}",
            path.display()
        ))
    })?;

    let document: PolicyDocument = serde_json::from_str(&content)
        .map_err(|err| other_error(format!("invalid policy JSON at {}: {err}", path.display())))?;

    compile_policy(document).map_err(|err| {
        other_error(format!(
            "failed to compile policy at {}: {err}",
            path.display()
        ))
    })
}

fn default_policy_document() -> PolicyDocument {
    serde_json::from_value(serde_json::json!({
        "version":"1.0.0",
        "metadata":{"name":"default-policy","revision":"builtin","author":"dns"},
        "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
        "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
        "dimensions":{
            "dns.qname":{"type":"string","source_stage":"REQUEST","description":"DNS query name"},
            "dns.qtype":{"type":"string","source_stage":"REQUEST","description":"DNS query type"},
            "client.ip":{"type":"ip","source_stage":"CONNECTION","description":"Client source IP"}
        },
        "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":"Exact equality"}},
        "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
        "rule_sets":[]
    }))
    .expect("default policy JSON should be valid")
}

fn other_error(msg: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(msg.into()).into()
}

#[cfg(test)]
mod tests {
    use super::{PolicyRuntime, RuleEngineConfig};
    use crate::dns::{
        DnsClass, DnsMessage, DnsName, DnsQuestion, DnsRequest, RecordType, TransportProtocol,
    };
    use crate::policy::schema::ActionType;
    use std::{
        net::IpAddr,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn write_temp_policy(contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dns-policy-runtime-{}-{nanos}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("policy write");
        path
    }

    fn request_from_wire(name: &str, record_type: RecordType) -> DnsRequest {
        let mut message = DnsMessage::query(
            0,
            DnsQuestion {
                name: DnsName::parse_ascii(name).expect("valid name"),
                record_type,
                class: DnsClass::IN,
            },
        );
        message.header.recursion_desired = true;
        DnsRequest {
            client_ip: IpAddr::from([127, 0, 0, 1]),
            protocol: TransportProtocol::Udp,
            message,
        }
    }

    #[tokio::test]
    async fn invalid_policy_path_fails_startup() {
        let result = PolicyRuntime::from_file_or_default(
            Some("/tmp/definitely-missing-dns-policy.json"),
            RuleEngineConfig::default(),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn invalid_reload_keeps_existing_policy_active() {
        let runtime = PolicyRuntime::from_file_or_default(None, RuleEngineConfig::default())
            .await
            .expect("runtime");
        let request = request_from_wire("www.example.com.", RecordType::A);

        let before = runtime.evaluate_repo_dns(&request);
        assert_eq!(before.decision, ActionType::Allow);

        let reload = runtime
            .reload_if_configured(
                Some("/tmp/definitely-missing-dns-policy-reload.json"),
                RuleEngineConfig::default(),
            )
            .await;
        assert!(reload.is_err());

        let after = runtime.evaluate_repo_dns(&request);
        assert_eq!(after.decision, ActionType::Allow);
    }

    #[tokio::test]
    async fn reload_without_policy_path_restores_default_policy() {
        let policy_path = write_temp_policy(
            r#"{
  "version":"1.0.0",
  "defaults":{"action":"DENY","log_level":"info","fail_closed":false},
  "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
  "dimensions":{},
  "operators":{},
  "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
  "rule_sets":[]
}"#,
        );
        let runtime = PolicyRuntime::from_file_or_default(
            Some(policy_path.to_string_lossy().as_ref()),
            RuleEngineConfig::default(),
        )
        .await
        .expect("runtime");
        let request = request_from_wire("www.example.com.", RecordType::A);

        let before = runtime.evaluate_repo_dns(&request);
        assert_eq!(before.decision, ActionType::Deny);

        runtime
            .reload_if_configured(None, RuleEngineConfig::default())
            .await
            .expect("default reload should succeed");
        let _ = std::fs::remove_file(policy_path);

        let after = runtime.evaluate_repo_dns(&request);
        assert_eq!(after.decision, ActionType::Allow);
    }
}
