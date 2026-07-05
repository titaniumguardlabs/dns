use crate::config::{AppConfig, McpConfig};
use crate::dns::{
    DnsClass, DnsMessage, DnsName, DnsQuestion, DnsRecord, DnsRequest, RData, RecordType,
    TransportProtocol,
};
use crate::forwarder::{Forwarder, RuntimeState};
use axum::Router;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ErrorData, Json, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub(crate) struct McpRuntime {
    forwarder: Forwarder,
    runtime: RuntimeState,
    config: Arc<RwLock<AppConfig>>,
    resolve_client_ip: IpAddr,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ResolveRequest {
    #[schemars(
        description = "Host name to resolve. Relative names are normalized to absolute DNS names."
    )]
    hostname: String,
    #[serde(default = "default_record_type")]
    #[schemars(description = "DNS record type: A, AAAA, TXT, SRV, NS, or SOA.")]
    record_type: String,
    #[serde(default)]
    #[schemars(description = "Set EDNS DNSSEC OK on the synthetic DNS query.")]
    dnssec_ok: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct StatusResult {
    ready: bool,
    effective_ready: bool,
    draining: bool,
    active_queries: u64,
    queries_total: u64,
    policy_denies: u64,
    recursion_denies: u64,
    cache_required: bool,
    cache_healthy: bool,
    cache_errors: u64,
    audit_healthy: bool,
    audit_errors: u64,
    reload_successes: u64,
    reload_failures: u64,
    reload_requires_restart: u64,
    drain_timeouts: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct MetricsResult {
    metrics: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ConfigSummaryResult {
    listen_addr: String,
    policy_file_configured: bool,
    resolver_count: usize,
    zone_count: usize,
    recursion_enabled: bool,
    recursion_allowed_client_cidrs: Vec<String>,
    cache_type: String,
    logging_enabled: bool,
    health_listen_addr: String,
    mcp_enabled: bool,
    mcp_listen_addr: String,
    mcp_endpoint: String,
    secure_transports: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ZonesResult {
    zones: Vec<ZoneSummary>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ZoneSummary {
    name: String,
    owners: Vec<ZoneOwnerSummary>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ZoneOwnerSummary {
    owner: String,
    record_types: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ResolveResult {
    hostname: String,
    record_type: String,
    response_code: String,
    authoritative: bool,
    recursion_available: bool,
    answers: Vec<RecordSummary>,
    authorities: Vec<RecordSummary>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct RecordSummary {
    name: String,
    record_type: String,
    ttl: u32,
    value: String,
}

impl McpRuntime {
    pub(crate) fn new(
        forwarder: Forwarder,
        runtime: RuntimeState,
        config: Arc<RwLock<AppConfig>>,
        resolve_client_ip: IpAddr,
    ) -> Self {
        Self {
            forwarder,
            runtime,
            config,
            resolve_client_ip,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl McpRuntime {
    #[tool(description = "Return DNS server readiness, health, and operational counters.")]
    fn status(&self) -> Json<StatusResult> {
        let snapshot = self.runtime.snapshot();
        Json(StatusResult {
            ready: snapshot.ready,
            effective_ready: self.runtime.ready(),
            draining: snapshot.draining,
            active_queries: snapshot.active_queries,
            queries_total: snapshot.queries_total,
            policy_denies: snapshot.policy_denies,
            recursion_denies: snapshot.recursion_denies,
            cache_required: snapshot.cache_required,
            cache_healthy: snapshot.cache_healthy,
            cache_errors: snapshot.cache_errors,
            audit_healthy: snapshot.audit_healthy,
            audit_errors: snapshot.audit_errors,
            reload_successes: snapshot.reload_successes,
            reload_failures: snapshot.reload_failures,
            reload_requires_restart: snapshot.reload_requires_restart,
            drain_timeouts: snapshot.drain_timeouts,
        })
    }

    #[tool(description = "Return the same text metrics exposed by GET /metrics.")]
    fn metrics(&self) -> Json<MetricsResult> {
        Json(MetricsResult {
            metrics: self.runtime.metrics(),
        })
    }

    #[tool(description = "Return a non-secret summary of the active DNS configuration.")]
    async fn config_summary(&self) -> Json<ConfigSummaryResult> {
        let config = self.config.read().await;
        Json(ConfigSummaryResult {
            listen_addr: config.listen_addr.to_string(),
            policy_file_configured: config.policy_file_path.is_some(),
            resolver_count: config.resolvers.len(),
            zone_count: config.zones.len(),
            recursion_enabled: config.recursion.enabled,
            recursion_allowed_client_cidrs: config.recursion.allowed_client_cidrs.clone(),
            cache_type: cache_type(&config),
            logging_enabled: config.logging.enabled,
            health_listen_addr: config.health.listen_addr.to_string(),
            mcp_enabled: config.mcp.enabled,
            mcp_listen_addr: config.mcp.listen_addr.to_string(),
            mcp_endpoint: config.mcp.endpoint.clone(),
            secure_transports: secure_transports(&config),
        })
    }

    #[tool(description = "List configured authoritative zones, owners, and record types.")]
    async fn zones(&self) -> Json<ZonesResult> {
        let config = self.config.read().await;
        Json(ZonesResult {
            zones: config
                .zones
                .iter()
                .map(|zone| ZoneSummary {
                    name: zone.name.clone(),
                    owners: zone
                        .records
                        .iter()
                        .map(|(owner, rrsets)| ZoneOwnerSummary {
                            owner: owner.clone(),
                            record_types: rrsets.keys().cloned().collect(),
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    #[tool(
        description = "Resolve a host name through the live DNS server policy, authoritative, cache, and recursion path."
    )]
    async fn resolve(
        &self,
        Parameters(request): Parameters<ResolveRequest>,
    ) -> Result<Json<ResolveResult>, ErrorData> {
        let record_type = parse_record_type(&request.record_type)?;
        let name = normalize_name(&request.hostname)?;
        let dns_request = synthetic_request(
            &name,
            record_type,
            request.dnssec_ok,
            self.resolve_client_ip,
        )?;
        let message = self.forwarder.handle_dns_request(dns_request).await;

        Ok(Json(ResolveResult {
            hostname: name.to_ascii(),
            record_type: record_type.to_string(),
            response_code: message.header.response_code.to_string(),
            authoritative: message.header.authoritative,
            recursion_available: message.header.recursion_available,
            answers: summarize_records(&message.answers),
            authorities: summarize_records(&message.authorities),
        }))
    }
}

#[tool_handler]
impl ServerHandler for McpRuntime {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info({
                let mut implementation =
                    Implementation::new("titaniumguard-dns", env!("CARGO_PKG_VERSION"));
                implementation.title = Some("TitaniumGuard DNS MCP".into());
                implementation.description =
                    Some("Read-only MCP interface for TitaniumGuard DNS".into());
                implementation
            })
            .with_instructions("Read-only DNS operations and host resolution through the live TitaniumGuard DNS policy path.")
    }
}

pub(crate) async fn serve(
    listener: TcpListener,
    forwarder: Forwarder,
    runtime: RuntimeState,
    config: Arc<RwLock<AppConfig>>,
    mcp_config: McpConfig,
    cancellation_token: CancellationToken,
) -> DynResult<()> {
    let addr = listener.local_addr()?;
    let endpoint = mcp_config.endpoint.clone();
    let service_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(mcp_config.allowed_hosts)
        .with_allowed_origins(mcp_config.allowed_origins)
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_cancellation_token(cancellation_token.child_token());
    let resolve_client_ip = mcp_config.resolve_client_ip;
    let service: StreamableHttpService<McpRuntime, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(McpRuntime::new(
                    forwarder.clone(),
                    runtime.clone(),
                    config.clone(),
                    resolve_client_ip,
                ))
            },
            Default::default(),
            service_config,
        );
    let router = Router::new().nest_service(&endpoint, service);
    info!("listening for mcp on http://{}{}", addr, endpoint);
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation_token.cancelled_owned().await })
        .await?;
    Ok(())
}

fn default_record_type() -> String {
    "A".to_string()
}

fn parse_record_type(input: &str) -> Result<RecordType, ErrorData> {
    match input.to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "TXT" => Ok(RecordType::TXT),
        "SRV" => Ok(RecordType::SRV),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        other => Err(ErrorData::invalid_params(
            format!("unsupported record_type: {other}"),
            None,
        )),
    }
}

fn normalize_name(input: &str) -> Result<DnsName, ErrorData> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ErrorData::invalid_params(
            "hostname must be non-empty",
            None,
        ));
    }
    let absolute = if trimmed.ends_with('.') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    };
    DnsName::parse_ascii(&absolute).map_err(|err| {
        ErrorData::invalid_params(
            "hostname must be a valid DNS name",
            Some(serde_json::json!({ "error": err.to_string() })),
        )
    })
}

fn synthetic_request(
    name: &DnsName,
    record_type: RecordType,
    dnssec_ok: bool,
    client_ip: IpAddr,
) -> Result<DnsRequest, ErrorData> {
    let mut message = DnsMessage::query(
        0,
        DnsQuestion {
            name: name.clone(),
            record_type,
            class: DnsClass::IN,
        },
    );
    message.header.recursion_desired = true;
    if dnssec_ok {
        message.additionals.push(DnsRecord {
            name: DnsName::root(),
            ttl: 0x0000_8000,
            class: DnsClass::Unknown(1232),
            data: RData::OPT(Vec::new()),
        });
    }

    Ok(DnsRequest {
        client_ip,
        protocol: TransportProtocol::Udp,
        message,
    })
}

fn summarize_records(records: &[DnsRecord]) -> Vec<RecordSummary> {
    records
        .iter()
        .map(|record| RecordSummary {
            name: record.name.to_ascii(),
            record_type: record.record_type().to_string(),
            ttl: record.ttl,
            value: summarize_rdata(&record.data),
        })
        .collect()
}

fn summarize_rdata(data: &RData) -> String {
    match data {
        RData::A(addr) => addr.to_string(),
        RData::AAAA(addr) => addr.to_string(),
        RData::NS(name) | RData::CNAME(name) | RData::PTR(name) => name.to_ascii(),
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
        RData::MX {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        RData::TXT(chunks) => chunks
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(""),
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RData::OPT(bytes) => format!("{} bytes", bytes.len()),
        RData::Unknown { bytes, .. } => format!("{} bytes", bytes.len()),
    }
}

fn cache_type(config: &AppConfig) -> String {
    match &config.caching {
        crate::caching::CachingConfig::Memory { .. } => "memory".to_string(),
        crate::caching::CachingConfig::Redis { .. } => "redis".to_string(),
    }
}

fn secure_transports(config: &AppConfig) -> Vec<String> {
    let mut transports = Vec::new();
    if config.transports.dot.is_some() {
        transports.push("dot".to_string());
    }
    if config.transports.doh.is_some() {
        transports.push("doh".to_string());
    }
    if config.transports.doq.is_some() {
        transports.push("doq".to_string());
    }
    if config.transports.doh3.is_some() {
        transports.push("doh3".to_string());
    }
    transports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caching::MokaDnsRecordCache;
    use crate::config::{RecursionConfig, ZoneConfig, ZoneSoaConfig};
    use crate::logging::{LoggingConfig, LoggingPipeline};
    use crate::policy::{PolicyRuntime, RuleEngineConfig};
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_policy_runtime() -> Arc<PolicyRuntime> {
        Arc::new(
            PolicyRuntime::from_file_or_default(None, RuleEngineConfig::default())
                .await
                .expect("policy runtime"),
        )
    }

    fn write_temp_policy(contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dns-mcp-policy-{}-{nanos}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("policy write");
        path
    }

    async fn test_mcp_runtime(
        zones: Vec<ZoneConfig>,
        policy_runtime: Arc<PolicyRuntime>,
        recursion: RecursionConfig,
    ) -> McpRuntime {
        let logging = Arc::new(LoggingPipeline::from_config(&LoggingConfig::default()));
        let runtime = RuntimeState::default();
        runtime.update_audit_health(true, 0);
        let forwarder = Forwarder::with_cache_and_recursion(
            &[IpAddr::from([198, 41, 0, 4])],
            &zones,
            Arc::new(MokaDnsRecordCache::new(100_000)),
            logging,
            policy_runtime,
            runtime.clone(),
            &recursion,
        )
        .expect("forwarder");
        let mut config = AppConfig::default();
        config.zones = zones;
        config.recursion = recursion;
        McpRuntime::new(
            forwarder,
            runtime,
            Arc::new(RwLock::new(config)),
            IpAddr::V4([127, 0, 0, 1].into()),
        )
    }

    fn test_zone() -> ZoneConfig {
        let mut records = BTreeMap::new();
        records.insert(
            "api".to_string(),
            BTreeMap::from([(
                "A".to_string(),
                crate::config::ZoneRecordSetConfig {
                    ttl: 300,
                    values: vec!["10.10.1.10".to_string()],
                },
            )]),
        );
        ZoneConfig {
            name: "corp.internal.".to_string(),
            soa: ZoneSoaConfig {
                mname: "ns1.corp.internal.".to_string(),
                rname: "dns-admin.corp.internal.".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 1209600,
                minimum: 300,
                ttl: 3600,
            },
            records,
        }
    }

    #[test]
    fn normalize_name_makes_relative_names_absolute() {
        let name = normalize_name("www.example.com").expect("valid name");
        assert_eq!(name.to_ascii(), "www.example.com.");
    }

    #[test]
    fn normalize_name_rejects_empty_names() {
        let err = normalize_name(" ").expect_err("empty name should fail");
        assert!(err.message.contains("hostname"));
    }

    #[test]
    fn parse_record_type_rejects_unsupported_types() {
        let err = parse_record_type("MX").expect_err("MX should fail");
        assert!(err.message.contains("unsupported"));
    }

    #[test]
    fn synthetic_request_sets_client_ip_and_dnssec_ok() {
        let name = normalize_name("www.example.com").expect("valid name");
        let request = synthetic_request(
            &name,
            RecordType::A,
            true,
            IpAddr::V4([127, 0, 0, 1].into()),
        )
        .expect("request");
        assert_eq!(request.client_ip, IpAddr::V4([127, 0, 0, 1].into()));
        assert!(request.dnssec_ok());
    }

    #[tokio::test]
    async fn resolve_returns_authoritative_zone_records() {
        let service = test_mcp_runtime(
            vec![test_zone()],
            test_policy_runtime().await,
            RecursionConfig::default(),
        )
        .await;

        let Json(result) = service
            .resolve(Parameters(ResolveRequest {
                hostname: "api.corp.internal".to_string(),
                record_type: "A".to_string(),
                dnssec_ok: false,
            }))
            .await
            .expect("resolve");

        assert_eq!(result.response_code, "NOERROR");
        assert!(result.authoritative);
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.answers[0].value, "10.10.1.10");
    }

    #[tokio::test]
    async fn resolve_policy_deny_returns_refused_and_updates_metrics() {
        let policy_path = write_temp_policy(
            r#"{
  "version":"1.0.0",
  "defaults":{"action":"ALLOW","log_level":"info","fail_closed":false},
  "evaluation":{"mode":"ORDERED","first_match_wins":true,"tie_breakers":[],"merge_rule_sets":[]},
  "dimensions":{"dns.qname":{"type":"string","source_stage":"REQUEST","description":""}},
  "operators":{"EQ":{"applicable_types":["string"],"value_schema":{"type":"string"},"semantics":""}},
  "schemas":{},"evaluation_semantics":{},"specificity":{},"examples":{},"explain_trace":{},"implementation_notes":{},
  "rule_sets":[{"id":"global","scope":"GLOBAL","enabled":true,"rules":[{"id":"deny_bad","enabled":true,"priority":100,"description":"","when":{"all":[{"field":"dns.qname","op":"EQ","value":"blocked.example."}]},"action":{"type":"DENY","deny":{"reason":"blocked","status_code":403,"body":"blocked"}},"provenance":{"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","created_by":"test"}}]}]
}"#,
        );
        let policy_runtime = Arc::new(
            PolicyRuntime::from_file_or_default(
                Some(policy_path.to_string_lossy().as_ref()),
                RuleEngineConfig::default(),
            )
            .await
            .expect("policy runtime"),
        );
        let service =
            test_mcp_runtime(Vec::new(), policy_runtime, RecursionConfig::default()).await;

        let Json(result) = service
            .resolve(Parameters(ResolveRequest {
                hostname: "blocked.example.".to_string(),
                record_type: "A".to_string(),
                dnssec_ok: false,
            }))
            .await
            .expect("resolve");
        let _ = std::fs::remove_file(policy_path);

        assert_eq!(result.response_code, "REFUSED");
        assert_eq!(service.runtime.snapshot().queries_total, 1);
        assert_eq!(service.runtime.snapshot().policy_denies, 1);
    }

    #[tokio::test]
    async fn resolve_obeys_recursion_authorization() {
        let service = test_mcp_runtime(
            Vec::new(),
            test_policy_runtime().await,
            RecursionConfig::default(),
        )
        .await;

        let Json(result) = service
            .resolve(Parameters(ResolveRequest {
                hostname: "www.example.com.".to_string(),
                record_type: "A".to_string(),
                dnssec_ok: false,
            }))
            .await
            .expect("resolve");

        assert_eq!(result.response_code, "REFUSED");
        assert_eq!(service.runtime.snapshot().recursion_denies, 1);
    }

    #[tokio::test]
    async fn streamable_http_lists_and_calls_resolve_tool() {
        let service = test_mcp_runtime(
            vec![test_zone()],
            test_policy_runtime().await,
            RecursionConfig::default(),
        )
        .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut mcp_config = McpConfig::default();
        mcp_config.listen_addr = addr;
        let cancellation = CancellationToken::new();
        let server_cancellation = cancellation.child_token();
        tokio::spawn(serve(
            listener,
            service.forwarder.clone(),
            service.runtime.clone(),
            service.config.clone(),
            mcp_config,
            server_cancellation,
        ));

        let initialize = post_json(
            addr,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#,
        )
        .await;
        assert_eq!(initialize["id"], 1);
        assert!(initialize["result"]["capabilities"]["tools"].is_object());

        let tools = post_json(
            addr,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        )
        .await;
        let listed = tools["result"]["tools"].as_array().expect("tools");
        assert!(
            listed.iter().any(|tool| tool["name"] == "resolve"),
            "unexpected tools: {listed:?}"
        );

        let resolved = post_json(
            addr,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resolve","arguments":{"hostname":"api.corp.internal","record_type":"A"}}}"#,
        )
        .await;
        assert_eq!(
            resolved["result"]["structuredContent"]["response_code"],
            "NOERROR"
        );
        assert_eq!(
            resolved["result"]["structuredContent"]["answers"][0]["value"],
            "10.10.1.10"
        );

        cancellation.cancel();
    }

    async fn post_json(addr: SocketAddr, body: &str) -> serde_json::Value {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        let response = String::from_utf8(response).expect("utf8");
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "unexpected response: {response}"
        );
        let (_, body) = response.split_once("\r\n\r\n").expect("body");
        serde_json::from_str(body).expect("json body")
    }
}
