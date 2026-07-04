use super::zones::AuthoritativeZones;
use super::{DynResult, Forwarder, RuntimeState};
use crate::caching::DnsRecordCache;
use crate::config::{RecursionConfig, ZoneConfig};
#[cfg(feature = "recursion")]
use crate::dns::DnsRecord as WireDnsRecord;
use crate::dns::{DnsMessage, DnsRequest, ResponseCode as WireResponseCode};
use crate::logging::{LoggingPipeline, RawLogEvent};
use crate::policy::PolicyRuntime;
use crate::policy::schema::ActionType;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Instant, SystemTime},
};
#[cfg(feature = "recursion")]
use tracing::error;

impl Forwarder {
    pub(crate) const MAX_RESPONSE_UDP_PAYLOAD: u16 = 1232;

    #[cfg(test)]
    pub fn with_cache(
        root_servers: &[IpAddr],
        zone_configs: &[ZoneConfig],
        #[cfg_attr(not(feature = "recursion"), allow(unused_variables))] cache: Arc<
            dyn DnsRecordCache,
        >,
        logging: Arc<LoggingPipeline>,
        policy: Arc<PolicyRuntime>,
        runtime: RuntimeState,
    ) -> DynResult<Self> {
        Self::with_cache_and_recursion(
            root_servers,
            zone_configs,
            cache,
            logging,
            policy,
            runtime,
            &RecursionConfig::default(),
        )
    }

    pub fn with_cache_and_recursion(
        #[cfg_attr(not(feature = "recursion"), allow(unused_variables))] root_servers: &[IpAddr],
        zone_configs: &[ZoneConfig],
        cache: Arc<dyn DnsRecordCache>,
        logging: Arc<LoggingPipeline>,
        policy: Arc<PolicyRuntime>,
        runtime: RuntimeState,
        #[cfg_attr(not(feature = "recursion"), allow(unused_variables))]
        recursion_config: &RecursionConfig,
    ) -> DynResult<Self> {
        #[cfg(not(feature = "recursion"))]
        let _ = &cache;

        #[cfg(feature = "recursion")]
        let recursive_resolver = super::RecursiveResolver::new(root_servers)?;
        let authoritative_zones = AuthoritativeZones::from_configs(zone_configs)?;
        #[cfg(feature = "recursion")]
        let recursion = super::RecursionAuthorizer::from_config(recursion_config)
            .map_err(|err| format!("invalid recursion config: {err}"))?;
        Ok(Self {
            #[cfg(feature = "recursion")]
            recursive_resolver,
            authoritative_zones: Arc::new(authoritative_zones),
            #[cfg(feature = "recursion")]
            cache,
            logging,
            policy,
            runtime,
            #[cfg(feature = "recursion")]
            recursion,
        })
    }

    #[cfg(feature = "recursion")]
    pub(super) fn cache_key(request: &DnsRequest) -> DynResult<String> {
        let question = request
            .message
            .first_question()
            .ok_or("dns request has no question")?;
        Ok(format!(
            "{}|type={}|class={}|dnssec_ok={}",
            question.name.to_ascii(),
            question.record_type,
            question.class.code(),
            request.dnssec_ok()
        ))
    }

    #[cfg(feature = "recursion")]
    fn cached_response_for_request(request: &DnsRequest, records: &[WireDnsRecord]) -> DnsMessage {
        let mut response =
            DnsMessage::response_for_request(&request.message, WireResponseCode::NoError);
        response.header.recursion_available = true;
        response.answers = records.to_vec();
        response
    }

    fn update_audit_health(&self) {
        let errors = self.logging.write_error_count();
        self.runtime
            .update_audit_health(self.logging.is_healthy(), errors);
    }

    pub fn check_audit_health(&self) -> std::io::Result<bool> {
        self.logging.check_health()
    }

    pub fn audit_write_error_count(&self) -> u64 {
        self.logging.write_error_count()
    }

    pub(crate) async fn handle_dns_request(&self, request: DnsRequest) -> DnsMessage {
        let _query_guard = self.runtime.query_guard();
        let started_at = SystemTime::now();
        let started = Instant::now();
        let question = match request.message.first_question() {
            Some(question) => question.clone(),
            None => {
                return DnsMessage::response_for_request(
                    &request.message,
                    WireResponseCode::FormErr,
                );
            }
        };
        let qname = question.name.to_ascii();
        let qtype = question.record_type;
        let client_ip = request.client_ip;
        let device_hint = None;

        let policy_result = self.policy.evaluate_repo_dns(&request);
        if policy_result.decision == ActionType::Deny {
            self.runtime.inc_policy_denies();
            let response =
                DnsMessage::response_for_request(&request.message, WireResponseCode::Refused);
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: response.header.response_code.to_string(),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        if let Some(lookup) = self.authoritative_zones.resolve_question(&question) {
            let mut response =
                DnsMessage::response_for_request(&request.message, lookup.response_code);
            response.header.authoritative = true;
            response.answers = lookup.answers;
            response.authorities = lookup.authorities;
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: response.header.response_code.to_string(),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        #[cfg(feature = "recursion")]
        if self.recursion.allows(client_ip) {
            let cache_key = match Self::cache_key(&request) {
                Ok(key) => key,
                Err(err) => {
                    error!("failed to build dns cache key: {err}");
                    let mut response = DnsMessage::response_for_request(
                        &request.message,
                        WireResponseCode::FormErr,
                    );
                    response.header.recursion_available = true;
                    self.logging.log_request(RawLogEvent {
                        started_at,
                        latency_ms: started.elapsed().as_millis(),
                        client_ip,
                        qname,
                        qtype,
                        response_code: response.header.response_code.to_string(),
                        device_hint,
                    });
                    self.update_audit_health();
                    return response;
                }
            };

            if let Some(records) = self.cache.get(&cache_key).await {
                self.runtime.inc_cache_hits();
                self.runtime.update_cache_health(
                    self.cache.is_required(),
                    self.cache.is_healthy(),
                    self.cache.error_count(),
                );
                let response = Self::cached_response_for_request(&request, records.as_slice());
                self.logging.log_request(RawLogEvent {
                    started_at,
                    latency_ms: started.elapsed().as_millis(),
                    client_ip,
                    qname,
                    qtype,
                    response_code: response.header.response_code.to_string(),
                    device_hint,
                });
                self.update_audit_health();
                return response;
            }

            self.runtime.inc_cache_misses();
            self.runtime.update_cache_health(
                self.cache.is_required(),
                self.cache.is_healthy(),
                self.cache.error_count(),
            );

            let mut response = match self.recursive_resolver.resolve(&request).await {
                Ok(response) => response,
                Err(err) => {
                    error!("recursive dns lookup failed: {err}");
                    DnsMessage::response_for_request(&request.message, WireResponseCode::ServFail)
                }
            };
            response.header.recursion_available = true;
            if response.header.response_code == WireResponseCode::NoError
                && !response.answers.is_empty()
            {
                self.cache.insert(cache_key, response.answers.clone()).await;
                self.runtime.update_cache_health(
                    self.cache.is_required(),
                    self.cache.is_healthy(),
                    self.cache.error_count(),
                );
            }
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: response.header.response_code.to_string(),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        self.runtime.inc_recursion_denies();
        let response =
            DnsMessage::response_for_request(&request.message, WireResponseCode::Refused);
        self.logging.log_request(RawLogEvent {
            started_at,
            latency_ms: started.elapsed().as_millis(),
            client_ip,
            qname,
            qtype,
            response_code: response.header.response_code.to_string(),
            device_hint,
        });
        self.update_audit_health();
        response
    }
}
