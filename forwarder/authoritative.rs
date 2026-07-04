use super::zones::{AuthoritativeLookup, AuthoritativeZones};
use super::{DynResult, Forwarder, RuntimeState};
use crate::caching::DnsRecordCache;
use crate::config::{RecursionConfig, ZoneConfig};
use crate::logging::{LoggingPipeline, RawLogEvent, extract_device_hint};
use crate::policy::PolicyRuntime;
use crate::policy::schema::ActionType;
use hickory_recursor::{DnssecPolicy, NameServerConfigGroup, Recursor};
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::op::{Edns, Header, Query, ResponseCode},
    proto::rr::{Record, RecordType},
    server::{Request, ResponseHandler, ResponseInfo},
};
use std::{
    iter,
    net::IpAddr,
    sync::Arc,
    time::{Instant, SystemTime},
};
use tracing::error;

impl Forwarder {
    const MAX_RESPONSE_UDP_PAYLOAD: u16 = 1232;

    fn root_hints(root_servers: &[IpAddr]) -> NameServerConfigGroup {
        NameServerConfigGroup::from_ips_clear(root_servers, 53, true)
    }

    #[cfg(test)]
    pub fn with_cache(
        root_servers: &[IpAddr],
        zone_configs: &[ZoneConfig],
        cache: Arc<dyn DnsRecordCache>,
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
        root_servers: &[IpAddr],
        zone_configs: &[ZoneConfig],
        cache: Arc<dyn DnsRecordCache>,
        logging: Arc<LoggingPipeline>,
        policy: Arc<PolicyRuntime>,
        runtime: RuntimeState,
        recursion_config: &RecursionConfig,
    ) -> DynResult<Self> {
        if root_servers.is_empty() {
            return Err("at least one root server address must be configured".into());
        }

        let recursor = Recursor::builder()
            .dnssec_policy(DnssecPolicy::ValidateWithStaticKey { trust_anchor: None })
            .build(Self::root_hints(root_servers))?;
        let authoritative_zones = AuthoritativeZones::from_configs(zone_configs)?;
        let recursion = super::RecursionAuthorizer::from_config(recursion_config)
            .map_err(|err| format!("invalid recursion config: {err}"))?;
        Ok(Self {
            recursor: Arc::new(recursor),
            authoritative_zones: Arc::new(authoritative_zones),
            cache,
            logging,
            policy,
            runtime,
            recursion,
        })
    }

    fn serve_failed_info() -> ResponseInfo {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }

    fn response_has_authentic_data(records: &[Record]) -> bool {
        let mut has_secure_records = false;

        for record in records {
            let proof = record.proof();
            if proof.is_bogus() || proof.is_indeterminate() {
                return false;
            }

            if proof.is_secure() {
                has_secure_records = true;
            }
        }

        has_secure_records
    }

    fn builder_from_request(request: &'_ Request) -> MessageResponseBuilder<'_> {
        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = request.edns() {
            builder.edns(Self::response_edns_from_request(edns));
        }

        builder
    }

    pub(super) fn response_edns_from_request(request_edns: &Edns) -> Edns {
        let mut response_edns = Edns::new();
        response_edns
            .set_version(0)
            .set_dnssec_ok(request_edns.flags().dnssec_ok)
            .set_max_payload(
                request_edns
                    .max_payload()
                    .min(Self::MAX_RESPONSE_UDP_PAYLOAD),
            );
        *response_edns.options_mut() = request_edns.options().clone();
        response_edns
    }

    pub(super) fn cache_key(request: &Request, query_has_dnssec_ok: bool) -> DynResult<String> {
        let info = request.request_info()?;
        let query = info.query.original();
        Ok(format!(
            "{}|type={:?}|class={:?}|dnssec_ok={query_has_dnssec_ok}",
            query.name().to_lowercase().to_ascii(),
            query.query_type(),
            query.query_class()
        ))
    }

    pub(super) fn minimized_zone_chain(
        query_name: &hickory_server::proto::rr::Name,
    ) -> Vec<hickory_server::proto::rr::Name> {
        let total_labels = query_name.num_labels() as usize;
        if total_labels <= 1 {
            return Vec::new();
        }

        (1..total_labels).map(|n| query_name.trim_to(n)).collect()
    }

    async fn prime_qname_minimization(&self, query: &Query, query_has_dnssec_ok: bool) {
        for zone_name in Self::minimized_zone_chain(query.name()) {
            let ns_query = Query::query(zone_name.clone(), RecordType::NS);
            if let Err(err) = self
                .recursor
                .resolve(ns_query, Instant::now(), query_has_dnssec_ok)
                .await
            {
                if err.is_nx_domain() {
                    break;
                }
            }
        }
    }

    async fn send_records_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        records: &[Record],
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);
        header.set_authentic_data(Self::response_has_authentic_data(records));
        header.set_response_code(ResponseCode::NoError);

        let builder = Self::builder_from_request(request);
        let response = builder.build(
            header,
            records.iter(),
            iter::empty::<&Record>(),
            iter::empty::<&Record>(),
            iter::empty::<&Record>(),
        );

        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|err| {
                error!("failed to send response: {err}");
                Self::serve_failed_info()
            })
    }

    async fn send_authoritative_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        lookup: AuthoritativeLookup,
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        header.set_recursion_available(false);
        header.set_authentic_data(false);
        header.set_response_code(lookup.response_code);

        let builder = Self::builder_from_request(request);
        let response = builder.build(
            header,
            lookup.answers.iter(),
            lookup.authorities.iter(),
            iter::empty::<&Record>(),
            iter::empty::<&Record>(),
        );

        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|err| {
                error!("failed to send authoritative response: {err}");
                Self::serve_failed_info()
            })
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

    pub(super) async fn forward_query<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let _query_guard = self.runtime.query_guard();
        let started_at = SystemTime::now();
        let started = Instant::now();
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(err) => {
                let response = self
                    .send_error_response(request, response_handle, ResponseCode::FormErr)
                    .await;
                let _ = err;
                return response;
            }
        };

        let query = request_info.query.original().clone();
        let qname = query.name().to_ascii();
        let qtype = query.query_type();
        let client_ip = request.src().ip();
        let device_hint = extract_device_hint(request.edns());
        let query_has_dnssec_ok = request
            .edns()
            .map(|edns| edns.flags().dnssec_ok)
            .unwrap_or(false);

        let policy_result = self.policy.evaluate_dns(request);
        if policy_result.decision == ActionType::Deny {
            self.runtime.inc_policy_denies();
            let response = self
                .send_error_response(request, response_handle, ResponseCode::Refused)
                .await;
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: format!("{:?}", response.response_code()),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        let cache_key = match Self::cache_key(request, query_has_dnssec_ok) {
            Ok(key) => key,
            Err(err) => {
                let response = self
                    .send_error_response(request, response_handle, ResponseCode::FormErr)
                    .await;
                let _ = err;
                return response;
            }
        };

        if let Some(lookup) = self.authoritative_zones.resolve(&query) {
            let response = self
                .send_authoritative_response(request, response_handle, lookup)
                .await;
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: format!("{:?}", response.response_code()),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        if !self.recursion.allows(client_ip) {
            self.runtime.inc_recursion_denies();
            let response = self
                .send_error_response(request, response_handle, ResponseCode::Refused)
                .await;
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: format!("{:?}", response.response_code()),
                device_hint,
            });
            self.update_audit_health();
            return response;
        }

        if let Some(records) = self.cache.get(&cache_key).await {
            self.runtime.update_cache_health(
                self.cache.is_required(),
                self.cache.is_healthy(),
                self.cache.error_count(),
            );
            self.runtime.inc_cache_hits();
            let response = self
                .send_records_response(request, response_handle, records.as_slice())
                .await;
            self.logging.log_request(RawLogEvent {
                started_at,
                latency_ms: started.elapsed().as_millis(),
                client_ip,
                qname,
                qtype,
                response_code: format!("{:?}", response.response_code()),
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

        self.prime_qname_minimization(&query, query_has_dnssec_ok)
            .await;

        let lookup = match self
            .recursor
            .resolve(query, Instant::now(), query_has_dnssec_ok)
            .await
        {
            Ok(lookup) => lookup,
            Err(err) => {
                let response_code = if err.is_nx_domain() {
                    ResponseCode::NXDomain
                } else if err.is_no_records_found() {
                    ResponseCode::NoError
                } else {
                    ResponseCode::ServFail
                };
                let authorities = err
                    .clone()
                    .authorities()
                    .map(|records| records.iter().cloned().collect::<Vec<Record>>())
                    .unwrap_or_default();
                let response = self
                    .send_error_response_with_records(
                        request,
                        response_handle,
                        response_code,
                        authorities.as_slice(),
                    )
                    .await;
                self.logging.log_request(RawLogEvent {
                    started_at,
                    latency_ms: started.elapsed().as_millis(),
                    client_ip,
                    qname,
                    qtype,
                    response_code: format!("{:?}", response.response_code()),
                    device_hint,
                });
                self.update_audit_health();
                return response;
            }
        };

        let records: Vec<Record> = lookup.records().iter().cloned().collect();
        self.cache.insert(cache_key, records.clone()).await;
        self.runtime.update_cache_health(
            self.cache.is_required(),
            self.cache.is_healthy(),
            self.cache.error_count(),
        );

        let response = self
            .send_records_response(request, response_handle, &records)
            .await;
        self.logging.log_request(RawLogEvent {
            started_at,
            latency_ms: started.elapsed().as_millis(),
            client_ip,
            qname,
            qtype,
            response_code: format!("{:?}", response.response_code()),
            device_hint,
        });
        self.update_audit_health();
        response
    }

    async fn send_error_response_with_records<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        response_code: ResponseCode,
        authorities: &[Record],
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);
        header.set_recursion_available(true);
        header.set_response_code(response_code);

        let builder = Self::builder_from_request(request);
        let response = builder.build(
            header,
            iter::empty::<&Record>(),
            authorities.iter(),
            iter::empty::<&Record>(),
            iter::empty::<&Record>(),
        );

        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|err| {
                error!("failed to send error response: {err}");
                Self::serve_failed_info()
            })
    }

    pub(super) async fn send_error_response<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        response_code: ResponseCode,
    ) -> ResponseInfo {
        self.send_error_response_with_records(request, response_handle, response_code, &[])
            .await
    }
}
