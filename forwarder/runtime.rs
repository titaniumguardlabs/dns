use prometheus::{Encoder, IntCounter, IntGauge, Opts, Registry, TextEncoder};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Default)]
pub struct RuntimeState {
    inner: Arc<RuntimeInner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub ready: bool,
    pub draining: bool,
    pub active_queries: u64,
    pub queries_total: u64,
    pub policy_denies: u64,
    pub recursion_denies: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub audit_write_errors: u64,
    pub reload_successes: u64,
    pub reload_failures: u64,
    pub reload_requires_restart: u64,
    pub drain_timeouts: u64,
    pub cache_required: bool,
    pub cache_healthy: bool,
    pub cache_errors: u64,
    pub audit_healthy: bool,
    pub audit_errors: u64,
}

struct RuntimeInner {
    ready: AtomicBool,
    draining: AtomicBool,
    active_queries: AtomicU64,
    queries_total: AtomicU64,
    policy_denies: AtomicU64,
    recursion_denies: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    audit_write_errors: AtomicU64,
    reload_successes: AtomicU64,
    reload_failures: AtomicU64,
    reload_requires_restart: AtomicU64,
    drain_timeouts: AtomicU64,
    cache_required: AtomicBool,
    cache_healthy: AtomicBool,
    cache_errors: AtomicU64,
    audit_healthy: AtomicBool,
    audit_errors: AtomicU64,
}

pub struct QueryGuard {
    state: RuntimeState,
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        self.state
            .inner
            .active_queries
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl RuntimeState {
    pub fn mark_ready(&self) {
        self.inner.ready.store(true, Ordering::Relaxed);
    }

    pub fn mark_draining(&self) {
        self.inner.draining.store(true, Ordering::Relaxed);
        self.inner.ready.store(false, Ordering::Relaxed);
    }

    pub fn ready(&self) -> bool {
        self.inner.ready.load(Ordering::Relaxed)
            && !self.inner.draining.load(Ordering::Relaxed)
            && (!self.inner.cache_required.load(Ordering::Relaxed)
                || self.inner.cache_healthy.load(Ordering::Relaxed))
            && self.inner.audit_healthy.load(Ordering::Relaxed)
    }

    pub fn is_idle(&self) -> bool {
        self.inner.active_queries.load(Ordering::Relaxed) == 0
    }

    pub fn query_guard(&self) -> QueryGuard {
        self.inner.queries_total.fetch_add(1, Ordering::Relaxed);
        self.inner.active_queries.fetch_add(1, Ordering::Relaxed);
        QueryGuard {
            state: self.clone(),
        }
    }

    pub fn inc_policy_denies(&self) {
        self.inner.policy_denies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recursion_denies(&self) {
        self.inner.recursion_denies.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "recursion")]
    pub fn inc_cache_hits(&self) {
        self.inner.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "recursion")]
    pub fn inc_cache_misses(&self) {
        self.inner.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reload_successes(&self) {
        self.inner.reload_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reload_failures(&self) {
        self.inner.reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_reload_requires_restart(&self) {
        self.inner
            .reload_requires_restart
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_drain_timeouts(&self) {
        self.inner.drain_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_cache_health(&self, required: bool, healthy: bool, errors: u64) {
        self.inner.cache_required.store(required, Ordering::Relaxed);
        self.inner.cache_healthy.store(healthy, Ordering::Relaxed);
        self.inner.cache_errors.store(errors, Ordering::Relaxed);
    }

    pub fn update_audit_health(&self, healthy: bool, errors: u64) {
        self.inner.audit_healthy.store(healthy, Ordering::Relaxed);
        self.inner.audit_errors.store(errors, Ordering::Relaxed);
        self.inner
            .audit_write_errors
            .store(errors, Ordering::Relaxed);
    }

    pub fn metrics(&self) -> String {
        let snapshot = self.snapshot();
        let registry = Registry::new_custom(Some("dns".to_string()), None)
            .expect("valid prometheus registry prefix");

        register_gauge(&registry, "ready", "DNS server has completed startup.", snapshot.ready);
        register_gauge(
            &registry,
            "draining",
            "DNS server is draining before shutdown.",
            snapshot.draining,
        );
        register_u64_gauge(
            &registry,
            "active_queries",
            "DNS queries currently being handled.",
            snapshot.active_queries,
        );
        register_counter(
            &registry,
            "queries_total",
            "DNS queries handled by the server.",
            snapshot.queries_total,
        );
        register_counter(
            &registry,
            "policy_denials_total",
            "DNS queries denied by policy.",
            snapshot.policy_denies,
        );
        register_counter(
            &registry,
            "recursion_denials_total",
            "DNS queries denied because recursion was unavailable or unauthorized.",
            snapshot.recursion_denies,
        );
        register_counter(
            &registry,
            "cache_hits_total",
            "DNS cache hits.",
            snapshot.cache_hits,
        );
        register_counter(
            &registry,
            "cache_misses_total",
            "DNS cache misses.",
            snapshot.cache_misses,
        );
        register_counter(
            &registry,
            "audit_write_errors_total",
            "Audit log write errors.",
            snapshot.audit_write_errors,
        );
        register_counter(
            &registry,
            "reload_successes_total",
            "Successful runtime reloads.",
            snapshot.reload_successes,
        );
        register_counter(
            &registry,
            "reload_failures_total",
            "Failed runtime reloads.",
            snapshot.reload_failures,
        );
        register_counter(
            &registry,
            "reloads_requiring_restart_total",
            "Runtime reloads rejected because a restart is required.",
            snapshot.reload_requires_restart,
        );
        register_counter(
            &registry,
            "drain_timeouts_total",
            "Shutdown drains that exceeded the configured timeout.",
            snapshot.drain_timeouts,
        );
        register_gauge(
            &registry,
            "cache_required",
            "Configured cache backend gates readiness.",
            snapshot.cache_required,
        );
        register_gauge(
            &registry,
            "cache_healthy",
            "Configured cache backend is currently healthy.",
            snapshot.cache_healthy,
        );
        register_counter(
            &registry,
            "cache_errors_total",
            "Cache backend errors.",
            snapshot.cache_errors,
        );
        register_gauge(
            &registry,
            "audit_healthy",
            "Audit logging sink is currently healthy.",
            snapshot.audit_healthy,
        );
        register_counter(
            &registry,
            "audit_errors_total",
            "Audit logging errors.",
            snapshot.audit_errors,
        );

        let encoder = TextEncoder::new();
        let mut encoded = Vec::new();
        encoder
            .encode(&registry.gather(), &mut encoded)
            .expect("prometheus text encoding should succeed");
        String::from_utf8(encoded).expect("prometheus text encoding should be utf8")
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            ready: self.inner.ready.load(Ordering::Relaxed),
            draining: self.inner.draining.load(Ordering::Relaxed),
            active_queries: self.inner.active_queries.load(Ordering::Relaxed),
            queries_total: self.inner.queries_total.load(Ordering::Relaxed),
            policy_denies: self.inner.policy_denies.load(Ordering::Relaxed),
            recursion_denies: self.inner.recursion_denies.load(Ordering::Relaxed),
            cache_hits: self.inner.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.inner.cache_misses.load(Ordering::Relaxed),
            audit_write_errors: self.inner.audit_write_errors.load(Ordering::Relaxed),
            reload_successes: self.inner.reload_successes.load(Ordering::Relaxed),
            reload_failures: self.inner.reload_failures.load(Ordering::Relaxed),
            reload_requires_restart: self.inner.reload_requires_restart.load(Ordering::Relaxed),
            drain_timeouts: self.inner.drain_timeouts.load(Ordering::Relaxed),
            cache_required: self.inner.cache_required.load(Ordering::Relaxed),
            cache_healthy: self.inner.cache_healthy.load(Ordering::Relaxed),
            cache_errors: self.inner.cache_errors.load(Ordering::Relaxed),
            audit_healthy: self.inner.audit_healthy.load(Ordering::Relaxed),
            audit_errors: self.inner.audit_errors.load(Ordering::Relaxed),
        }
    }
}

fn register_gauge(registry: &Registry, name: &str, help: &str, value: bool) {
    let gauge = IntGauge::with_opts(Opts::new(name, help)).expect("valid prometheus gauge");
    gauge.set(i64::from(value));
    registry
        .register(Box::new(gauge))
        .expect("unique prometheus gauge name");
}

fn register_u64_gauge(registry: &Registry, name: &str, help: &str, value: u64) {
    let gauge = IntGauge::with_opts(Opts::new(name, help)).expect("valid prometheus gauge");
    gauge.set(value.try_into().unwrap_or(i64::MAX));
    registry
        .register(Box::new(gauge))
        .expect("unique prometheus gauge name");
}

fn register_counter(registry: &Registry, name: &str, help: &str, value: u64) {
    let counter = IntCounter::with_opts(Opts::new(name, help)).expect("valid prometheus counter");
    counter.inc_by(value);
    registry
        .register(Box::new(counter))
        .expect("unique prometheus counter name");
}

impl Default for RuntimeInner {
    fn default() -> Self {
        Self {
            ready: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            active_queries: AtomicU64::new(0),
            queries_total: AtomicU64::new(0),
            policy_denies: AtomicU64::new(0),
            recursion_denies: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            audit_write_errors: AtomicU64::new(0),
            reload_successes: AtomicU64::new(0),
            reload_failures: AtomicU64::new(0),
            reload_requires_restart: AtomicU64::new(0),
            drain_timeouts: AtomicU64::new(0),
            cache_required: AtomicBool::new(false),
            cache_healthy: AtomicBool::new(true),
            cache_errors: AtomicU64::new(0),
            audit_healthy: AtomicBool::new(true),
            audit_errors: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_metrics_track_current_health_and_cumulative_errors() {
        let state = RuntimeState::default();
        state.mark_ready();

        state.update_audit_health(false, 1);
        assert!(!state.ready());
        let failed_metrics = state.metrics();
        assert!(failed_metrics.contains("dns_audit_write_errors_total 1\n"));
        assert!(failed_metrics.contains("dns_audit_healthy 0\n"));
        assert!(failed_metrics.contains("dns_audit_errors_total 1\n"));

        state.update_audit_health(true, 1);
        assert!(state.ready());
        let recovered_metrics = state.metrics();
        assert!(recovered_metrics.contains("dns_audit_write_errors_total 1\n"));
        assert!(recovered_metrics.contains("dns_audit_healthy 1\n"));
        assert!(recovered_metrics.contains("dns_audit_errors_total 1\n"));
    }

    #[test]
    fn required_cache_health_is_fail_closed_until_success() {
        let state = RuntimeState::default();
        state.mark_ready();

        state.update_cache_health(true, false, 1);
        assert!(!state.ready());
        assert!(state.metrics().contains("dns_cache_healthy 0\n"));

        state.update_cache_health(true, true, 1);
        assert!(state.ready());
        assert!(state.metrics().contains("dns_cache_healthy 1\n"));
    }
}
