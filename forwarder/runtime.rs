use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Default)]
pub struct RuntimeState {
    inner: Arc<RuntimeInner>,
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
        format!(
            concat!(
                "dns_ready {}\n",
                "dns_draining {}\n",
                "dns_active_queries {}\n",
                "dns_queries_total {}\n",
                "dns_policy_denied_total {}\n",
                "dns_recursion_denied_total {}\n",
                "dns_cache_hits_total {}\n",
                "dns_cache_misses_total {}\n",
                "dns_audit_write_errors_total {}\n",
                "dns_reload_success_total {}\n",
                "dns_reload_failure_total {}\n",
                "dns_reload_requires_restart_total {}\n",
                "dns_drain_timeout_total {}\n",
                "dns_cache_required {}\n",
                "dns_cache_healthy {}\n",
                "dns_cache_errors_total {}\n",
                "dns_audit_healthy {}\n",
                "dns_audit_errors_total {}\n"
            ),
            u8::from(self.inner.ready.load(Ordering::Relaxed)),
            u8::from(self.inner.draining.load(Ordering::Relaxed)),
            self.inner.active_queries.load(Ordering::Relaxed),
            self.inner.queries_total.load(Ordering::Relaxed),
            self.inner.policy_denies.load(Ordering::Relaxed),
            self.inner.recursion_denies.load(Ordering::Relaxed),
            self.inner.cache_hits.load(Ordering::Relaxed),
            self.inner.cache_misses.load(Ordering::Relaxed),
            self.inner.audit_write_errors.load(Ordering::Relaxed),
            self.inner.reload_successes.load(Ordering::Relaxed),
            self.inner.reload_failures.load(Ordering::Relaxed),
            self.inner.reload_requires_restart.load(Ordering::Relaxed),
            self.inner.drain_timeouts.load(Ordering::Relaxed),
            u8::from(self.inner.cache_required.load(Ordering::Relaxed)),
            u8::from(self.inner.cache_healthy.load(Ordering::Relaxed)),
            self.inner.cache_errors.load(Ordering::Relaxed),
            u8::from(self.inner.audit_healthy.load(Ordering::Relaxed)),
            self.inner.audit_errors.load(Ordering::Relaxed),
        )
    }
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
