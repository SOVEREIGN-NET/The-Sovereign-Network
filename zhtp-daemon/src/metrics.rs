//! Gateway metrics and observability.
//!
//! Lightweight atomic counters plus structured tracing for operational visibility.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

/// Runtime metrics for the gateway.
#[derive(Debug, Default)]
pub struct GatewayMetrics {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_failure: AtomicU64,
    retries_total: AtomicU64,
    dynamic_candidates_seen: AtomicU64,
    dynamic_promotions: AtomicU64,
}

impl GatewayMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.requests_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_retry(&self) {
        self.retries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dynamic_candidate(&self) {
        self.dynamic_candidates_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dynamic_promotion(&self) {
        self.dynamic_promotions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failure: self.requests_failure.load(Ordering::Relaxed),
            retries_total: self.retries_total.load(Ordering::Relaxed),
            dynamic_candidates_seen: self.dynamic_candidates_seen.load(Ordering::Relaxed),
            dynamic_promotions: self.dynamic_promotions.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failure: u64,
    pub retries_total: u64,
    pub dynamic_candidates_seen: u64,
    pub dynamic_promotions: u64,
}

/// Log a backend state transition for observability.
pub fn log_state_transition(addr: &str, old_state: &str, new_state: &str) {
    info!(
        addr = %addr,
        old_state = %old_state,
        new_state = %new_state,
        event = "backend_state_transition",
        "Backend state changed"
    );
}

/// Log a periodic pool snapshot.
pub fn log_pool_snapshot(
    static_total: usize,
    dynamic_total: usize,
    healthy: usize,
    unhealthy: usize,
    half_open: usize,
    quarantined: usize,
) {
    info!(
        static_total,
        dynamic_total,
        healthy,
        unhealthy,
        half_open,
        quarantined,
        event = "pool_snapshot",
        "Backend pool snapshot"
    );
}
