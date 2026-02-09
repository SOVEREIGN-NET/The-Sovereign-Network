//! Ren AI Metrics
//!
//! Prometheus-compatible counters and histograms for monitoring
//! the Ren inference engine in production.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Collected metrics for the Ren AI inference engine.
pub struct RenAiMetrics {
    /// Total inference requests completed.
    total_inferences: AtomicU64,
    /// Total inference requests that failed.
    total_failures: AtomicU64,
    /// Currently in-flight requests.
    active_requests: AtomicU32,
    /// Total input tokens processed (lifetime).
    total_input_tokens: AtomicU64,
    /// Total output tokens generated (lifetime).
    total_output_tokens: AtomicU64,
    /// Cumulative latency in ms (for average calculation).
    cumulative_latency_ms: AtomicU64,
    /// Total requests rejected by rate limiter.
    rate_limited_count: AtomicU64,
    /// Total requests blocked by content filter.
    content_filtered_count: AtomicU64,
}

/// Point-in-time snapshot of metrics (for serialization).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RenAiMetricsSnapshot {
    pub total_inferences: u64,
    pub total_failures: u64,
    pub active_requests: u32,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub avg_latency_ms: f64,
    pub rate_limited_count: u64,
    pub content_filtered_count: u64,
}

impl RenAiMetrics {
    pub fn new() -> Self {
        Self {
            total_inferences: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            active_requests: AtomicU32::new(0),
            total_input_tokens: AtomicU64::new(0),
            total_output_tokens: AtomicU64::new(0),
            cumulative_latency_ms: AtomicU64::new(0),
            rate_limited_count: AtomicU64::new(0),
            content_filtered_count: AtomicU64::new(0),
        }
    }

    /// Record a completed inference.
    pub fn record_inference(&self, latency_ms: u64, input_tokens: u32, output_tokens: u32) {
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.total_input_tokens.fetch_add(input_tokens as u64, Ordering::Relaxed);
        self.total_output_tokens.fetch_add(output_tokens as u64, Ordering::Relaxed);
        self.cumulative_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
    }

    /// Record a failed inference.
    pub fn record_failure(&self) {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment active request counter.
    pub fn increment_active_requests(&self) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active request counter.
    pub fn decrement_active_requests(&self) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a rate-limited request.
    pub fn record_rate_limited(&self) {
        self.rate_limited_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a content-filtered request.
    pub fn record_content_filtered(&self) {
        self.content_filtered_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a point-in-time snapshot of all metrics.
    pub fn snapshot(&self) -> RenAiMetricsSnapshot {
        let total = self.total_inferences.load(Ordering::Relaxed);
        let cumulative = self.cumulative_latency_ms.load(Ordering::Relaxed);
        let avg_latency = if total > 0 {
            cumulative as f64 / total as f64
        } else {
            0.0
        };

        RenAiMetricsSnapshot {
            total_inferences: total,
            total_failures: self.total_failures.load(Ordering::Relaxed),
            active_requests: self.active_requests.load(Ordering::Relaxed),
            total_input_tokens: self.total_input_tokens.load(Ordering::Relaxed),
            total_output_tokens: self.total_output_tokens.load(Ordering::Relaxed),
            avg_latency_ms: avg_latency,
            rate_limited_count: self.rate_limited_count.load(Ordering::Relaxed),
            content_filtered_count: self.content_filtered_count.load(Ordering::Relaxed),
        }
    }

    /// Format metrics as Prometheus exposition text.
    pub fn to_prometheus(&self) -> String {
        let s = self.snapshot();
        format!(
            "\
# HELP ren_ai_total_inferences Total completed inference requests.
# TYPE ren_ai_total_inferences counter
ren_ai_total_inferences {total}

# HELP ren_ai_total_failures Total failed inference requests.
# TYPE ren_ai_total_failures counter
ren_ai_total_failures {failures}

# HELP ren_ai_active_requests Currently in-flight inference requests.
# TYPE ren_ai_active_requests gauge
ren_ai_active_requests {active}

# HELP ren_ai_total_input_tokens Total input tokens processed.
# TYPE ren_ai_total_input_tokens counter
ren_ai_total_input_tokens {input_tok}

# HELP ren_ai_total_output_tokens Total output tokens generated.
# TYPE ren_ai_total_output_tokens counter
ren_ai_total_output_tokens {output_tok}

# HELP ren_ai_avg_latency_ms Average inference latency in milliseconds.
# TYPE ren_ai_avg_latency_ms gauge
ren_ai_avg_latency_ms {avg_lat}

# HELP ren_ai_rate_limited_total Requests rejected by rate limiter.
# TYPE ren_ai_rate_limited_total counter
ren_ai_rate_limited_total {rate_lim}

# HELP ren_ai_content_filtered_total Requests blocked by content filter.
# TYPE ren_ai_content_filtered_total counter
ren_ai_content_filtered_total {content_filt}
",
            total = s.total_inferences,
            failures = s.total_failures,
            active = s.active_requests,
            input_tok = s.total_input_tokens,
            output_tok = s.total_output_tokens,
            avg_lat = s.avg_latency_ms,
            rate_lim = s.rate_limited_count,
            content_filt = s.content_filtered_count,
        )
    }
}

impl Default for RenAiMetrics {
    fn default() -> Self {
        Self::new()
    }
}
