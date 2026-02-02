//! PoUW-Specific Metrics for Monitoring
//!
//! Provides Prometheus-compatible metrics for the PoUW protocol.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// PoUW metrics collector
pub struct PouwMetrics {
    /// Total receipts received
    pub receipts_received: AtomicU64,
    /// Receipts accepted
    pub receipts_accepted: AtomicU64,
    /// Receipts rejected - by reason
    rejection_counters: Arc<RwLock<RejectionCounters>>,
    /// Signature verification timing (microseconds)
    sig_verification_times: Arc<RwLock<Vec<u64>>>,
    /// Receipt processing timing (microseconds)
    processing_times: Arc<RwLock<Vec<u64>>>,
    /// Challenge tokens issued
    pub challenges_issued: AtomicU64,
    /// Challenges expired
    pub challenges_expired: AtomicU64,
    /// Total rewards calculated
    pub rewards_calculated: AtomicU64,
    /// Total rewards distributed
    pub rewards_distributed: AtomicU64,
    /// Rate limit denials
    pub rate_limit_denials: AtomicU64,
    /// Disputes logged
    pub disputes_logged: AtomicU64,
}

/// Counters for rejection reasons
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RejectionCounters {
    pub invalid_signature: u64,
    pub expired_challenge: u64,
    pub invalid_challenge_binding: u64,
    pub duplicate_nonce: u64,
    pub invalid_proof_type: u64,
    pub policy_violation: u64,
    pub malformed_receipt: u64,
    pub unknown_client: u64,
    pub other: u64,
}

impl PouwMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            receipts_received: AtomicU64::new(0),
            receipts_accepted: AtomicU64::new(0),
            rejection_counters: Arc::new(RwLock::new(RejectionCounters::default())),
            sig_verification_times: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            processing_times: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            challenges_issued: AtomicU64::new(0),
            challenges_expired: AtomicU64::new(0),
            rewards_calculated: AtomicU64::new(0),
            rewards_distributed: AtomicU64::new(0),
            rate_limit_denials: AtomicU64::new(0),
            disputes_logged: AtomicU64::new(0),
        }
    }

    /// Increment receipt received counter
    pub fn record_receipt_received(&self) {
        self.receipts_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment receipt accepted counter
    pub fn record_receipt_accepted(&self) {
        self.receipts_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejection with reason
    pub async fn record_rejection(&self, reason: RejectionType) {
        let mut counters = self.rejection_counters.write().await;
        match reason {
            RejectionType::InvalidSignature => counters.invalid_signature += 1,
            RejectionType::ExpiredChallenge => counters.expired_challenge += 1,
            RejectionType::InvalidChallengeBinding => counters.invalid_challenge_binding += 1,
            RejectionType::DuplicateNonce => counters.duplicate_nonce += 1,
            RejectionType::InvalidProofType => counters.invalid_proof_type += 1,
            RejectionType::PolicyViolation => counters.policy_violation += 1,
            RejectionType::MalformedReceipt => counters.malformed_receipt += 1,
            RejectionType::UnknownClient => counters.unknown_client += 1,
            RejectionType::Other => counters.other += 1,
        }
    }

    /// Record signature verification time
    pub async fn record_sig_verification_time(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        let mut times = self.sig_verification_times.write().await;
        times.push(micros);
        // Keep last 10000 samples
        if times.len() > 10000 {
            times.drain(0..5000);
        }
    }

    /// Record receipt processing time
    pub async fn record_processing_time(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        let mut times = self.processing_times.write().await;
        times.push(micros);
        // Keep last 10000 samples
        if times.len() > 10000 {
            times.drain(0..5000);
        }
    }

    /// Increment challenge issued counter
    pub fn record_challenge_issued(&self) {
        self.challenges_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment challenge expired counter
    pub fn record_challenge_expired(&self) {
        self.challenges_expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment rate limit denial counter
    pub fn record_rate_limit_denial(&self) {
        self.rate_limit_denials.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment dispute logged counter
    pub fn record_dispute(&self) {
        self.disputes_logged.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of all metrics
    pub async fn snapshot(&self) -> PouwMetricsSnapshot {
        let rejection_counters = self.rejection_counters.read().await.clone();
        let sig_times = self.sig_verification_times.read().await;
        let proc_times = self.processing_times.read().await;

        PouwMetricsSnapshot {
            receipts_received: self.receipts_received.load(Ordering::Relaxed),
            receipts_accepted: self.receipts_accepted.load(Ordering::Relaxed),
            rejection_counters,
            sig_verification_histogram: compute_histogram(&sig_times),
            processing_histogram: compute_histogram(&proc_times),
            challenges_issued: self.challenges_issued.load(Ordering::Relaxed),
            challenges_expired: self.challenges_expired.load(Ordering::Relaxed),
            rewards_calculated: self.rewards_calculated.load(Ordering::Relaxed),
            rewards_distributed: self.rewards_distributed.load(Ordering::Relaxed),
            rate_limit_denials: self.rate_limit_denials.load(Ordering::Relaxed),
            disputes_logged: self.disputes_logged.load(Ordering::Relaxed),
        }
    }

    /// Export metrics in Prometheus format
    pub async fn export_prometheus(&self) -> String {
        let snapshot = self.snapshot().await;
        let mut output = String::new();

        // Counter metrics
        output.push_str("# HELP pouw_receipts_received_total Total receipts received\n");
        output.push_str("# TYPE pouw_receipts_received_total counter\n");
        output.push_str(&format!("pouw_receipts_received_total {}\n", snapshot.receipts_received));

        output.push_str("# HELP pouw_receipts_accepted_total Total receipts accepted\n");
        output.push_str("# TYPE pouw_receipts_accepted_total counter\n");
        output.push_str(&format!("pouw_receipts_accepted_total {}\n", snapshot.receipts_accepted));

        // Rejection counters with labels
        output.push_str("# HELP pouw_receipts_rejected_total Total receipts rejected by reason\n");
        output.push_str("# TYPE pouw_receipts_rejected_total counter\n");
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"invalid_signature\"}} {}\n", snapshot.rejection_counters.invalid_signature));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"expired_challenge\"}} {}\n", snapshot.rejection_counters.expired_challenge));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"invalid_challenge_binding\"}} {}\n", snapshot.rejection_counters.invalid_challenge_binding));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"duplicate_nonce\"}} {}\n", snapshot.rejection_counters.duplicate_nonce));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"invalid_proof_type\"}} {}\n", snapshot.rejection_counters.invalid_proof_type));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"policy_violation\"}} {}\n", snapshot.rejection_counters.policy_violation));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"malformed_receipt\"}} {}\n", snapshot.rejection_counters.malformed_receipt));
        output.push_str(&format!("pouw_receipts_rejected_total{{reason=\"unknown_client\"}} {}\n", snapshot.rejection_counters.unknown_client));

        // Challenge metrics
        output.push_str("# HELP pouw_challenges_issued_total Total challenges issued\n");
        output.push_str("# TYPE pouw_challenges_issued_total counter\n");
        output.push_str(&format!("pouw_challenges_issued_total {}\n", snapshot.challenges_issued));

        // Rate limiting
        output.push_str("# HELP pouw_rate_limit_denials_total Total rate limit denials\n");
        output.push_str("# TYPE pouw_rate_limit_denials_total counter\n");
        output.push_str(&format!("pouw_rate_limit_denials_total {}\n", snapshot.rate_limit_denials));

        // Histograms
        if let Some(hist) = &snapshot.sig_verification_histogram {
            output.push_str("# HELP pouw_signature_verification_duration_microseconds Signature verification duration\n");
            output.push_str("# TYPE pouw_signature_verification_duration_microseconds histogram\n");
            output.push_str(&format!("pouw_signature_verification_duration_microseconds_sum {}\n", hist.sum));
            output.push_str(&format!("pouw_signature_verification_duration_microseconds_count {}\n", hist.count));
            for (le, count) in &hist.buckets {
                output.push_str(&format!("pouw_signature_verification_duration_microseconds_bucket{{le=\"{}\"}} {}\n", le, count));
            }
        }

        if let Some(hist) = &snapshot.processing_histogram {
            output.push_str("# HELP pouw_receipt_processing_duration_microseconds Receipt processing duration\n");
            output.push_str("# TYPE pouw_receipt_processing_duration_microseconds histogram\n");
            output.push_str(&format!("pouw_receipt_processing_duration_microseconds_sum {}\n", hist.sum));
            output.push_str(&format!("pouw_receipt_processing_duration_microseconds_count {}\n", hist.count));
            for (le, count) in &hist.buckets {
                output.push_str(&format!("pouw_receipt_processing_duration_microseconds_bucket{{le=\"{}\"}} {}\n", le, count));
            }
        }

        output
    }
}

impl Default for PouwMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all PoUW metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PouwMetricsSnapshot {
    pub receipts_received: u64,
    pub receipts_accepted: u64,
    pub rejection_counters: RejectionCounters,
    pub sig_verification_histogram: Option<Histogram>,
    pub processing_histogram: Option<Histogram>,
    pub challenges_issued: u64,
    pub challenges_expired: u64,
    pub rewards_calculated: u64,
    pub rewards_distributed: u64,
    pub rate_limit_denials: u64,
    pub disputes_logged: u64,
}

/// Histogram data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    pub sum: u64,
    pub count: u64,
    pub buckets: Vec<(String, u64)>,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
}

/// Rejection types for metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionType {
    InvalidSignature,
    ExpiredChallenge,
    InvalidChallengeBinding,
    DuplicateNonce,
    InvalidProofType,
    PolicyViolation,
    MalformedReceipt,
    UnknownClient,
    Other,
}

/// Compute histogram from samples
fn compute_histogram(samples: &[u64]) -> Option<Histogram> {
    if samples.is_empty() {
        return None;
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();

    let sum: u64 = sorted.iter().sum();
    let count = sorted.len() as u64;

    // Standard histogram buckets (microseconds)
    let bucket_boundaries = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000];
    let mut buckets = Vec::new();
    
    for boundary in bucket_boundaries {
        let count_below = sorted.iter().filter(|&&x| x <= boundary).count() as u64;
        buckets.push((boundary.to_string(), count_below));
    }
    buckets.push(("+Inf".to_string(), count));

    // Percentiles
    let p50 = sorted[sorted.len() / 2];
    let p90 = sorted[(sorted.len() * 90) / 100];
    let p99 = sorted[(sorted.len() * 99) / 100];

    Some(Histogram {
        sum,
        count,
        buckets,
        p50,
        p90,
        p99,
    })
}

/// Timer for measuring operation duration
pub struct MetricsTimer {
    start: Instant,
}

impl MetricsTimer {
    pub fn start() -> Self {
        Self { start: Instant::now() }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_receipt_counters() {
        let metrics = PouwMetrics::new();
        
        metrics.record_receipt_received();
        metrics.record_receipt_received();
        metrics.record_receipt_accepted();

        let snapshot = metrics.snapshot().await;
        assert_eq!(snapshot.receipts_received, 2);
        assert_eq!(snapshot.receipts_accepted, 1);
    }

    #[tokio::test]
    async fn test_rejection_counters() {
        let metrics = PouwMetrics::new();
        
        metrics.record_rejection(RejectionType::InvalidSignature).await;
        metrics.record_rejection(RejectionType::InvalidSignature).await;
        metrics.record_rejection(RejectionType::ExpiredChallenge).await;

        let snapshot = metrics.snapshot().await;
        assert_eq!(snapshot.rejection_counters.invalid_signature, 2);
        assert_eq!(snapshot.rejection_counters.expired_challenge, 1);
    }

    #[tokio::test]
    async fn test_timing_histogram() {
        let metrics = PouwMetrics::new();
        
        metrics.record_sig_verification_time(Duration::from_micros(100)).await;
        metrics.record_sig_verification_time(Duration::from_micros(200)).await;
        metrics.record_sig_verification_time(Duration::from_micros(300)).await;

        let snapshot = metrics.snapshot().await;
        let hist = snapshot.sig_verification_histogram.unwrap();
        assert_eq!(hist.count, 3);
        assert_eq!(hist.sum, 600);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let metrics = PouwMetrics::new();
        metrics.record_receipt_received();
        metrics.record_challenge_issued();

        let output = metrics.export_prometheus().await;
        assert!(output.contains("pouw_receipts_received_total 1"));
        assert!(output.contains("pouw_challenges_issued_total 1"));
    }
}
