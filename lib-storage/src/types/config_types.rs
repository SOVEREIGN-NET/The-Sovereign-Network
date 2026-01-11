//! Configuration type definitions
//!
//! Contains all configuration-related types for the storage system including
//! storage configuration, erasure coding configuration, and system parameters.

use std::path::PathBuf;
use std::time::Duration;
use serde::{Serialize, Deserialize};

/// Storage system configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Local storage path
    pub storage_path: PathBuf,
    /// Total storage capacity
    pub capacity: u64,
    /// Replication factor for content
    pub replication_factor: u8,
    /// Node identifier bytes
    pub node_id: [u8; 32],
    /// Network addresses for this node
    pub addresses: Vec<String>,
    /// K-bucket size for Kademlia routing
    pub k_bucket_size: usize,
    /// DHT replication factor
    pub dht_replication: usize,
    /// Number of erasure coding data chunks
    pub erasure_data_chunks: usize,
    /// Number of erasure coding parity chunks
    pub erasure_parity_chunks: usize,
    /// Chunk size for erasure coding
    pub chunk_size: usize,
}

/// Erasure coding configuration
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of data chunks
    pub data_chunks: u8,
    /// Number of parity chunks
    pub parity_chunks: u8,
    /// Chunk size in bytes
    pub chunk_size: u32,
}

/// Configuration for ZK proof verification timeouts
///
/// [DB-002] Security: Prevents DoS attacks through crafted proofs
/// that could consume excessive verification time.
///
/// # Security Rationale
///
/// Zero-knowledge proof verification is computationally intensive.
/// Malicious actors could submit specially crafted proofs designed to
/// cause verification to take excessively long, leading to denial of service.
/// This configuration allows setting timeouts to bound verification time.
///
/// # Usage
///
/// ```rust
/// use lib_storage::types::ZkVerificationConfig;
/// use std::time::Duration;
///
/// let config = ZkVerificationConfig {
///     timeout: Duration::from_secs(5),
///     enable_metrics: true,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVerificationConfig {
    /// Maximum time allowed for ZK proof verification.
    /// Default: 5 seconds (recommended for production).
    ///
    /// Considerations:
    /// - Too short: May fail valid proofs on slow hardware
    /// - Too long: Increases DoS vulnerability window
    /// - Typical Plonky2 verification: <100ms
    #[serde(with = "humantime_serde", default = "default_zk_timeout")]
    pub timeout: Duration,

    /// Enable metrics collection for verification timeouts.
    /// Useful for monitoring and alerting on potential attacks.
    #[serde(default = "default_enable_metrics")]
    pub enable_metrics: bool,
}

fn default_zk_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_enable_metrics() -> bool {
    true
}

impl Default for ZkVerificationConfig {
    fn default() -> Self {
        Self {
            timeout: default_zk_timeout(),
            enable_metrics: default_enable_metrics(),
        }
    }
}

/// Metrics for ZK verification operations
///
/// [DB-002] Tracks timeout occurrences for monitoring and alerting.
#[derive(Debug, Clone, Default)]
pub struct ZkVerificationMetrics {
    /// Total number of verification attempts
    pub total_verifications: u64,
    /// Number of successful verifications
    pub successful_verifications: u64,
    /// Number of failed verifications (proof invalid)
    pub failed_verifications: u64,
    /// Number of verification timeouts
    pub timeout_count: u64,
    /// Number of verification errors (system errors)
    pub error_count: u64,
    /// Average verification time in milliseconds
    pub avg_verification_time_ms: f64,
    /// Maximum verification time observed in milliseconds
    pub max_verification_time_ms: u64,
}

impl ZkVerificationMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful verification
    pub fn record_success(&mut self, duration_ms: u64) {
        self.total_verifications += 1;
        self.successful_verifications += 1;
        self.update_timing(duration_ms);
    }

    /// Record a failed verification (proof invalid)
    pub fn record_failure(&mut self, duration_ms: u64) {
        self.total_verifications += 1;
        self.failed_verifications += 1;
        self.update_timing(duration_ms);
    }

    /// Record a verification timeout
    pub fn record_timeout(&mut self) {
        self.total_verifications += 1;
        self.timeout_count += 1;
    }

    /// Record a verification error
    pub fn record_error(&mut self) {
        self.total_verifications += 1;
        self.error_count += 1;
    }

    /// Update timing statistics
    fn update_timing(&mut self, duration_ms: u64) {
        if duration_ms > self.max_verification_time_ms {
            self.max_verification_time_ms = duration_ms;
        }

        // Update rolling average using incremental average formula
        let completed = self.successful_verifications.saturating_add(self.failed_verifications);
        if completed > 0 {
            self.avg_verification_time_ms =
                self.avg_verification_time_ms
                    + (duration_ms as f64 - self.avg_verification_time_ms) / completed as f64;
        }
    }

    /// Get the timeout rate as a percentage
    pub fn timeout_rate(&self) -> f64 {
        if self.total_verifications == 0 {
            0.0
        } else {
            (self.timeout_count as f64 / self.total_verifications as f64) * 100.0
        }
    }
}
