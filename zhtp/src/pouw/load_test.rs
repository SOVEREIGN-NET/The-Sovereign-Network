//! Synthetic Receipt Generator for Load Testing
//!
//! Generates realistic PoUW receipts for stress testing the validation pipeline.

use crate::pouw::types::{
    ChallengeToken, Receipt, SignedReceipt, Policy, ProofType,
    DEFAULT_CHALLENGE_TTL_SECS, DEFAULT_MAX_RECEIPTS, DEFAULT_MAX_BYTES_TOTAL,
    DEFAULT_MIN_BYTES_PER_RECEIPT, POUW_VERSION,
};
use rand::{Rng, thread_rng};
use std::time::{Duration, Instant};

/// Configuration for load test generation
#[derive(Debug, Clone)]
pub struct LoadTestConfig {
    /// Number of concurrent clients to simulate
    pub concurrent_clients: usize,
    /// Receipts per second target
    pub receipts_per_second: u32,
    /// Duration of the test
    pub duration: Duration,
    /// Distribution of proof types
    pub proof_type_distribution: ProofTypeDistribution,
    /// Percentage of receipts that should be invalid (for testing rejection)
    pub invalid_receipt_percentage: f32,
    /// Maximum batch size
    pub batch_size: usize,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_clients: 10,
            receipts_per_second: 100,
            duration: Duration::from_secs(60),
            proof_type_distribution: ProofTypeDistribution::default(),
            invalid_receipt_percentage: 5.0,
            batch_size: 10,
        }
    }
}

/// Distribution of proof types in generated receipts
#[derive(Debug, Clone)]
pub struct ProofTypeDistribution {
    /// Percentage of HASH proofs (0-100)
    pub hash_percent: f32,
    /// Percentage of MERKLE proofs (0-100)
    pub merkle_percent: f32,
    /// Percentage of SIGNATURE proofs (0-100)
    pub signature_percent: f32,
}

impl Default for ProofTypeDistribution {
    fn default() -> Self {
        Self {
            hash_percent: 60.0,
            merkle_percent: 30.0,
            signature_percent: 10.0,
        }
    }
}

impl ProofTypeDistribution {
    pub fn select_proof_type(&self) -> ProofType {
        let mut rng = thread_rng();
        let roll: f32 = rng.gen_range(0.0..100.0);
        
        if roll < self.hash_percent {
            ProofType::Hash
        } else if roll < self.hash_percent + self.merkle_percent {
            ProofType::Merkle
        } else {
            ProofType::Signature
        }
    }
}

/// Synthetic receipt generator
pub struct SyntheticReceiptGenerator {
    config: LoadTestConfig,
    client_dids: Vec<String>,
}

impl SyntheticReceiptGenerator {
    /// Create a new generator with the given config
    pub fn new(config: LoadTestConfig) -> Self {
        // Generate synthetic client DIDs
        let client_dids: Vec<String> = (0..config.concurrent_clients)
            .map(|i| format!("did:sov:loadtest-client-{:04}", i))
            .collect();

        Self {
            config,
            client_dids,
        }
    }

    /// Generate a single synthetic challenge token
    pub fn generate_challenge(&self) -> ChallengeToken {
        let proof_type = self.config.proof_type_distribution.select_proof_type();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Create a policy for the proof type
        let policy = Policy {
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_bytes_total: DEFAULT_MAX_BYTES_TOTAL,
            min_bytes_per_receipt: DEFAULT_MIN_BYTES_PER_RECEIPT,
            allowed_proof_types: vec![proof_type],
        };
        
        // Generate challenge with proper types
        ChallengeToken {
            version: POUW_VERSION,
            node_id: generate_random_vec(32),
            task_id: generate_random_vec(16),
            challenge_nonce: generate_random_vec(32),
            policy,
            issued_at: now,
            expires_at: now + DEFAULT_CHALLENGE_TTL_SECS,
            node_signature: generate_random_vec(64), // Placeholder signature
        }
    }

    /// Generate a synthetic receipt for the given challenge
    pub fn generate_receipt(&self, challenge: &ChallengeToken, valid: bool) -> SignedReceipt {
        let mut rng = thread_rng();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Select a random client DID
        let client_did = self.client_dids[rng.gen_range(0..self.client_dids.len())].clone();
        
        // Select proof type from the challenge policy
        let proof_type = if challenge.policy.allowed_proof_types.is_empty() {
            ProofType::Hash
        } else {
            challenge.policy.allowed_proof_types[0]
        };

        // Generate bytes verified (between min and a reasonable max)
        let bytes_verified = rng.gen_range(
            challenge.policy.min_bytes_per_receipt..=challenge.policy.min_bytes_per_receipt * 10
        );

        let receipt = Receipt {
            version: POUW_VERSION,
            task_id: if valid {
                challenge.task_id.clone()
            } else {
                // Invalid: wrong task_id
                generate_random_vec(16)
            },
            client_did: client_did.clone(),
            client_node_id: generate_random_vec(32),
            provider_id: generate_random_vec(32),
            content_id: generate_random_vec(32),
            proof_type,
            bytes_verified,
            result_ok: true,
            started_at: now - rng.gen_range(1..60),
            finished_at: now,
            receipt_nonce: generate_random_vec(16),
            challenge_nonce: if valid {
                challenge.challenge_nonce.clone()
            } else {
                // Some invalid receipts have wrong nonce
                if rng.gen_bool(0.5) {
                    challenge.challenge_nonce.clone()
                } else {
                    generate_random_vec(32)
                }
            },
            aux: None,
        };

        SignedReceipt {
            receipt,
            sig_scheme: "ed25519".to_string(),
            signature: generate_random_vec(64), // Would be real signature in production
        }
    }

    /// Generate a batch of receipts
    pub fn generate_batch(&self, size: usize) -> Vec<(ChallengeToken, SignedReceipt)> {
        let mut rng = thread_rng();
        let mut batch = Vec::with_capacity(size);
        
        for _ in 0..size {
            let challenge = self.generate_challenge();
            let valid = rng.gen_range(0.0..100.0) >= self.config.invalid_receipt_percentage;
            let receipt = self.generate_receipt(&challenge, valid);
            batch.push((challenge, receipt));
        }
        
        batch
    }

    /// Get client DIDs for the load test
    pub fn client_dids(&self) -> &[String] {
        &self.client_dids
    }
}

/// Generate random bytes as Vec<u8>
fn generate_random_vec(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Load test results
#[derive(Debug, Clone, Default)]
pub struct LoadTestResults {
    /// Total receipts submitted
    pub total_submitted: u64,
    /// Receipts accepted
    pub accepted: u64,
    /// Receipts rejected
    pub rejected: u64,
    /// Average latency in microseconds
    pub avg_latency_us: u64,
    /// P50 latency in microseconds
    pub p50_latency_us: u64,
    /// P90 latency in microseconds
    pub p90_latency_us: u64,
    /// P99 latency in microseconds
    pub p99_latency_us: u64,
    /// Throughput (receipts per second)
    pub throughput_rps: f64,
    /// Errors encountered
    pub errors: u64,
    /// Test duration
    pub duration: Duration,
}

impl LoadTestResults {
    pub fn summary(&self) -> String {
        let accepted_pct = if self.total_submitted > 0 {
            (self.accepted as f64 / self.total_submitted as f64) * 100.0
        } else {
            0.0
        };
        let rejected_pct = if self.total_submitted > 0 {
            (self.rejected as f64 / self.total_submitted as f64) * 100.0
        } else {
            0.0
        };
        
        format!(
            "Load Test Results:\n\
             - Duration: {:?}\n\
             - Total Submitted: {}\n\
             - Accepted: {} ({:.1}%)\n\
             - Rejected: {} ({:.1}%)\n\
             - Errors: {}\n\
             - Throughput: {:.1} receipts/sec\n\
             - Latency P50: {} us\n\
             - Latency P90: {} us\n\
             - Latency P99: {} us",
            self.duration,
            self.total_submitted,
            self.accepted, accepted_pct,
            self.rejected, rejected_pct,
            self.errors,
            self.throughput_rps,
            self.p50_latency_us,
            self.p90_latency_us,
            self.p99_latency_us,
        )
    }
}

/// Run a simple load test and return results
pub async fn run_load_test(config: LoadTestConfig) -> LoadTestResults {
    let generator = SyntheticReceiptGenerator::new(config.clone());
    let start = Instant::now();
    let mut results = LoadTestResults::default();
    let mut latencies: Vec<u64> = Vec::new();

    // Calculate how many batches to generate
    let total_receipts = config.receipts_per_second as u64 * config.duration.as_secs();
    let num_batches = (total_receipts as usize + config.batch_size - 1) / config.batch_size;

    for _ in 0..num_batches {
        let batch_start = Instant::now();
        let batch = generator.generate_batch(config.batch_size);
        
        for (challenge, receipt) in batch {
            results.total_submitted += 1;
            
            // Simulate validation (would call actual validator in real test)
            let validation_start = Instant::now();
            
            // Simplified validation: check task_id matches challenge
            let is_valid = receipt.receipt.task_id == challenge.task_id
                && receipt.receipt.challenge_nonce == challenge.challenge_nonce;
            
            let latency = validation_start.elapsed().as_micros() as u64;
            latencies.push(latency);
            
            if is_valid {
                results.accepted += 1;
            } else {
                results.rejected += 1;
            }
        }

        // Rate limiting to match target throughput
        let expected_duration = Duration::from_secs_f64(
            config.batch_size as f64 / config.receipts_per_second as f64
        );
        let actual_duration = batch_start.elapsed();
        if actual_duration < expected_duration {
            tokio::time::sleep(expected_duration - actual_duration).await;
        }

        // Check if we've exceeded test duration
        if start.elapsed() >= config.duration {
            break;
        }
    }

    results.duration = start.elapsed();
    results.throughput_rps = if results.duration.as_secs_f64() > 0.0 {
        results.total_submitted as f64 / results.duration.as_secs_f64()
    } else {
        0.0
    };

    // Calculate latency percentiles
    if !latencies.is_empty() {
        latencies.sort_unstable();
        let sum: u64 = latencies.iter().sum();
        results.avg_latency_us = sum / latencies.len() as u64;
        results.p50_latency_us = latencies[latencies.len() / 2];
        results.p90_latency_us = latencies[(latencies.len() * 90) / 100];
        results.p99_latency_us = latencies[std::cmp::min((latencies.len() * 99) / 100, latencies.len() - 1)];
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_type_distribution() {
        let dist = ProofTypeDistribution {
            hash_percent: 100.0,
            merkle_percent: 0.0,
            signature_percent: 0.0,
        };
        
        // Should always return Hash
        for _ in 0..10 {
            assert!(matches!(dist.select_proof_type(), ProofType::Hash));
        }
    }

    #[test]
    fn test_generate_challenge() {
        let config = LoadTestConfig::default();
        let generator = SyntheticReceiptGenerator::new(config);
        
        let challenge = generator.generate_challenge();
        assert_eq!(challenge.task_id.len(), 16);
        assert_eq!(challenge.challenge_nonce.len(), 32);
        assert!(challenge.expires_at > challenge.issued_at);
    }

    #[test]
    fn test_generate_receipt() {
        let config = LoadTestConfig::default();
        let generator = SyntheticReceiptGenerator::new(config);
        
        let challenge = generator.generate_challenge();
        let receipt = generator.generate_receipt(&challenge, true);
        
        // Valid receipt should have matching task_id and challenge_nonce
        assert_eq!(receipt.receipt.task_id, challenge.task_id);
        assert_eq!(receipt.receipt.challenge_nonce, challenge.challenge_nonce);
    }

    #[test]
    fn test_generate_batch() {
        let config = LoadTestConfig {
            concurrent_clients: 5,
            batch_size: 10,
            ..Default::default()
        };
        let generator = SyntheticReceiptGenerator::new(config);
        
        let batch = generator.generate_batch(10);
        assert_eq!(batch.len(), 10);
    }

    #[tokio::test]
    async fn test_run_short_load_test() {
        let config = LoadTestConfig {
            concurrent_clients: 2,
            receipts_per_second: 10,
            duration: Duration::from_millis(100),
            batch_size: 5,
            ..Default::default()
        };
        
        let results = run_load_test(config).await;
        assert!(results.total_submitted > 0);
    }
}
