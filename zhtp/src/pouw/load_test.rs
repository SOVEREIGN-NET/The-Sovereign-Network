//! Synthetic Receipt Generator for Load Testing
//!
//! Generates realistic PoUW receipts for stress testing the validation pipeline.

use crate::pouw::types::{
    ChallengeToken, Receipt, SignedReceipt, Policy, ProofType,
    DEFAULT_CHALLENGE_TTL_SECS, DEFAULT_MAX_RECEIPTS, DEFAULT_MAX_BYTES_TOTAL,
    DEFAULT_MIN_BYTES_PER_RECEIPT, POUW_VERSION,
};
use crate::pouw::{ChallengeGenerator, ReceiptValidator};
use rand::{Rng, thread_rng};
use std::sync::Arc;
use tokio::sync::RwLock;
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
    // Use as_secs_f64() to handle sub-second durations correctly
    let total_receipts = (config.receipts_per_second as f64 * config.duration.as_secs_f64()).ceil() as usize;
    // Ensure at least one batch for short durations
    let num_batches = std::cmp::max(1, (total_receipts + config.batch_size - 1) / config.batch_size);

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

#[cfg(test)]
mod stress_tests {
    use super::*;
    use std::collections::HashSet;

    fn build_validator() -> ReceiptValidator {
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);

        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        ReceiptValidator::new(generator, Arc::new(RwLock::new(lib_identity::IdentityManager::new())))
    }

    fn build_batch_with_client(config: &LoadTestConfig, client_did: &str) -> crate::pouw::types::ReceiptBatch {
        let synth_gen = SyntheticReceiptGenerator::new(config.clone());
        let receipts: Vec<SignedReceipt> = synth_gen
            .generate_batch(config.batch_size)
            .into_iter()
            .map(|(_, mut receipt)| {
                receipt.receipt.client_did = client_did.to_string();
                receipt
            })
            .collect();

        crate::pouw::types::ReceiptBatch {
            version: POUW_VERSION,
            client_did: client_did.to_string(),
            receipts,
        }
    }

    #[tokio::test]
    async fn test_high_throughput_receipt_validation() {
        let config = LoadTestConfig {
            concurrent_clients: 100,
            receipts_per_second: 1000,
            duration: Duration::from_secs(1),
            batch_size: 100,
            invalid_receipt_percentage: 10.0,
            ..Default::default()
        };
        let validator = build_validator();

        let start = Instant::now();
        let mut total_accepted = 0u64;
        let mut total_rejected = 0u64;

        for _ in 0..10 {
            let batch_struct = build_batch_with_client(&config, "did:sov:throughput-test");
            let result = validator.validate_batch(&batch_struct).await.unwrap();
            total_accepted += result.accepted.len() as u64;
            total_rejected += result.rejected.len() as u64;
        }

        let elapsed = start.elapsed();
        let total_processed = total_accepted + total_rejected;
        let throughput = total_processed as f64 / elapsed.as_secs_f64();
        
        println!(
            "High throughput validation test: {} receipts/sec (accepted={}, rejected={})",
            throughput, total_accepted, total_rejected
        );
        assert_eq!(total_processed, 1000, "Expected 1000 processed receipts");
        assert!(throughput > 100.0, "Expected >100 receipts/sec, got {}", throughput);
    }

    #[tokio::test]
    async fn test_concurrent_validation_stress() {
        let validator = Arc::new(build_validator());
        let config = LoadTestConfig {
            concurrent_clients: 50,
            batch_size: 50,
            ..Default::default()
        };
        let base_batch = build_batch_with_client(&config, "did:sov:concurrent-overlap");
        let base_receipts = base_batch.receipts.clone();

        let start = Instant::now();
        let mut handles = vec![];
        
        for _ in 0..20 {
            let validator = Arc::clone(&validator);
            let receipts = base_receipts.clone();
            let handle = tokio::spawn(async move {
                let batch_struct = crate::pouw::types::ReceiptBatch {
                    version: POUW_VERSION,
                    client_did: "did:sov:concurrent-overlap".to_string(),
                    receipts,
                };
                validator.validate_batch(&batch_struct).await.unwrap()
            });
            handles.push(handle);
        }

        let mut total_processed = 0usize;
        for handle in handles {
            let result = handle.await.unwrap();
            total_processed += result.accepted.len() + result.rejected.len();
        }

        let elapsed = start.elapsed();
        let throughput = total_processed as f64 / elapsed.as_secs_f64();
        println!(
            "Concurrent overlap validation: {} receipts/sec processed={}",
            throughput, total_processed
        );
        assert_eq!(total_processed, 1000, "Should process 1000 receipts concurrently");
        assert!(throughput > 100.0, "Should process >100 receipts/sec concurrently");
    }

    #[tokio::test]
    async fn test_nonce_deduplication_stress() {
        let mut seen_nonces: HashSet<Vec<u8>> = HashSet::new();
        let config = LoadTestConfig {
            concurrent_clients: 1000,
            batch_size: 100,
            ..Default::default()
        };
        
        let generator = SyntheticReceiptGenerator::new(config.clone());
        let mut duplicates = 0u64;
        
        for _ in 0..10 {
            let batch = generator.generate_batch(config.batch_size);
            for (_, receipt) in batch {
                let nonce = receipt.receipt.receipt_nonce.clone();
                if seen_nonces.contains(&nonce) {
                    duplicates += 1;
                } else {
                    seen_nonces.insert(nonce);
                }
            }
        }
        
        println!(
            "Deduplication test: {} duplicate nonces observed in 1000 generated nonces",
            duplicates
        );
        assert_eq!(duplicates, 0, "Expected no duplicate random nonces");
    }

    #[tokio::test]
    async fn test_signature_verification_throughput() {
        let validator = build_validator();
        
        let config = LoadTestConfig {
            batch_size: 100,
            ..Default::default()
        };
        
        let start = Instant::now();
        let iterations = 100;
        let mut total_accepted = 0u64;
        let mut total_rejected = 0u64;
        
        for _ in 0..iterations {
            let batch_struct = build_batch_with_client(&config, "did:sov:signature-path");
            let result = validator.validate_batch(&batch_struct).await.unwrap();
            total_accepted += result.accepted.len() as u64;
            total_rejected += result.rejected.len() as u64;
        }
        
        let elapsed = start.elapsed();
        let total_processed = total_accepted + total_rejected;
        let throughput = total_processed as f64 / elapsed.as_secs_f64();
        
        println!(
            "Signature-path throughput: {} receipts/sec (accepted={}, rejected={})",
            throughput, total_accepted, total_rejected
        );
        assert_eq!(total_processed, 10000, "Expected 10k receipts processed");
        assert!(throughput > 50.0, "Expected >50 verifications/sec");
    }

    #[tokio::test]
    async fn test_memory_usage_under_load() {
        let config = LoadTestConfig {
            concurrent_clients: 1000,
            batch_size: 500,
            duration: Duration::from_secs(2),
            ..Default::default()
        };
        
        let generator = SyntheticReceiptGenerator::new(config.clone());
        let mut all_batches = vec![];
        
        for _ in 0..10 {
            let batch = generator.generate_batch(config.batch_size);
            all_batches.push(batch);
        }
        
        let total_receipts: usize = all_batches.iter()
            .map(|b| b.len())
            .sum();
        
        println!("Memory test: {} receipts stored in memory", total_receipts);
        assert!(total_receipts == 5000, "Should have 5000 receipts");
        
        drop(all_batches);
    }

    #[tokio::test]
    async fn test_rate_limiter_stress() {
        use crate::pouw::PouwRateLimiter;
        use std::net::IpAddr;
        
        let limiter = Arc::new(PouwRateLimiter::with_defaults());
        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
        
        let start = Instant::now();
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        
        for i in 0..1000 {
            let did = format!("did:sov:stress-client-{}", i);
            match limiter.check_request(test_ip, &did).await {
                crate::pouw::rate_limiter::RateLimitResult::Allowed { .. } => {
                    accepted += 1;
                }
                crate::pouw::rate_limiter::RateLimitResult::Denied { .. } => {
                    rejected += 1;
                }
            }
        }
        
        let elapsed = start.elapsed();
        let throughput = 1000 as f64 / elapsed.as_secs_f64();
        
        println!("Rate limiter stress: {} req/sec, accepted={}, rejected={}", 
                 throughput, accepted, rejected);
        assert!(throughput > 10000.0, "Rate limiter should handle >10k req/sec");
    }

    #[tokio::test]
    async fn test_batch_processing_latency() {
        let config = LoadTestConfig {
            batch_size: 100,
            ..Default::default()
        };
        
        let (node_pubkey, node_privkey) = lib_crypto::classical::ed25519::ed25519_keypair();
        let mut priv_arr = [0u8; 32];
        let mut node_id = [0u8; 32];
        priv_arr.copy_from_slice(&node_privkey[..32]);
        node_id.copy_from_slice(&node_pubkey[..32]);
        
        let generator = Arc::new(ChallengeGenerator::new(priv_arr, node_id));
        let validator = ReceiptValidator::new(generator, Arc::new(RwLock::new(lib_identity::IdentityManager::new())));
        
        let mut latencies = vec![];
        
        for _ in 0..100 {
            let synth_gen = SyntheticReceiptGenerator::new(config.clone());
            let batch = synth_gen.generate_batch(config.batch_size);
            let receipts: Vec<SignedReceipt> = batch.into_iter().map(|(_, r)| r).collect();
            
            let batch_struct = crate::pouw::types::ReceiptBatch {
                version: POUW_VERSION,
                client_did: "did:sov:latency-test".to_string(),
                receipts,
            };
            
            let start = Instant::now();
            let _ = validator.validate_batch(&batch_struct).await;
            latencies.push(start.elapsed().as_millis() as f64);
        }
        
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = latencies[latencies.len() / 2];
        let p99 = latencies[(latencies.len() * 99) / 100];
        
        println!("Batch processing latency: P50={}ms, P99={}ms", p50, p99);
        assert!(p50 < 100.0, "P50 latency should be <100ms");
        assert!(p99 < 500.0, "P99 latency should be <500ms");
    }

    #[tokio::test]
    async fn test_concurrent_batch_validation() {
        let validator = Arc::new(build_validator());
        
        let config = LoadTestConfig {
            batch_size: 50,
            ..Default::default()
        };
        let base_batch = build_batch_with_client(&config, "did:sov:concurrent-test");
        let base_receipts = base_batch.receipts.clone();
        
        let start = Instant::now();
        
        let mut handles = vec![];
        for _ in 0..20 {
            let validator = validator.clone();
            let receipts = base_receipts.clone();
            
            let handle = tokio::spawn(async move {
                let batch_struct = crate::pouw::types::ReceiptBatch {
                    version: POUW_VERSION,
                    client_did: "did:sov:concurrent-test".to_string(),
                    receipts,
                };
                
                validator.validate_batch(&batch_struct).await
            });
            handles.push(handle);
        }
        
        let mut total_accepted = 0u64;
        let mut total_rejected = 0u64;
        
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            total_accepted += result.accepted.len() as u64;
            total_rejected += result.rejected.len() as u64;
        }
        
        let elapsed = start.elapsed();
        let throughput = (total_accepted + total_rejected) as f64 / elapsed.as_secs_f64();
        
        println!("Concurrent validation: {} receipts/sec, accepted={}, rejected={}", 
                 throughput, total_accepted, total_rejected);
        assert!(throughput > 100.0, "Should process >100 receipts/sec concurrently");
    }
}
