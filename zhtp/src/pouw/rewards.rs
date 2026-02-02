//! Reward Calculation and Distribution (Phase 3)
//!
//! Implements reward aggregation and calculation:
//! - Epoch-based aggregation of validated receipts
//! - Proof type multipliers (Hash=1x, Merkle=2x, Signature=3x)
//! - Idempotent payout mechanism
//!
//! Reference: docs/dapps_auth/pouw-protocol-spec.md Section 9

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::types::ProofType;
use super::validation::ValidatedReceipt;

/// Epoch duration in seconds (1 hour default)
pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 3600;

/// Base reward unit (in smallest denomination)
pub const BASE_REWARD_UNIT: u64 = 1000;

/// Maximum reward per epoch per client (anti-gaming cap)
pub const MAX_REWARD_PER_EPOCH: u64 = 1_000_000;

/// Reward record stored in database
#[derive(Debug, Clone)]
pub struct Reward {
    /// Unique reward ID
    pub reward_id: Vec<u8>,
    /// Client DID receiving the reward
    pub client_did: String,
    /// Epoch number this reward belongs to
    pub epoch: u64,
    /// Total bytes verified in this epoch
    pub total_bytes: u64,
    /// Breakdown by proof type
    pub proof_type_counts: ProofTypeCounts,
    /// Raw reward amount (before multipliers)
    pub raw_amount: u64,
    /// Final reward amount (after multipliers)
    pub final_amount: u64,
    /// Calculation timestamp
    pub calculated_at: u64,
    /// Payout status
    pub payout_status: PayoutStatus,
    /// Payout timestamp (if paid)
    pub paid_at: Option<u64>,
    /// Transaction hash (if paid on-chain)
    pub tx_hash: Option<Vec<u8>>,
}

/// Counts of receipts by proof type
#[derive(Debug, Clone, Default)]
pub struct ProofTypeCounts {
    pub hash_count: u64,
    pub merkle_count: u64,
    pub signature_count: u64,
}

impl ProofTypeCounts {
    pub fn increment(&mut self, proof_type: ProofType) {
        match proof_type {
            ProofType::Hash => self.hash_count += 1,
            ProofType::Merkle => self.merkle_count += 1,
            ProofType::Signature => self.signature_count += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.hash_count + self.merkle_count + self.signature_count
    }
}

/// Payout status for a reward
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutStatus {
    /// Reward calculated, not yet paid
    Pending,
    /// Payout in progress (locked)
    Processing,
    /// Payout completed
    Paid,
    /// Payout failed (will retry)
    Failed,
}

/// Aggregated stats for a client in an epoch
#[derive(Debug, Clone)]
pub struct EpochClientStats {
    pub client_did: String,
    pub epoch: u64,
    pub total_bytes: u64,
    pub receipt_count: u64,
    pub proof_type_counts: ProofTypeCounts,
    pub receipts: Vec<ValidatedReceipt>,
}

/// Reward calculator
pub struct RewardCalculator {
    /// Epoch duration in seconds
    epoch_duration_secs: u64,
    /// Genesis timestamp (epoch 0 start)
    genesis_timestamp: u64,
    /// Calculated rewards storage
    rewards: Arc<RwLock<Vec<Reward>>>,
    /// Proof type multipliers
    multipliers: ProofTypeMultipliers,
}

/// Configurable multipliers for proof types
#[derive(Debug, Clone)]
pub struct ProofTypeMultipliers {
    pub hash: u64,
    pub merkle: u64,
    pub signature: u64,
}

impl Default for ProofTypeMultipliers {
    fn default() -> Self {
        Self {
            hash: 1,
            merkle: 2,
            signature: 3,
        }
    }
}

impl RewardCalculator {
    /// Create a new reward calculator
    pub fn new(genesis_timestamp: u64) -> Self {
        Self {
            epoch_duration_secs: DEFAULT_EPOCH_DURATION_SECS,
            genesis_timestamp,
            rewards: Arc::new(RwLock::new(Vec::new())),
            multipliers: ProofTypeMultipliers::default(),
        }
    }

    /// Create with custom epoch duration
    pub fn with_epoch_duration(mut self, duration_secs: u64) -> Self {
        self.epoch_duration_secs = duration_secs;
        self
    }

    /// Create with custom multipliers
    pub fn with_multipliers(mut self, multipliers: ProofTypeMultipliers) -> Self {
        self.multipliers = multipliers;
        self
    }

    /// Get current timestamp
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Calculate current epoch number
    pub fn current_epoch(&self) -> u64 {
        let now = self.now_secs();
        if now < self.genesis_timestamp {
            return 0;
        }
        (now - self.genesis_timestamp) / self.epoch_duration_secs
    }

    /// Calculate epoch for a given timestamp
    pub fn epoch_for_timestamp(&self, timestamp: u64) -> u64 {
        if timestamp < self.genesis_timestamp {
            return 0;
        }
        (timestamp - self.genesis_timestamp) / self.epoch_duration_secs
    }

    /// Get epoch start timestamp
    pub fn epoch_start(&self, epoch: u64) -> u64 {
        self.genesis_timestamp + (epoch * self.epoch_duration_secs)
    }

    /// Get epoch end timestamp
    pub fn epoch_end(&self, epoch: u64) -> u64 {
        self.epoch_start(epoch + 1)
    }

    /// Aggregate validated receipts by client and epoch
    pub fn aggregate_receipts(&self, receipts: &[ValidatedReceipt]) -> HashMap<(String, u64), EpochClientStats> {
        let mut aggregated: HashMap<(String, u64), EpochClientStats> = HashMap::new();

        for receipt in receipts {
            let epoch = self.epoch_for_timestamp(receipt.validated_at);
            let key = (receipt.client_did.clone(), epoch);

            let stats = aggregated.entry(key).or_insert_with(|| EpochClientStats {
                client_did: receipt.client_did.clone(),
                epoch,
                total_bytes: 0,
                receipt_count: 0,
                proof_type_counts: ProofTypeCounts::default(),
                receipts: Vec::new(),
            });

            stats.total_bytes += receipt.bytes_verified;
            stats.receipt_count += 1;
            stats.proof_type_counts.increment(receipt.proof_type);
            stats.receipts.push(receipt.clone());
        }

        aggregated
    }

    /// Calculate reward for a client's epoch stats
    pub fn calculate_reward(&self, stats: &EpochClientStats) -> Reward {
        // Calculate weighted reward based on proof types
        let weighted_count = 
            stats.proof_type_counts.hash_count * self.multipliers.hash +
            stats.proof_type_counts.merkle_count * self.multipliers.merkle +
            stats.proof_type_counts.signature_count * self.multipliers.signature;

        // Raw amount = base unit * weighted count
        let raw_amount = BASE_REWARD_UNIT * weighted_count;

        // Apply cap
        let final_amount = raw_amount.min(MAX_REWARD_PER_EPOCH);

        // Generate reward ID
        let mut reward_id = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut reward_id);

        info!(
            client = %stats.client_did,
            epoch = stats.epoch,
            receipts = stats.receipt_count,
            total_bytes = stats.total_bytes,
            raw_amount = raw_amount,
            final_amount = final_amount,
            "Reward calculated"
        );

        Reward {
            reward_id,
            client_did: stats.client_did.clone(),
            epoch: stats.epoch,
            total_bytes: stats.total_bytes,
            proof_type_counts: stats.proof_type_counts.clone(),
            raw_amount,
            final_amount,
            calculated_at: self.now_secs(),
            payout_status: PayoutStatus::Pending,
            paid_at: None,
            tx_hash: None,
        }
    }

    /// Calculate rewards for all clients in a given epoch
    pub async fn calculate_epoch_rewards(
        &self,
        receipts: &[ValidatedReceipt],
        epoch: u64,
    ) -> Result<Vec<Reward>> {
        let aggregated = self.aggregate_receipts(receipts);
        let mut rewards = Vec::new();

        for ((client_did, receipt_epoch), stats) in aggregated {
            if receipt_epoch == epoch {
                let reward = self.calculate_reward(&stats);
                rewards.push(reward.clone());

                // Store reward
                self.rewards.write().await.push(reward);
            }
        }

        info!(
            epoch = epoch,
            reward_count = rewards.len(),
            "Epoch rewards calculated"
        );

        Ok(rewards)
    }

    /// Get all pending rewards for payout
    pub async fn get_pending_rewards(&self) -> Vec<Reward> {
        self.rewards.read().await
            .iter()
            .filter(|r| r.payout_status == PayoutStatus::Pending)
            .cloned()
            .collect()
    }

    /// Mark reward as processing (locked for payout)
    pub async fn mark_processing(&self, reward_id: &[u8]) -> bool {
        let mut rewards = self.rewards.write().await;
        for reward in rewards.iter_mut() {
            if reward.reward_id == reward_id && reward.payout_status == PayoutStatus::Pending {
                reward.payout_status = PayoutStatus::Processing;
                return true;
            }
        }
        false
    }

    /// Mark reward as paid (idempotent)
    pub async fn mark_paid(&self, reward_id: &[u8], tx_hash: Option<Vec<u8>>) -> bool {
        let mut rewards = self.rewards.write().await;
        for reward in rewards.iter_mut() {
            if reward.reward_id == reward_id {
                match reward.payout_status {
                    PayoutStatus::Processing => {
                        reward.payout_status = PayoutStatus::Paid;
                        reward.paid_at = Some(self.now_secs());
                        reward.tx_hash = tx_hash;
                        return true;
                    }
                    PayoutStatus::Paid => {
                        // Already paid - idempotent success
                        return true;
                    }
                    _ => return false,
                }
            }
        }
        false
    }

    /// Mark reward as failed (will retry)
    pub async fn mark_failed(&self, reward_id: &[u8]) -> bool {
        let mut rewards = self.rewards.write().await;
        for reward in rewards.iter_mut() {
            if reward.reward_id == reward_id && reward.payout_status == PayoutStatus::Processing {
                reward.payout_status = PayoutStatus::Failed;
                return true;
            }
        }
        false
    }

    /// Reset failed rewards to pending for retry
    pub async fn reset_failed_rewards(&self) -> usize {
        let mut rewards = self.rewards.write().await;
        let mut count = 0;
        for reward in rewards.iter_mut() {
            if reward.payout_status == PayoutStatus::Failed {
                reward.payout_status = PayoutStatus::Pending;
                count += 1;
            }
        }
        count
    }

    /// Get rewards for a specific client
    pub async fn get_client_rewards(&self, client_did: &str) -> Vec<Reward> {
        self.rewards.read().await
            .iter()
            .filter(|r| r.client_did == client_did)
            .cloned()
            .collect()
    }

    /// Get rewards for a specific epoch
    pub async fn get_epoch_rewards(&self, epoch: u64) -> Vec<Reward> {
        self.rewards.read().await
            .iter()
            .filter(|r| r.epoch == epoch)
            .cloned()
            .collect()
    }

    /// Get total rewards paid
    pub async fn total_paid_rewards(&self) -> u64 {
        self.rewards.read().await
            .iter()
            .filter(|r| r.payout_status == PayoutStatus::Paid)
            .map(|r| r.final_amount)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_receipt(client_did: &str, proof_type: ProofType, bytes: u64, timestamp: u64) -> ValidatedReceipt {
        ValidatedReceipt {
            receipt_nonce: vec![1u8; 32],
            client_did: client_did.to_string(),
            task_id: vec![2u8; 16],
            proof_type,
            bytes_verified: bytes,
            validated_at: timestamp,
            challenge_nonce: vec![3u8; 32],
        }
    }

    #[test]
    fn test_epoch_calculation() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        assert_eq!(calculator.epoch_for_timestamp(genesis), 0);
        assert_eq!(calculator.epoch_for_timestamp(genesis + 3599), 0);
        assert_eq!(calculator.epoch_for_timestamp(genesis + 3600), 1);
        assert_eq!(calculator.epoch_for_timestamp(genesis + 7200), 2);
    }

    #[test]
    fn test_epoch_boundaries() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        assert_eq!(calculator.epoch_start(0), genesis);
        assert_eq!(calculator.epoch_end(0), genesis + 3600);
        assert_eq!(calculator.epoch_start(1), genesis + 3600);
    }

    #[test]
    fn test_receipt_aggregation() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        let receipts = vec![
            create_test_receipt("did:zhtp:alice", ProofType::Hash, 1024, genesis + 100),
            create_test_receipt("did:zhtp:alice", ProofType::Hash, 2048, genesis + 200),
            create_test_receipt("did:zhtp:alice", ProofType::Merkle, 1024, genesis + 300),
            create_test_receipt("did:zhtp:bob", ProofType::Hash, 1024, genesis + 100),
        ];

        let aggregated = calculator.aggregate_receipts(&receipts);

        // Alice should have 3 receipts in epoch 0
        let alice_stats = aggregated.get(&("did:zhtp:alice".to_string(), 0)).unwrap();
        assert_eq!(alice_stats.receipt_count, 3);
        assert_eq!(alice_stats.total_bytes, 1024 + 2048 + 1024);
        assert_eq!(alice_stats.proof_type_counts.hash_count, 2);
        assert_eq!(alice_stats.proof_type_counts.merkle_count, 1);

        // Bob should have 1 receipt
        let bob_stats = aggregated.get(&("did:zhtp:bob".to_string(), 0)).unwrap();
        assert_eq!(bob_stats.receipt_count, 1);
    }

    #[test]
    fn test_reward_calculation() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        let stats = EpochClientStats {
            client_did: "did:zhtp:alice".to_string(),
            epoch: 0,
            total_bytes: 4096,
            receipt_count: 4,
            proof_type_counts: ProofTypeCounts {
                hash_count: 2,     // 2 * 1 = 2
                merkle_count: 1,   // 1 * 2 = 2
                signature_count: 1, // 1 * 3 = 3
            },
            receipts: vec![],
        };

        let reward = calculator.calculate_reward(&stats);

        // Weighted: 2*1 + 1*2 + 1*3 = 7
        // Raw amount: 1000 * 7 = 7000
        assert_eq!(reward.raw_amount, 7000);
        assert_eq!(reward.final_amount, 7000); // Below cap
        assert_eq!(reward.payout_status, PayoutStatus::Pending);
    }

    #[test]
    fn test_reward_cap() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        let stats = EpochClientStats {
            client_did: "did:zhtp:whale".to_string(),
            epoch: 0,
            total_bytes: 1_000_000_000,
            receipt_count: 10000,
            proof_type_counts: ProofTypeCounts {
                hash_count: 0,
                merkle_count: 0,
                signature_count: 10000, // 10000 * 3 = 30000 weighted
            },
            receipts: vec![],
        };

        let reward = calculator.calculate_reward(&stats);

        // Raw: 1000 * 30000 = 30_000_000
        // Should be capped at MAX_REWARD_PER_EPOCH
        assert!(reward.raw_amount > MAX_REWARD_PER_EPOCH);
        assert_eq!(reward.final_amount, MAX_REWARD_PER_EPOCH);
    }

    #[tokio::test]
    async fn test_payout_state_machine() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        let stats = EpochClientStats {
            client_did: "did:zhtp:alice".to_string(),
            epoch: 0,
            total_bytes: 1024,
            receipt_count: 1,
            proof_type_counts: ProofTypeCounts {
                hash_count: 1,
                merkle_count: 0,
                signature_count: 0,
            },
            receipts: vec![],
        };

        let reward = calculator.calculate_reward(&stats);
        let reward_id = reward.reward_id.clone();
        calculator.rewards.write().await.push(reward);

        // Should be pending
        let pending = calculator.get_pending_rewards().await;
        assert_eq!(pending.len(), 1);

        // Mark as processing
        assert!(calculator.mark_processing(&reward_id).await);

        // Should not be in pending anymore
        let pending = calculator.get_pending_rewards().await;
        assert_eq!(pending.len(), 0);

        // Mark as paid
        assert!(calculator.mark_paid(&reward_id, Some(vec![0xAB; 32])).await);

        // Idempotent - marking paid again should succeed
        assert!(calculator.mark_paid(&reward_id, None).await);

        // Total paid should be the reward amount
        assert_eq!(calculator.total_paid_rewards().await, 1000);
    }

    #[tokio::test]
    async fn test_failed_reward_retry() {
        let genesis = 1700000000u64;
        let calculator = RewardCalculator::new(genesis);

        let stats = EpochClientStats {
            client_did: "did:zhtp:alice".to_string(),
            epoch: 0,
            total_bytes: 1024,
            receipt_count: 1,
            proof_type_counts: ProofTypeCounts::default(),
            receipts: vec![],
        };

        let reward = calculator.calculate_reward(&stats);
        let reward_id = reward.reward_id.clone();
        calculator.rewards.write().await.push(reward);

        // Process and fail
        calculator.mark_processing(&reward_id).await;
        calculator.mark_failed(&reward_id).await;

        // Should not be pending
        assert_eq!(calculator.get_pending_rewards().await.len(), 0);

        // Reset failed
        let reset_count = calculator.reset_failed_rewards().await;
        assert_eq!(reset_count, 1);

        // Should be pending again
        assert_eq!(calculator.get_pending_rewards().await.len(), 1);
    }
}
