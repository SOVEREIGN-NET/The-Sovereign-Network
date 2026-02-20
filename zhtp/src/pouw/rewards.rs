//! Reward Calculation and Distribution (Phase 3)
//!
//! Implements reward aggregation and calculation:
//! - Epoch-based aggregation of validated receipts
//! - Proof type multipliers (Hash=1x, Merkle=2x, Signature=3x)
//! - Idempotent payout mechanism
//!
//! Reference: docs/dapps_auth/pouw-protocol-spec.md Section 9

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::types::ProofType;
use super::validation::ValidatedReceipt;

/// Epoch duration in seconds (1 hour default)
pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 3600;

/// Base reward unit (in smallest denomination, 10^-8 SOV)
pub const BASE_REWARD_UNIT: u64 = 1000;

// ─── SOV Budget Allocation ────────────────────────────────────────────────────
// Total supply:  21,000,000 SOV × 10^8 atomic units
// POUW budget:   10% of total supply over 4 years
// Per-epoch:     budget / (4 years × 8760 epochs/year) ≈ 59.93 SOV / epoch
// Per-node cap:  epoch pool / expected_active_nodes (default 100 nodes)
//                ≈ 0.599 SOV = 59,931,506 atomic units per node per epoch
// ─────────────────────────────────────────────────────────────────────────────

/// Total SOV supply in atomic units (21M SOV × 10^8)
pub const SOV_TOTAL_SUPPLY: u64 = 21_000_000 * 100_000_000;

/// POUW reward budget: 10% of total supply
pub const POUW_BUDGET_FRACTION_PERCENT: u64 = 10;

/// POUW budget vesting period in years
pub const POUW_BUDGET_YEARS: u64 = 4;

/// Total POUW allocation in atomic units
pub const POUW_TOTAL_BUDGET: u64 = SOV_TOTAL_SUPPLY / 100 * POUW_BUDGET_FRACTION_PERCENT;

/// Epochs per year (3600s epochs, 365 days)
pub const EPOCHS_PER_YEAR: u64 = 365 * 24;

/// Per-epoch pool across all nodes (atomic units)
/// = 2,100,000,000,000 / (4 × 8760) = 59,931,506 atomic units ≈ 0.599 SOV
pub const POUW_EPOCH_POOL: u64 = POUW_TOTAL_BUDGET / (POUW_BUDGET_YEARS * EPOCHS_PER_YEAR);

/// Expected active nodes at launch — used to compute per-node epoch cap
pub const EXPECTED_ACTIVE_NODES: u64 = 100;

/// Per-node cap per epoch = epoch_pool / expected_active_nodes
/// ≈ 599,315 atomic units ≈ 0.006 SOV per node per epoch
pub const POUW_PER_NODE_EPOCH_CAP: u64 = POUW_EPOCH_POOL / EXPECTED_ACTIVE_NODES;

/// Backwards-compatible alias — use POUW_PER_NODE_EPOCH_CAP for new code
pub const MAX_REWARD_PER_EPOCH: u64 = POUW_PER_NODE_EPOCH_CAP;

// ─── Anomaly Detection ────────────────────────────────────────────────────────

/// Number of past epochs to retain per-DID in memory (1 epoch = 1 hour → 24h)
pub const HISTORY_EPOCHS: usize = 24;

/// Flag a DID if it hits the per-node cap for this many consecutive epochs
pub const MAX_CONSECUTIVE_CAP_EPOCHS: usize = 12;

/// Flag a DID if its weighted receipt count is > SPIKE_FACTOR × its own recent average
pub const SPIKE_FACTOR: u64 = 3;

/// Number of epochs used for the spike baseline average (7 days)
pub const SPIKE_BASELINE_EPOCHS: usize = 7 * 24;

// ─────────────────────────────────────────────────────────────────────────────

/// Reward record stored in database
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProofTypeCounts {
    pub hash_count: u64,
    pub merkle_count: u64,
    pub signature_count: u64,
    pub web4_manifest_route_count: u64,
    pub web4_content_served_count: u64,
}

impl ProofTypeCounts {
    pub fn increment(&mut self, proof_type: ProofType) {
        match proof_type {
            ProofType::Hash => self.hash_count += 1,
            ProofType::Merkle => self.merkle_count += 1,
            ProofType::Signature => self.signature_count += 1,
            ProofType::Web4ManifestRoute => self.web4_manifest_route_count += 1,
            ProofType::Web4ContentServed => self.web4_content_served_count += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.hash_count + self.merkle_count + self.signature_count
            + self.web4_manifest_route_count + self.web4_content_served_count
    }
}

/// Payout status for a reward
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// Epoch pool configuration — controls per-node reward cap
/// Configurable for governance adjustments without recompiling.
#[derive(Debug, Clone)]
pub struct EpochPoolConfig {
    /// Total SOV emitted per epoch across all nodes (atomic units)
    pub epoch_pool: u64,
    /// Expected number of active nodes (used to derive per-node cap)
    pub expected_active_nodes: u64,
}

impl EpochPoolConfig {
    /// Default beta configuration: 10% of 21M SOV over 4 years, 100 nodes
    pub fn default_beta() -> Self {
        Self {
            epoch_pool: POUW_EPOCH_POOL,
            expected_active_nodes: EXPECTED_ACTIVE_NODES,
        }
    }

    /// Per-node cap = epoch_pool / expected_active_nodes
    pub fn per_node_cap(&self) -> u64 {
        self.epoch_pool / self.expected_active_nodes.max(1)
    }
}

/// Per-DID, per-epoch history record used for anomaly detection
#[derive(Debug, Clone)]
pub struct DIDEpochRecord {
    pub epoch: u64,
    pub weighted_receipt_count: u64,
    pub bytes_verified: u64,
    pub reward_amount: u64,
    pub hit_cap: bool,
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
    /// Epoch pool config for per-node cap calculation
    pool_config: EpochPoolConfig,
    /// Per-DID epoch history for anomaly detection (last HISTORY_EPOCHS epochs per DID)
    did_history: Arc<RwLock<HashMap<String, VecDeque<DIDEpochRecord>>>>,
    /// DIDs flagged for manual review due to anomalous reward patterns
    suspicious_dids: Arc<RwLock<HashSet<String>>>,
}

/// Configurable multipliers for proof types
#[derive(Debug, Clone)]
pub struct ProofTypeMultipliers {
    pub hash: u64,
    pub merkle: u64,
    pub signature: u64,
    pub web4_manifest_route: u64,
    pub web4_content_served: u64,
}

impl Default for ProofTypeMultipliers {
    fn default() -> Self {
        Self {
            hash: 1,
            merkle: 2,
            signature: 3,
            web4_manifest_route: 2,
            web4_content_served: 3,
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
            pool_config: EpochPoolConfig::default_beta(),
            did_history: Arc::new(RwLock::new(HashMap::new())),
            suspicious_dids: Arc::new(RwLock::new(HashSet::new())),
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

    /// Calculate reward for a client's epoch stats (sync portion — history recording is async)
    pub fn calculate_reward(&self, stats: &EpochClientStats) -> Reward {
        // Calculate weighted reward based on proof types
        let weighted_count =
            stats.proof_type_counts.hash_count * self.multipliers.hash +
            stats.proof_type_counts.merkle_count * self.multipliers.merkle +
            stats.proof_type_counts.signature_count * self.multipliers.signature +
            stats.proof_type_counts.web4_manifest_route_count * self.multipliers.web4_manifest_route +
            stats.proof_type_counts.web4_content_served_count * self.multipliers.web4_content_served;

        // Raw amount = base unit * weighted count
        let raw_amount = BASE_REWARD_UNIT * weighted_count;

        // Apply per-node epoch cap (governance-adjustable via EpochPoolConfig)
        let final_amount = raw_amount.min(self.pool_config.per_node_cap());
        let hit_cap = raw_amount > self.pool_config.per_node_cap();
        let _ = hit_cap; // used by calculate_epoch_rewards async path

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

    /// Record epoch history for a DID and run anomaly detection
    async fn record_and_check_anomalies(
        &self,
        client_did: &str,
        weighted_count: u64,
        bytes_verified: u64,
        reward_amount: u64,
        epoch: u64,
        hit_cap: bool,
        min_bytes_per_receipt: u64,
        receipt_count: u64,
    ) {
        let record = DIDEpochRecord {
            epoch,
            weighted_receipt_count: weighted_count,
            bytes_verified,
            reward_amount,
            hit_cap,
        };

        let mut history_map = self.did_history.write().await;
        let history = history_map.entry(client_did.to_string()).or_default();
        history.push_back(record);

        // Extend baseline window if needed but keep no more than SPIKE_BASELINE_EPOCHS
        let max_keep = SPIKE_BASELINE_EPOCHS.max(HISTORY_EPOCHS);
        while history.len() > max_keep {
            history.pop_front();
        }

        // ── Anomaly 1: Sustained cap-hitting ────────────────────────────────
        let recent: Vec<&DIDEpochRecord> = history.iter().rev().take(MAX_CONSECUTIVE_CAP_EPOCHS).collect();
        if recent.len() == MAX_CONSECUTIVE_CAP_EPOCHS && recent.iter().all(|r| r.hit_cap) {
            warn!(
                did = %client_did,
                consecutive_epochs = MAX_CONSECUTIVE_CAP_EPOCHS,
                "PoUW anomaly: DID hitting per-node cap every epoch (sustained cap-hitting)"
            );
            self.suspicious_dids.write().await.insert(client_did.to_string());
        }

        // ── Anomaly 2: Receipt volume spike ─────────────────────────────────
        // Compare current epoch's weighted count against the DID's own baseline average
        let baseline_epochs: Vec<&DIDEpochRecord> = history
            .iter()
            .rev()
            .skip(1) // exclude current epoch
            .take(SPIKE_BASELINE_EPOCHS)
            .collect();
        if !baseline_epochs.is_empty() {
            let baseline_sum: u64 = baseline_epochs.iter().map(|r| r.weighted_receipt_count).sum();
            let baseline_avg = baseline_sum / baseline_epochs.len() as u64;
            if baseline_avg > 0 && weighted_count > SPIKE_FACTOR * baseline_avg {
                warn!(
                    did = %client_did,
                    epoch = epoch,
                    weighted_count = weighted_count,
                    baseline_avg = baseline_avg,
                    spike_factor = SPIKE_FACTOR,
                    "PoUW anomaly: DID receipt volume spike ({}x above own average)", weighted_count / baseline_avg
                );
                self.suspicious_dids.write().await.insert(client_did.to_string());
            }
        }

        // ── Anomaly 3: Bytes uniformity (fabrication signal) ─────────────────
        // If every receipt claims exactly min_bytes_per_receipt, it's suspicious
        if receipt_count >= 3 && min_bytes_per_receipt > 0 {
            let expected_uniform = min_bytes_per_receipt * receipt_count;
            if bytes_verified == expected_uniform {
                warn!(
                    did = %client_did,
                    epoch = epoch,
                    bytes_verified = bytes_verified,
                    receipt_count = receipt_count,
                    "PoUW anomaly: all receipts claim exactly MIN_BYTES_PER_RECEIPT (fabrication signal)"
                );
                self.suspicious_dids.write().await.insert(client_did.to_string());
            }
        }
    }

    /// Get the set of DIDs flagged as suspicious for manual review
    pub async fn get_suspicious_dids(&self) -> Vec<String> {
        self.suspicious_dids.read().await.iter().cloned().collect()
    }

    /// Calculate rewards for all clients in a given epoch
    pub async fn calculate_epoch_rewards(
        &self,
        receipts: &[ValidatedReceipt],
        epoch: u64,
    ) -> Result<Vec<Reward>> {
        let aggregated = self.aggregate_receipts(receipts);
        let mut rewards = Vec::new();

        for ((_client_did, receipt_epoch), stats) in aggregated {
            if receipt_epoch == epoch {
                // Compute weighted count for anomaly detection
                let weighted_count =
                    stats.proof_type_counts.hash_count * self.multipliers.hash +
                    stats.proof_type_counts.merkle_count * self.multipliers.merkle +
                    stats.proof_type_counts.signature_count * self.multipliers.signature +
                    stats.proof_type_counts.web4_manifest_route_count * self.multipliers.web4_manifest_route +
                    stats.proof_type_counts.web4_content_served_count * self.multipliers.web4_content_served;

                let reward = self.calculate_reward(&stats);
                let hit_cap = reward.raw_amount > self.pool_config.per_node_cap();

                // Run anomaly detection — uses MIN_BYTES_PER_RECEIPT from policy default
                self.record_and_check_anomalies(
                    &stats.client_did,
                    weighted_count,
                    stats.total_bytes,
                    reward.final_amount,
                    epoch,
                    hit_cap,
                    super::types::DEFAULT_MIN_BYTES_PER_RECEIPT,
                    stats.receipt_count,
                ).await;

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

    /// Get all rewards (for stats and persistence).
    pub async fn get_all_rewards(&self) -> Vec<Reward> {
        self.rewards.read().await.clone()
    }

    /// List unique epochs that have any rewards, sorted ascending.
    pub async fn list_epochs_with_rewards(&self) -> Vec<u64> {
        let rewards = self.rewards.read().await;
        let mut epochs: Vec<u64> = rewards.iter().map(|r| r.epoch).collect();
        epochs.sort_unstable();
        epochs.dedup();
        epochs
    }

    /// Persist current rewards to a bincode file.
    ///
    /// Rewards survive node restarts when loaded back via `load_rewards_from_file`.
    /// Conventionally placed alongside blockchain.dat as rewards.dat.
    pub async fn save_rewards_to_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;
        let rewards = self.rewards.read().await.clone();
        let encoded = bincode::serialize(&rewards)
            .map_err(|e| anyhow::anyhow!("Failed to serialize rewards: {}", e))?;
        let mut file = std::fs::File::create(path)
            .map_err(|e| anyhow::anyhow!("Failed to create {}: {}", path.display(), e))?;
        file.write_all(&encoded)
            .map_err(|e| anyhow::anyhow!("Failed to write rewards file: {}", e))?;
        info!(
            path = %path.display(),
            count = rewards.len(),
            "POUW rewards saved to disk"
        );
        Ok(())
    }

    /// Load rewards from a bincode file, replacing in-memory state.
    ///
    /// Silently returns Ok if the file does not exist (first boot).
    pub async fn load_rewards_from_file(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if !path.exists() {
            info!("No rewards file at {} — starting with empty state", path.display());
            return Ok(());
        }
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;
        let loaded: Vec<Reward> = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize rewards (file may be corrupt): {}", e))?;
        let count = loaded.len();
        *self.rewards.write().await = loaded;
        info!(path = %path.display(), count = count, "POUW rewards loaded from disk");
        Ok(())
    }

    /// Derive the rewards file path from a blockchain.dat path.
    ///
    /// Example: `/data/testnet/blockchain.dat` → `/data/testnet/rewards.dat`
    pub fn rewards_path_for(blockchain_dat: &std::path::Path) -> std::path::PathBuf {
        blockchain_dat
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("rewards.dat")
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
            manifest_cid: None,
            domain: None,
            route_hops: None,
            served_from_cache: None,
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
                web4_manifest_route_count: 0,
                web4_content_served_count: 0,
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
            // Need enough receipts so raw_amount > POUW_PER_NODE_EPOCH_CAP (~59,931,506)
            // 30,000 Signature receipts × 3 multiplier × 1000 base = 90,000,000 > cap
            receipt_count: 30_000,
            proof_type_counts: ProofTypeCounts {
                hash_count: 0,
                merkle_count: 0,
                signature_count: 30_000, // 30000 * 3 * 1000 = 90_000_000 > cap
                web4_manifest_route_count: 0,
                web4_content_served_count: 0,
            },
            receipts: vec![],
        };

        let reward = calculator.calculate_reward(&stats);

        // Raw: 1000 * 90000 = 90_000_000
        // Should be capped at POUW_PER_NODE_EPOCH_CAP
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
                web4_manifest_route_count: 0,
                web4_content_served_count: 0,
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
