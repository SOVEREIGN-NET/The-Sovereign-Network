//! SOV Staking Contract for DAO Launches
//!
//! This contract implements the staking mechanism for launching new DAOs.
//! Citizens stake SOV towards a pending DAO, and when the threshold is reached,
//! the DAO launches automatically with stakers receiving proportional DAO tokens.
//!
//! # Two-Layer Threshold Model
//!
//! **Layer 1: Global Guardrails** (Protocol Level)
//! - Hard minimums and maximums enforced at protocol level
//! - Prevents Sybil attacks (minimum: 10,000 SOV)
//! - Prevents plutocratic capture (maximum: 10,000,000 SOV)
//!
//! **Layer 2: Per-DAO Configurable Thresholds**
//! - Each DAO defines threshold within global bounds
//! - Non-Profit DAOs: Recommended ~50,000 SOV
//! - For-Profit DAOs: Recommended ~200,000 SOV

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;
use blake3;

/// Global protocol-level guardrails for staking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStakingGuardrails {
    /// Absolute minimum threshold (prevents spam DAOs)
    pub min_threshold: u64,
    /// Absolute maximum threshold (prevents plutocratic capture)
    pub max_threshold: u64,
    /// Governance address for guardrail updates
    pub governance_addr: PublicKey,
}

impl Default for GlobalStakingGuardrails {
    fn default() -> Self {
        Self {
            min_threshold: 10_000_00000000,    // 10,000 SOV (8 decimals)
            max_threshold: 10_000_000_00000000, // 10,000,000 SOV (8 decimals)
            governance_addr: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
        }
    }
}

/// Pending DAO awaiting staking threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDao {
    pub dao_id: [u8; 32],
    pub dao_type: DAOType,
    pub token_name: String,
    pub token_symbol: String,
    /// Per-DAO threshold (must be within global bounds)
    pub threshold_sov: u64,
    /// Minimum number of stakers required
    pub min_stakers: u32,
    /// Deadline for this DAO launch
    pub deadline_height: u64,
    /// Total SOV staked so far
    pub total_staked: u64,
    /// Number of stakers
    pub staker_count: u32,
    /// DAO creator
    pub creator: PublicKey,
    /// Metadata hash (mission, description, etc)
    pub metadata_hash: [u8; 32],
    /// Timestamp when DAO was created
    pub created_height: u64,
}

/// Staking position by a citizen towards a pending DAO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingPosition {
    pub staker: PublicKey,
    pub amount: u64,
    pub staked_at_height: u64,
    /// Whether this position has been claimed (after launch)
    pub claimed: bool,
}

/// Launched DAO (for reference by staking positions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchedDao {
    pub dao_id: [u8; 32],
    pub token_addr: PublicKey,
    pub treasury_addr: PublicKey,
    pub total_staked_sov: u64,
    pub launch_height: u64,
}

/// Main staking contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovDaoStaking {
    /// Global guardrails (protocol-level)
    pub guardrails: GlobalStakingGuardrails,

    /// All pending DAOs
    pub pending_daos: Vec<PendingDao>,

    /// Staking positions per pending DAO
    /// Key: DAO ID, Value: Vector of staking positions
    pub positions: HashMap<[u8; 32], Vec<StakingPosition>>,

    /// Launched DAOs (for unstaking reference)
    pub launched_daos: HashMap<[u8; 32], LaunchedDao>,

    /// Total SOV locked in staking contract
    pub total_staked_sov: u64,
}

impl SovDaoStaking {
    /// Create a new staking contract with default guardrails
    pub fn new(governance_addr: PublicKey) -> Self {
        let mut guardrails = GlobalStakingGuardrails::default();
        guardrails.governance_addr = governance_addr;
        Self {
            guardrails,
            pending_daos: Vec::new(),
            positions: HashMap::new(),
            launched_daos: HashMap::new(),
            total_staked_sov: 0,
        }
    }

    /// Create a new pending DAO for staking
    ///
    /// # Validation
    /// - threshold_sov must be within global bounds
    /// - min_stakers >= 10
    /// - deadline between 30 and 365 days (in blocks, assuming 10s blocks)
    pub fn create_pending_dao(
        &mut self,
        dao_type: DAOType,
        token_name: String,
        token_symbol: String,
        threshold_sov: u64,
        min_stakers: u32,
        deadline_blocks: u64,
        metadata_hash: [u8; 32],
        caller: PublicKey,
        current_height: u64,
    ) -> Result<[u8; 32]> {
        // Validate threshold against global guardrails
        if threshold_sov < self.guardrails.min_threshold {
            return Err(anyhow!(
                "Threshold {} below minimum {}",
                threshold_sov,
                self.guardrails.min_threshold
            ));
        }
        if threshold_sov > self.guardrails.max_threshold {
            return Err(anyhow!(
                "Threshold {} exceeds maximum {}",
                threshold_sov,
                self.guardrails.max_threshold
            ));
        }

        // Validate min stakers (at least 10)
        if min_stakers < 10 {
            return Err(anyhow!("Min stakers must be at least 10, got {}", min_stakers));
        }

        // Validate deadline (30-365 days, assuming ~8,640 blocks per day)
        let min_deadline_blocks = 30 * 8_640; // ~30 days
        let max_deadline_blocks = 365 * 8_640; // ~365 days
        if deadline_blocks < min_deadline_blocks || deadline_blocks > max_deadline_blocks {
            return Err(anyhow!(
                "Deadline must be 30-365 days, got {} blocks",
                deadline_blocks
            ));
        }

        // Derive deterministic DAO ID from inputs using BLAKE3
        let dao_id = derive_pending_dao_id(
            &token_name,
            &token_symbol,
            threshold_sov,
            &metadata_hash,
            &caller.key_id,
        );

        // Check DAO doesn't already exist
        if self.pending_daos.iter().any(|d| d.dao_id == dao_id) {
            return Err(anyhow!("DAO with this ID already exists"));
        }
        if self.launched_daos.contains_key(&dao_id) {
            return Err(anyhow!("Launched DAO with this ID already exists"));
        }

        let pending_dao = PendingDao {
            dao_id,
            dao_type,
            token_name,
            token_symbol,
            threshold_sov,
            min_stakers,
            deadline_height: current_height + deadline_blocks,
            total_staked: 0,
            staker_count: 0,
            creator: caller,
            metadata_hash,
            created_height: current_height,
        };

        self.pending_daos.push(pending_dao);
        self.positions.insert(dao_id, Vec::new());

        Ok(dao_id)
    }

    /// Stake SOV towards a pending DAO
    ///
    /// # Validation
    /// - DAO must be pending (not launched, not expired)
    /// - Minimum stake: 1,000 SOV per position
    pub fn stake_for_dao(
        &mut self,
        dao_id: [u8; 32],
        amount: u64,
        caller: PublicKey,
        current_height: u64,
    ) -> Result<()> {
        // Validate DAO exists and is pending
        let dao_idx = self
            .pending_daos
            .iter()
            .position(|d| d.dao_id == dao_id)
            .ok_or_else(|| anyhow!("Pending DAO not found"))?;

        let dao = &self.pending_daos[dao_idx];

        // Check not expired
        if current_height >= dao.deadline_height {
            return Err(anyhow!("DAO staking deadline has passed"));
        }

        // Validate minimum stake (1,000 SOV with 8 decimals = 100,000,000)
        let min_stake = 1_000_00000000;
        if amount < min_stake {
            return Err(anyhow!(
                "Minimum stake is {} SOV, got {}",
                min_stake / 100000000,
                amount / 100000000
            ));
        }

        // Check if staker already has position for this DAO
        let positions = self.positions.entry(dao_id).or_insert_with(Vec::new);
        let existing_pos = positions.iter_mut().find(|p| p.staker == caller);

        if let Some(pos) = existing_pos {
            // Add to existing position
            pos.amount = pos.amount.checked_add(amount)
                .ok_or_else(|| anyhow!("Stake amount overflow"))?;
        } else {
            // Create new position
            positions.push(StakingPosition {
                staker: caller,
                amount,
                staked_at_height: current_height,
                claimed: false,
            });

            // Increment staker count
            self.pending_daos[dao_idx].staker_count += 1;
        }

        // Update DAO total staked
        self.pending_daos[dao_idx].total_staked = self.pending_daos[dao_idx]
            .total_staked
            .checked_add(amount)
            .ok_or_else(|| anyhow!("Total staked overflow"))?;

        // Update contract total
        self.total_staked_sov = self.total_staked_sov
            .checked_add(amount)
            .ok_or_else(|| anyhow!("Total SOV locked overflow"))?;

        // Try to auto-launch if threshold reached
        self.try_launch_dao(dao_id, current_height)?;

        Ok(())
    }

    /// Try to launch a DAO if threshold is met
    fn try_launch_dao(&mut self, dao_id: [u8; 32], current_height: u64) -> Result<()> {
        // Find DAO
        let dao_idx = match self.pending_daos.iter().position(|d| d.dao_id == dao_id) {
            Some(idx) => idx,
            None => return Ok(()), // DAO not found, silently return
        };

        let dao = self.pending_daos[dao_idx].clone();

        // Check if threshold met AND min stakers met
        if dao.total_staked >= dao.threshold_sov && dao.staker_count >= dao.min_stakers {
            // Launch the DAO
            let token_addr = derive_token_address(&dao, current_height);
            let treasury_addr = derive_treasury_address(&dao, current_height);

            let launched_dao = LaunchedDao {
                dao_id,
                token_addr,
                treasury_addr,
                total_staked_sov: dao.total_staked,
                launch_height: current_height,
            };

            // Move from pending to launched
            self.launched_daos.insert(dao_id, launched_dao);
            self.pending_daos.remove(dao_idx);
        }

        Ok(())
    }

    /// Claim DAO tokens for a staker after DAO launch
    pub fn claim_dao_tokens(
        &mut self,
        dao_id: [u8; 32],
        caller: PublicKey,
    ) -> Result<u64> {
        // Verify DAO is launched
        let _launched_dao = self
            .launched_daos
            .get(&dao_id)
            .ok_or_else(|| anyhow!("DAO not launched yet"))?;

        // Find staker position
        let positions = self
            .positions
            .get_mut(&dao_id)
            .ok_or_else(|| anyhow!("No staking positions for this DAO"))?;

        let position = positions
            .iter_mut()
            .find(|p| p.staker == caller)
            .ok_or_else(|| anyhow!("Staker not found for this DAO"))?;

        if position.claimed {
            return Err(anyhow!("Tokens already claimed"));
        }

        // Calculate staker's share of DAO tokens.
        //
        // Current economics: the DAO mints governance tokens at a 1:1 ratio
        // with SOV staked. That is, `total_dao_tokens == total_staked_sov`,
        // so the proportional formula:
        //
        //     (staker_amount / total_staked_sov) * total_dao_tokens
        //
        // simplifies to `staker_amount`. We therefore return the staker's
        // original stake amount as the DAO token allocation.
        let staker_share = position.amount;
        let tokens_to_receive = staker_share;

        position.claimed = true;

        Ok(tokens_to_receive)
    }

    /// Unstake from a failed DAO (deadline passed without threshold)
    pub fn unstake_failed_dao(
        &mut self,
        dao_id: [u8; 32],
        caller: PublicKey,
        current_height: u64,
    ) -> Result<u64> {
        // Find pending DAO
        let dao_idx = self
            .pending_daos
            .iter()
            .position(|d| d.dao_id == dao_id)
            .ok_or_else(|| anyhow!("Pending DAO not found"))?;

        let dao = &self.pending_daos[dao_idx];

        // Check deadline passed
        if current_height <= dao.deadline_height {
            return Err(anyhow!("DAO staking deadline not passed yet"));
        }

        // Check threshold not met
        if dao.total_staked >= dao.threshold_sov && dao.staker_count >= dao.min_stakers {
            return Err(anyhow!("DAO threshold was met - cannot unstake"));
        }

        // Find staker position
        let positions = self
            .positions
            .get_mut(&dao_id)
            .ok_or_else(|| anyhow!("No staking positions for this DAO"))?;

        let position = positions
            .iter_mut()
            .find(|p| p.staker == caller && !p.claimed)
            .ok_or_else(|| anyhow!("Staker not found or already claimed"))?;

        let amount_to_return = position.amount;
        position.claimed = true; // Mark as processed to prevent double-unstaking

        // Update totals
        self.total_staked_sov = self.total_staked_sov.saturating_sub(amount_to_return);

        Ok(amount_to_return)
    }

    /// Get pending DAO by ID
    pub fn get_pending_dao(&self, dao_id: [u8; 32]) -> Option<&PendingDao> {
        self.pending_daos.iter().find(|d| d.dao_id == dao_id)
    }

    /// Get launched DAO by ID
    pub fn get_launched_dao(&self, dao_id: [u8; 32]) -> Option<&LaunchedDao> {
        self.launched_daos.get(&dao_id)
    }

    /// Get staking positions for a DAO
    pub fn get_dao_positions(&self, dao_id: [u8; 32]) -> Vec<StakingPosition> {
        self.positions
            .get(&dao_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get staker's position in a DAO
    pub fn get_staker_position(
        &self,
        dao_id: [u8; 32],
        staker: &PublicKey,
    ) -> Option<StakingPosition> {
        self.positions
            .get(&dao_id)?
            .iter()
            .find(|p| p.staker == *staker)
            .cloned()
    }

    /// Get all pending DAOs
    pub fn get_pending_daos(&self) -> Vec<PendingDao> {
        self.pending_daos.clone()
    }

    /// Get count of pending DAOs
    pub fn pending_dao_count(&self) -> usize {
        self.pending_daos.len()
    }

    /// Get count of launched DAOs
    pub fn launched_dao_count(&self) -> usize {
        self.launched_daos.len()
    }
}

impl Default for SovDaoStaking {
    fn default() -> Self {
        Self::new(PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        })
    }
}

/// Derive deterministic DAO ID from inputs using BLAKE3
fn derive_pending_dao_id(
    token_name: &str,
    token_symbol: &str,
    threshold: u64,
    metadata_hash: &[u8; 32],
    creator_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pending_dao");
    hasher.update(token_name.as_bytes());
    hasher.update(token_symbol.as_bytes());
    hasher.update(&threshold.to_le_bytes());
    hasher.update(metadata_hash);
    hasher.update(creator_key);
    let hash: [u8; 32] = hasher.finalize().into();
    hash
}

/// Derive deterministic token address for launched DAO
fn derive_token_address(dao: &PendingDao, current_height: u64) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"token_addr");
    hasher.update(&dao.dao_id);
    hasher.update(&current_height.to_le_bytes());
    let key_id: [u8; 32] = hasher.finalize().into();
    PublicKey {
        dilithium_pk: vec![key_id[0]; 32],
        kyber_pk: vec![key_id[1]; 32],
        key_id,
    }
}

/// Derive deterministic treasury address for launched DAO
fn derive_treasury_address(dao: &PendingDao, current_height: u64) -> PublicKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"treasury_addr");
    hasher.update(&dao.dao_id);
    hasher.update(&current_height.to_le_bytes());
    let key_id: [u8; 32] = hasher.finalize().into();
    PublicKey {
        dilithium_pk: vec![key_id[0]; 32],
        kyber_pk: vec![key_id[1]; 32],
        key_id,
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id; 32],
            kyber_pk: vec![id; 32],
            key_id: [id; 32],
        }
    }

    #[test]
    fn test_create_pending_dao() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Health Coalition".to_string(),
                "HEALTH".to_string(),
                50_000_00000000, // 50,000 SOV
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        assert_eq!(staking.pending_dao_count(), 1);
        assert!(staking.get_pending_dao(dao_id).is_some());
    }

    #[test]
    fn test_threshold_below_minimum_fails() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);

        let result = staking.create_pending_dao(
            DAOType::NP,
            "Low Stake DAO".to_string(),
            "LOW".to_string(),
            1_00000000, // 1 SOV (below minimum)
            10,
            30 * 8_640,
            [1u8; 32],
            creator,
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_stake_for_dao() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);
        let staker = test_public_key(2);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Health Coalition".to_string(),
                "HEALTH".to_string(),
                50_000_00000000,
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        staking
            .stake_for_dao(dao_id, 10_000_00000000, staker.clone(), 101)
            .unwrap();

        let dao = staking.get_pending_dao(dao_id).unwrap();
        assert_eq!(dao.total_staked, 10_000_00000000);
        assert_eq!(dao.staker_count, 1);
    }

    #[test]
    fn test_multiple_stakers_reach_threshold() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Health Coalition".to_string(),
                "HEALTH".to_string(),
                50_000_00000000, // 50,000 SOV threshold
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        // Add 10 stakers with 5,000 SOV each = 50,000 total (exactly threshold)
        for i in 2..12u8 {
            staking
                .stake_for_dao(dao_id, 5_000_00000000, test_public_key(i), 101 + i as u64)
                .unwrap();
        }

        // DAO should now be launched
        assert_eq!(staking.pending_dao_count(), 0);
        assert_eq!(staking.launched_dao_count(), 1);
        assert!(staking.get_launched_dao(dao_id).is_some());
    }

    #[test]
    fn test_claim_dao_tokens() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);
        let _staker = test_public_key(2);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Health Coalition".to_string(),
                "HEALTH".to_string(),
                50_000_00000000,
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        // Add 10 stakers to trigger launch
        for i in 2..12u8 {
            staking
                .stake_for_dao(dao_id, 5_000_00000000, test_public_key(i), 101 + i as u64)
                .unwrap();
        }

        // First staker claims tokens
        let tokens = staking.claim_dao_tokens(dao_id, test_public_key(2)).unwrap();
        assert_eq!(tokens, 5_000_00000000); // 1:1 ratio
    }

    #[test]
    fn test_unstake_failed_dao() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);
        let staker = test_public_key(2);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Low Support DAO".to_string(),
                "LOW".to_string(),
                50_000_00000000,
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        // Add only 1 staker (doesn't meet min_stakers of 10)
        staking
            .stake_for_dao(dao_id, 10_000_00000000, staker.clone(), 101)
            .unwrap();

        let deadline = staking.get_pending_dao(dao_id).unwrap().deadline_height;

        // Try to unstake after deadline
        let amount = staking
            .unstake_failed_dao(dao_id, staker, deadline + 1)
            .unwrap();
        assert_eq!(amount, 10_000_00000000);
    }

    #[test]
    fn test_staker_cannot_claim_twice() {
        let mut staking = SovDaoStaking::default();
        let creator = test_public_key(1);

        let dao_id = staking
            .create_pending_dao(
                DAOType::NP,
                "Health Coalition".to_string(),
                "HEALTH".to_string(),
                50_000_00000000,
                10,
                30 * 8_640,
                [1u8; 32],
                creator,
                100,
            )
            .unwrap();

        // Add 10 stakers to trigger launch
        for i in 2..12u8 {
            staking
                .stake_for_dao(dao_id, 5_000_00000000, test_public_key(i), 101 + i as u64)
                .unwrap();
        }

        let staker = test_public_key(2);

        // Claim once
        staking.claim_dao_tokens(dao_id, staker.clone()).unwrap();

        // Try to claim again
        let result = staking.claim_dao_tokens(dao_id, staker);
        assert!(result.is_err());
    }
}
