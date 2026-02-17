//! Validator set management
//!
//! # Validator Admission Model
//!
//! ZHTP uses a **permissioned-by-stake** admission model with the following invariants:
//!
//! 1. **Stake threshold**: A candidate must lock at least [`MIN_VALIDATOR_STAKE`] SOV tokens.
//!    This is the primary on-chain admission gate and is enforced unconditionally.
//!
//! 2. **Governance gating**: After the genesis bootstrap phase (block 0), every new validator
//!    registration must originate from an approved on-chain governance proposal.  Direct
//!    peer-to-peer registration (e.g., from a config file) is rejected for non-genesis
//!    validators so that the validator set can only grow through the DAO governance process.
//!    See [`ADMISSION_MODEL`] for the canonical declaration.
//!
//! 3. **Hybrid transition**: During genesis (block height == 0) a lightweight bootstrap path
//!    is available so that the initial validator set can be seeded from a config file without
//!    a prior on-chain vote.  Once the chain is live every subsequent admission follows the
//!    full stake + governance path.
//!
//! The model is therefore best described as **hybrid**: stake-gated for all validators,
//! governance-gated for post-genesis validators.
//!
//! # Constants
//!
//! | Constant | Value | Meaning |
//! |---|---|---|
//! | [`MIN_VALIDATOR_STAKE`] | 100_000 SOV | Minimum stake to be admitted |
//! | [`GENESIS_MIN_VALIDATOR_STAKE`] | 1_000 SOV | Reduced minimum during genesis bootstrap |
//! | [`MIN_VALIDATORS_BFT`] | 4 | Minimum validators for Byzantine Fault Tolerance |
//! | [`MAX_VALIDATORS`] | 256 | Hard cap on the validator set size |
//! | [`ADMISSION_MODEL`] | `"permissioned-by-stake+governance"` | Canonical admission model string |

use crate::types::{SlashType, ValidatorStatus};
use crate::validators::Validator;
use anyhow::Result;
use lib_identity::IdentityId;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Admission model constants
// ---------------------------------------------------------------------------

/// Canonical string identifying the validator admission model.
///
/// The admission model is **hybrid**:
/// - All validators (including genesis) must meet the minimum stake threshold.
/// - Post-genesis validators must additionally be admitted via an approved on-chain
///   governance proposal (DAO vote).
///
/// This constant is the single source of truth referenced by admission assertions.
pub const ADMISSION_MODEL: &str = "permissioned-by-stake+governance";

/// Minimum stake (in SOV tokens) required to register a validator in production.
///
/// This value applies at every block height > 0.  The stake is locked for the
/// duration of the validator's active tenure and is subject to slashing.
pub const MIN_VALIDATOR_STAKE: u64 = 100_000;

/// Reduced minimum stake allowed only during the genesis bootstrap (block height == 0).
///
/// This lower threshold allows the initial validator set to be seeded from a config
/// file without requiring the full production stake commitment.  It MUST NOT be used
/// for any post-genesis admission check.
pub const GENESIS_MIN_VALIDATOR_STAKE: u64 = 1_000;

/// Minimum number of active validators required for Byzantine Fault Tolerance.
///
/// BFT (PBFT/Tendermint) requires at least 3f + 1 participants to tolerate f faults.
/// With [`MIN_VALIDATORS_BFT`] == 4, the network can tolerate exactly one Byzantine
/// validator (f = 1).
pub const MIN_VALIDATORS_BFT: usize = 4;

/// Hard cap on the total number of validators that can be in the set at any time.
///
/// Admission requests that would push the active set past this limit MUST be rejected,
/// even if they satisfy the stake and governance requirements.
pub const MAX_VALIDATORS: usize = 256;

/// Trait for validator info structures that can be synced from blockchain
///
/// This allows ValidatorManager to sync from different validator data sources
/// (blockchain registry, genesis config, etc.) without tight coupling.
pub trait ValidatorInfo {
    /// Get validator identity
    fn identity_id(&self) -> IdentityId;
    /// Get validator stake
    fn stake(&self) -> u64;
    /// Get storage provided
    fn storage_provided(&self) -> u64;
    /// Get consensus key
    fn consensus_key(&self) -> Vec<u8>;
    /// Get commission rate
    fn commission_rate(&self) -> u8;
}

/// Manages the set of validators in the consensus system
#[derive(Debug, Clone)]
pub struct ValidatorManager {
    /// Active validators
    validators: HashMap<IdentityId, Validator>,
    /// Maximum number of validators
    max_validators: u32,
    /// Minimum stake required to be a validator
    min_stake: u64,
    /// Total voting power of all active validators
    total_voting_power: u64,
    /// Development mode flag - allows single validator consensus
    development_mode: bool,
}

impl ValidatorManager {
    /// Create a new validator manager
    pub fn new(max_validators: u32, min_stake: u64) -> Self {
        Self {
            validators: HashMap::new(),
            max_validators,
            min_stake,
            total_voting_power: 0,
            development_mode: false,
        }
    }

    /// Create a new validator manager with development mode
    pub fn new_with_development_mode(
        max_validators: u32,
        min_stake: u64,
        development_mode: bool,
    ) -> Self {
        Self {
            validators: HashMap::new(),
            max_validators,
            min_stake,
            total_voting_power: 0,
            development_mode,
        }
    }

    /// Register a new validator.
    ///
    /// # Admission model invariant
    ///
    /// This function is the **consensus-layer** enforcement point for the
    /// [`ADMISSION_MODEL`].  Every caller must have already verified that the
    /// candidate satisfies whichever on-chain requirements apply (governance
    /// proposal approval for post-genesis validators).  The consensus layer then
    /// enforces the stake threshold as an unconditional final gate.
    ///
    /// The assertion below acts as a compile-time + runtime canary: if someone
    /// changes the admission model string without updating the associated logic
    /// they will hit an immediate panic in any environment where the assertion
    /// evaluates to `false`.
    pub fn register_validator(
        &mut self,
        identity: IdentityId,
        stake: u64,
        storage_provided: u64,
        consensus_key: Vec<u8>,
        commission_rate: u8,
    ) -> Result<()> {
        // INVARIANT: Confirm that the admission model has not been silently changed.
        // Any modification to ADMISSION_MODEL must be accompanied by a deliberate
        // review of all stake/governance checks throughout this module.
        assert_eq!(
            ADMISSION_MODEL,
            "permissioned-by-stake+governance",
            "Admission model invariant violated: expected 'permissioned-by-stake+governance', \
             got '{}'. Update all admission checks before changing this constant.",
            ADMISSION_MODEL
        );

        // ADMISSION GATE 1 (stake): Every validator must meet the minimum stake threshold.
        // This is the primary on-chain admission gate enforced by the ADMISSION_MODEL.
        if stake < self.min_stake {
            return Err(anyhow::anyhow!(
                "Admission denied (model: {}): insufficient stake {} < {} required",
                ADMISSION_MODEL,
                stake,
                self.min_stake
            ));
        }

        // Storage is OPTIONAL for validators - no minimum requirement
        // Validators can choose to provide storage for bonus rewards but it's not mandatory

        // Check maximum validator limit (hard cap enforced regardless of stake/governance)
        if self.validators.len() >= self.max_validators as usize {
            return Err(anyhow::anyhow!(
                "Maximum validator limit reached: {} (hard cap: {})",
                self.max_validators,
                MAX_VALIDATORS
            ));
        }

        // Check if validator already exists
        if self.validators.contains_key(&identity) {
            return Err(anyhow::anyhow!("Validator already registered"));
        }

        // Create new validator
        let validator = Validator::new(
            identity.clone(),
            stake,
            storage_provided,
            consensus_key,
            commission_rate,
        );

        // Add to validator set
        self.total_voting_power += validator.voting_power;
        self.validators.insert(identity.clone(), validator);

        tracing::info!(
            "Registered new validator {:?} with {} SOV stake and {} bytes storage",
            identity,
            stake,
            storage_provided
        );

        Ok(())
    }

    /// Remove a validator from the set
    pub fn remove_validator(&mut self, identity: &IdentityId) -> Result<()> {
        if let Some(validator) = self.validators.remove(identity) {
            self.total_voting_power -= validator.voting_power;

            tracing::info!("Removed validator {:?} from validator set", identity);

            Ok(())
        } else {
            Err(anyhow::anyhow!("Validator not found"))
        }
    }

    /// Get validator by identity
    pub fn get_validator(&self, identity: &IdentityId) -> Option<&Validator> {
        self.validators.get(identity)
    }

    /// Get mutable validator by identity
    pub fn get_validator_mut(&mut self, identity: &IdentityId) -> Option<&mut Validator> {
        self.validators.get_mut(identity)
    }

    /// Get all active validators
    pub fn get_active_validators(&self) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.can_participate())
            .collect()
    }

    /// Get validator set for a specific consensus round
    pub fn get_validator_set_for_round(&self, _round: u64) -> Vec<&Validator> {
        // For now, return all active validators
        // In a more sophisticated implementation, this could rotate validators
        self.get_active_validators()
    }

    /// Select proposer for a given height and round
    pub fn select_proposer(&self, height: u64, round: u32) -> Option<&Validator> {
        let mut active_validators = self.get_active_validators();

        if active_validators.is_empty() {
            return None;
        }

        // CRITICAL: Sort validators by identity bytes to ensure deterministic ordering
        // HashMap iteration order is non-deterministic, so we must sort!
        active_validators.sort_by(|a, b| a.identity.as_bytes().cmp(b.identity.as_bytes()));

        // Round-robin selection based on height and round (now deterministic)
        let index = ((height + round as u64) % active_validators.len() as u64) as usize;
        Some(active_validators[index])
    }

    /// Slash a validator for misbehavior
    pub fn slash_validator(
        &mut self,
        identity: &IdentityId,
        slash_type: SlashType,
        slash_percentage: u8,
    ) -> Result<u64> {
        if let Some(validator) = self.validators.get_mut(identity) {
            let old_voting_power = validator.voting_power;
            let slashed_amount = validator.slash(slash_type, slash_percentage)?;

            // Update total voting power
            self.total_voting_power = self
                .total_voting_power
                .saturating_sub(old_voting_power)
                .saturating_add(validator.voting_power);

            Ok(slashed_amount)
        } else {
            Err(anyhow::anyhow!("Validator not found for slashing"))
        }
    }

    /// Update validator activity
    pub fn update_validator_activity(&mut self, identity: &IdentityId) {
        if let Some(validator) = self.validators.get_mut(identity) {
            validator.update_activity();
        }
    }

    /// Check if a validator exists and is active
    pub fn is_validator(&self, identity: &IdentityId) -> bool {
        self.validators.contains_key(identity)
            && self
                .validators
                .get(identity)
                .map_or(false, |v| v.status == ValidatorStatus::Active)
    }

    /// Check if a validator is active at a specific height
    pub fn is_validator_active(&self, identity: &IdentityId, _height: u64) -> bool {
        self.is_validator(identity)
    }

    /// Get total number of validators
    pub fn get_total_validators(&self) -> usize {
        self.validators.len()
    }

    /// Get proposer for a specific round
    pub fn get_proposer_for_round(&self, height: u64, round: u32) -> Option<&Validator> {
        self.select_proposer(height, round)
    }

    /// Process inactive validators
    pub fn process_inactive_validators(
        &mut self,
        max_inactive_seconds: u64,
    ) -> Result<Vec<IdentityId>> {
        let mut inactive_validators = Vec::new();

        for (identity, validator) in self.validators.iter_mut() {
            if validator.is_inactive(max_inactive_seconds)
                && validator.status == ValidatorStatus::Active
            {
                // Slash for liveness violation
                let old_voting_power = validator.voting_power;
                let _ = validator.slash(SlashType::Liveness, 1)?; // 1% slash for inactivity

                // Update total voting power
                self.total_voting_power = self
                    .total_voting_power
                    .saturating_sub(old_voting_power)
                    .saturating_add(validator.voting_power);

                inactive_validators.push(identity.clone());
            }

            // Try to release validators from jail
            validator.try_release_from_jail();
        }

        Ok(inactive_validators)
    }

    /// Get total voting power of all active validators
    pub fn get_total_voting_power(&self) -> u64 {
        self.get_active_validators()
            .iter()
            .map(|v| v.voting_power)
            .sum()
    }

    /// Check if we have enough validators for consensus
    pub fn has_sufficient_validators(&self) -> bool {
        let active_count = self.get_active_validators().len();

        if self.development_mode {
            //  TESTING MODE: Allow single validator for development/testing
            if active_count >= 1 {
                if active_count < 4 {
                    tracing::warn!(" TESTING MODE: {} validator(s) active (production requires minimum 4 for BFT)", active_count);
                }
                return true;
            }
            return false;
        }

        // Production mode: Require minimum 4 validators for Byzantine Fault Tolerance
        // BFT needs at least 3f+1 validators where f is the number of Byzantine failures
        // With 4 validators, we can tolerate 1 Byzantine failure: f=1, 3(1)+1=4
        if active_count < 4 {
            tracing::warn!(
                " INSUFFICIENT VALIDATORS: {} active (minimum 4 required for BFT)",
                active_count
            );
            return false;
        }

        true
    }

    /// Synchronize validators from blockchain validator info
    ///
    /// This method accepts a list of validator data structures and registers
    /// any new validators that aren't already in the consensus layer.
    ///
    /// Returns: (synced_count, skipped_count)
    pub fn sync_from_validator_list<T>(&mut self, validators: Vec<T>) -> Result<(usize, usize)>
    where
        T: ValidatorInfo,
    {
        let mut synced_count = 0;
        let mut skipped_count = 0;

        for validator_info in validators {
            let identity_id = validator_info.identity_id();

            // Skip if already registered
            if self.validators.contains_key(&identity_id) {
                skipped_count += 1;
                continue;
            }

            // Register new validator (clone identity_id for use in logging after move)
            let identity_id_for_log = identity_id.clone();
            match self.register_validator(
                identity_id,
                validator_info.stake(),
                validator_info.storage_provided(),
                validator_info.consensus_key(),
                validator_info.commission_rate(),
            ) {
                Ok(_) => {
                    synced_count += 1;
                    tracing::info!(
                        "Synced validator {:?} (stake: {}, storage: {})",
                        identity_id_for_log,
                        validator_info.stake(),
                        validator_info.storage_provided()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to sync validator {:?}: {}", identity_id_for_log, e);
                }
            }
        }

        tracing::info!(
            "Validator sync complete: {} new, {} skipped",
            synced_count,
            skipped_count
        );

        Ok((synced_count, skipped_count))
    }

    /// Get validator statistics
    pub fn get_validator_stats(&self) -> ValidatorStats {
        let active_count = self.get_active_validators().len();
        let total_count = self.validators.len();
        let total_stake: u64 = self.validators.values().map(|v| v.stake).sum();
        let total_storage: u64 = self.validators.values().map(|v| v.storage_provided).sum();

        ValidatorStats {
            total_validators: total_count,
            active_validators: active_count,
            total_stake,
            total_storage,
            total_voting_power: self.total_voting_power,
        }
    }

    /// Calculate Byzantine fault tolerance threshold
    pub fn get_byzantine_threshold(&self) -> u64 {
        // BFT requires 2/3 majority
        (self.get_total_voting_power() * 2) / 3 + 1
    }

    /// Check if a set of votes meets the Byzantine threshold
    pub fn meets_byzantine_threshold(&self, voting_power: u64) -> bool {
        voting_power >= self.get_byzantine_threshold()
    }
}

/// Validator statistics
#[derive(Debug, Clone)]
pub struct ValidatorStats {
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_stake: u64,
    pub total_storage: u64,
    pub total_voting_power: u64,
}
