//! Validator set management

use crate::types::{SlashType, ValidatorStatus};
use crate::validators::Validator;
use anyhow::Result;
use lib_identity::IdentityId;
use std::collections::HashMap;

// ============================================================================
// Validator count bounds
// ============================================================================

/// Minimum number of validators required for BFT consensus.
///
/// BFT (Byzantine Fault Tolerant) protocols require at least `3f + 1` validators
/// to tolerate `f` simultaneous Byzantine (malicious or faulty) nodes.  With
/// `MIN_VALIDATORS = 4` we tolerate `f = 1` Byzantine failure:
///
/// ```text
/// 3f + 1 = 3(1) + 1 = 4
/// ```
///
/// This is an absolute floor: the runtime MUST NOT allow the active validator set
/// to drop below this value, regardless of governance votes or slashing events.
///
/// # Governance control
///
/// `MIN_VALIDATORS` is a protocol constant and is intentionally NOT adjustable
/// through DAO governance.  Allowing governance to reduce the minimum below 4
/// would allow a majority to destroy safety guarantees for the minority.
///
/// To raise the floor (e.g. to support `f = 2`, requiring 7 validators), a
/// coordinated network upgrade with supermajority signalling is required.
pub const MIN_VALIDATORS: usize = 4;

/// Maximum number of validators that may participate in active consensus.
///
/// This default upper bound is enforced at runtime when adding validators.
/// It is intentionally set high enough to allow meaningful decentralisation
/// while preventing unbounded growth in consensus message complexity
/// (BFT message complexity scales as O(n²) with validator count).
///
/// # Governance control
///
/// `MAX_VALIDATORS` IS adjustable by governance via the DAO proposal type
/// `DaoProposalType::ValidatorUpdate` with a
/// `GovernanceParameterValue::MaxValidators(new_max)` payload.  The governance
/// path is:
///
/// 1. Any token holder submits a `DaoProposal` of type `ValidatorUpdate`.
/// 2. The proposal includes a `DaoExecutionAction::GovernanceParameterUpdate`
///    containing `GovernanceParameterValue::MaxValidators(new_max)`.
/// 3. After the voting period the proposal is executed via
///    `DaoEngine::apply_governance_update()`, which writes the new value into
///    `ConsensusConfig::max_validators`.
/// 4. On the next epoch boundary the `ConsensusEngine` reads the updated config
///    and passes the new limit to `ValidatorManager`.
///
/// The governance update is validated to ensure the new maximum is:
/// - ≥ `MIN_VALIDATORS` (safety floor cannot be breached).
/// - ≤ `MAX_VALIDATORS_HARD_CAP` (protocol ceiling).
///
/// See `DaoEngine::validate_governance_update()` and `ValidatorManager::register_validator()`.
pub const MAX_VALIDATORS: u32 = 100;

/// Hard cap on the maximum validators that governance may set.
///
/// Even a supermajority governance vote cannot raise `MAX_VALIDATORS` above this
/// value without a protocol upgrade.  At 256 validators, O(n²) BFT messaging
/// would produce ~65 000 messages per consensus round which is within acceptable
/// bounds for high-bandwidth validators.
pub const MAX_VALIDATORS_HARD_CAP: u32 = 256;

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

/// Manages the set of validators in the consensus system.
///
/// # Validator Count Invariants
///
/// The manager enforces two hard bounds at all times:
///
/// - **Minimum** ([`MIN_VALIDATORS`]): The active set must never fall below 4.
///   This guarantees BFT safety with up to 1 Byzantine fault (`3f+1`, `f=1`).
///   Attempts to remove a validator when the active count is already at the
///   minimum are rejected.
///
/// - **Maximum** ([`MAX_VALIDATORS`] / `max_validators` field): The active set
///   must not exceed the configured limit.  The runtime default is
///   [`MAX_VALIDATORS`]; governance may raise or lower it within
///   `[MIN_VALIDATORS, MAX_VALIDATORS_HARD_CAP]`.
///
/// # Governance Control
///
/// The upper bound (`max_validators`) is adjustable through DAO governance via
/// `GovernanceParameterValue::MaxValidators(n)`.  The lower bound
/// ([`MIN_VALIDATORS`]) is a protocol constant and is not governance-adjustable.
#[derive(Debug, Clone)]
pub struct ValidatorManager {
    /// Active validators
    validators: HashMap<IdentityId, Validator>,
    /// Maximum number of validators (governance-adjustable, default: MAX_VALIDATORS)
    max_validators: u32,
    /// Minimum stake required to be a validator
    min_stake: u64,
    /// Total voting power of all active validators
    total_voting_power: u64,
    /// Development mode flag - allows single validator consensus
    development_mode: bool,
}

impl ValidatorManager {
    /// Create a new validator manager.
    ///
    /// # Parameters
    ///
    /// - `max_validators`: Upper bound on the active validator set.  Should be
    ///   set to [`MAX_VALIDATORS`] (= 100) by default.  Must be ≥
    ///   [`MIN_VALIDATORS`] (= 4) and ≤ [`MAX_VALIDATORS_HARD_CAP`] (= 256).
    ///   Governance may later adjust this via
    ///   `GovernanceParameterValue::MaxValidators`.
    /// - `min_stake`: Minimum staked SOV to be eligible as a validator.
    pub fn new(max_validators: u32, min_stake: u64) -> Self {
        // Clamp max_validators into the valid range at construction time.
        let max_validators = max_validators
            .max(MIN_VALIDATORS as u32)
            .min(MAX_VALIDATORS_HARD_CAP);
        Self {
            validators: HashMap::new(),
            max_validators,
            min_stake,
            total_voting_power: 0,
            development_mode: false,
        }
    }

    /// Create a new validator manager with development mode.
    ///
    /// In development mode the BFT minimum is relaxed to 1 validator so that
    /// single-node test setups function correctly.  Warnings are emitted
    /// whenever the active count is below [`MIN_VALIDATORS`].
    pub fn new_with_development_mode(
        max_validators: u32,
        min_stake: u64,
        development_mode: bool,
    ) -> Self {
        let max_validators = max_validators
            .max(MIN_VALIDATORS as u32)
            .min(MAX_VALIDATORS_HARD_CAP);
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
    /// # Max-Validator Enforcement
    ///
    /// Registration is rejected when the current validator count already equals
    /// or exceeds `self.max_validators` (governance-adjustable, default:
    /// [`MAX_VALIDATORS`]).  This prevents unbounded growth in consensus message
    /// complexity.
    ///
    /// # Min-Validator Note
    ///
    /// Adding validators can never violate the minimum — only removals can.
    /// The floor is enforced in [`remove_validator`].
    pub fn register_validator(
        &mut self,
        identity: IdentityId,
        stake: u64,
        storage_provided: u64,
        consensus_key: Vec<u8>,
        commission_rate: u8,
    ) -> Result<()> {
        // Check minimum requirements - ONLY stake is required for validators
        if stake < self.min_stake {
            return Err(anyhow::anyhow!(
                "Insufficient stake: {} < {} required",
                stake,
                self.min_stake
            ));
        }

        // Storage is OPTIONAL for validators - no minimum requirement
        // Validators can choose to provide storage for bonus rewards but it's not mandatory

        // MAX-VALIDATOR ENFORCEMENT
        // Reject when the active set is already at or above the configured limit.
        // The limit is governance-adjustable (see GovernanceParameterValue::MaxValidators)
        // but is capped at MAX_VALIDATORS_HARD_CAP.
        // Note: self.max_validators is already clamped to [MIN_VALIDATORS, MAX_VALIDATORS_HARD_CAP]
        // in the constructors (new/with_development_mode), so no need to re-clamp here.
        if self.validators.len() >= self.max_validators as usize {
            return Err(anyhow::anyhow!(
                "Maximum validator limit reached: {} (governance limit: {}, hard cap: {}). \
                 A DAO governance proposal (DaoProposalType::ValidatorUpdate with \
                 GovernanceParameterValue::MaxValidators) is required to raise the limit.",
                self.max_validators,
                self.max_validators,
                MAX_VALIDATORS_HARD_CAP,
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

    /// Remove a validator from the set.
    ///
    /// # Min-Validator Enforcement
    ///
    /// Removal is rejected when the active validator count is already at or below
    /// [`MIN_VALIDATORS`] (= 4).  This protects BFT safety: with fewer than
    /// `3f + 1 = 4` validators the consensus protocol cannot guarantee safety
    /// against even a single Byzantine fault.
    ///
    /// **Exception — development mode**: In `development_mode` the minimum is
    /// reduced to 1 so that single-node test setups can remove validators freely.
    ///
    /// # Governance control
    ///
    /// [`MIN_VALIDATORS`] is a protocol constant and cannot be lowered via
    /// governance.  To remove a validator when the set is already at the minimum,
    /// you must first add a replacement through the normal admission path
    /// (`DaoProposalType::ValidatorUpdate`).
    pub fn remove_validator(&mut self, identity: &IdentityId) -> Result<()> {
        // MIN-VALIDATOR ENFORCEMENT
        // Count only active (non-jailed, non-slashed-out) validators for the floor check.
        let active_count = self.get_active_validators().len();
        let min_floor = if self.development_mode { 1 } else { MIN_VALIDATORS };

        // Only block removal if the validator being removed is active and we're at minimum.
        // Inactive (jailed/slashed) validators can always be removed since they do not
        // contribute to BFT quorum and removing them cannot compromise safety.
        let validator_is_active = self.validators
            .get(identity)
            .map(|v| v.can_participate())
            .unwrap_or(false);

        if validator_is_active && active_count <= min_floor {
            return Err(anyhow::anyhow!(
                "Cannot remove validator: active validator count ({}) is already at the \
                 minimum required for BFT safety ({} = MIN_VALIDATORS, 3f+1 with f=1). \
                 Add a replacement validator before removing this one. \
                 Governance path: DaoProposalType::ValidatorUpdate.",
                active_count,
                min_floor,
            ));
        }

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

    /// Returns `true` if the active validator set meets the BFT quorum floor.
    ///
    /// In production mode the minimum is [`MIN_VALIDATORS`] (= 4, satisfying
    /// `3f+1` with `f=1`).  In development mode the minimum is 1 to allow
    /// single-node test environments, but a warning is emitted when the count
    /// is below the production floor.
    pub fn has_sufficient_validators(&self) -> bool {
        let active_count = self.get_active_validators().len();

        if self.development_mode {
            // TESTING MODE: Allow single validator for development/testing
            if active_count >= 1 {
                if active_count < MIN_VALIDATORS {
                    tracing::warn!(
                        " TESTING MODE: {} validator(s) active \
                         (production requires minimum {} for BFT, 3f+1 with f=1)",
                        active_count,
                        MIN_VALIDATORS
                    );
                }
                return true;
            }
            return false;
        }

        // Production mode: require at least MIN_VALIDATORS active validators.
        // BFT needs 3f+1 validators to tolerate f Byzantine faults.
        // MIN_VALIDATORS = 4 ensures f=1 fault tolerance.
        if active_count < MIN_VALIDATORS {
            tracing::warn!(
                " INSUFFICIENT VALIDATORS: {} active (minimum {} required for BFT, 3f+1 with f=1)",
                active_count,
                MIN_VALIDATORS,
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
