//! Validator implementation

use crate::slashing::{
    check_unjail_eligibility, liveness_jail_status, safety_ban_status, BanReason, JailStatus,
};
use crate::types::{SlashType, ValidatorStatus};
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};

/// Consensus-layer representation of a registered validator.
///
/// # Key Separation
///
/// A validator operates with three distinct cryptographic keys.  Each key is isolated
/// to a specific security domain so that the compromise of one key does not automatically
/// compromise the others.  All three keys MUST be different — the consensus engine
/// asserts this invariant at registration time.
///
/// ## Key Roles
///
/// ### `consensus_key` — BFT Vote-Signing Key
/// Signs block proposals, pre-votes, pre-commits, and view-change messages.
/// - **Algorithm**: Post-quantum Dilithium2.
/// - **Exposure**: Hot — present online during every consensus round.
/// - **Compromise impact**: Attacker can equivocate (double-sign), triggering slashing.
///
/// ### `networking_key` — P2P Transport Identity Key
/// Establishes the validator's peer identity on the ZHTP mesh network (QUIC TLS
/// handshake, DHT node ID, peer authentication).
/// - **Algorithm**: Ed25519 / X25519.
/// - **Exposure**: Hot — required for all inbound and outbound connections.
/// - **Compromise impact**: Attacker can impersonate the validator on the network
///   layer but CANNOT forge signed consensus votes.
///
/// ### `rewards_key` — Rewards / Fee-Collection Key
/// Identifies the wallet that receives block rewards and protocol fee distributions.
/// - **Algorithm**: Dilithium2 or Ed25519 depending on wallet type.
/// - **Exposure**: Can be kept cold — only needed when claiming accumulated rewards.
/// - **Compromise impact**: Attacker can redirect future rewards; past on-chain
///   balances already credited are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator identity
    pub identity: IdentityId,
    /// Staked amount (SOV tokens)
    pub stake: u64,
    /// Storage provided (bytes)
    pub storage_provided: u64,
    /// Validator status
    pub status: ValidatorStatus,
    /// Post-quantum Dilithium2 public key used exclusively for signing BFT consensus
    /// messages (proposals, pre-votes, pre-commits).  MUST differ from `networking_key`
    /// and `rewards_key`.
    pub consensus_key: Vec<u8>,
    /// Ed25519 / X25519 public key used for P2P transport identity (QUIC TLS, DHT node
    /// ID).  MUST differ from `consensus_key` and `rewards_key`.
    pub networking_key: Vec<u8>,
    /// Public key of the rewards wallet that receives block rewards and fee
    /// distributions.  MUST differ from `consensus_key` and `networking_key`.
    pub rewards_key: Vec<u8>,
    /// Voting power (calculated from stake + storage)
    pub voting_power: u64,
    /// Commission rate (percentage)
    pub commission_rate: u8,
    /// Reputation score
    pub reputation: u32,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Slash count
    pub slash_count: u32,
    /// Jail release time (if jailed) - DEPRECATED: use jail_status instead
    #[deprecated(note = "Use jail_status field for recovery policy enforcement")]
    pub jail_until: Option<u64>,
    /// Jail status tracking for recovery policy enforcement
    pub jail_status: JailStatus,
}

impl Validator {
    /// Create a new validator.
    ///
    /// # Panics
    ///
    /// Panics in debug builds (and returns an error in release builds via the caller's
    /// [`ValidatorManager::register_validator`]) if any two of `consensus_key`,
    /// `networking_key`, and `rewards_key` are identical.  Key separation is a
    /// hard invariant — see the [`Validator`] struct documentation for the full
    /// rationale.
    pub fn new(
        identity: IdentityId,
        stake: u64,
        storage_provided: u64,
        consensus_key: Vec<u8>,
        networking_key: Vec<u8>,
        rewards_key: Vec<u8>,
        commission_rate: u8,
    ) -> Self {
        // Enforce key separation invariant at construction time.
        debug_assert_ne!(
            consensus_key, networking_key,
            "Key separation violation: consensus_key and networking_key must be different"
        );
        debug_assert_ne!(
            consensus_key, rewards_key,
            "Key separation violation: consensus_key and rewards_key must be different"
        );
        debug_assert_ne!(
            networking_key, rewards_key,
            "Key separation violation: networking_key and rewards_key must be different"
        );

        let voting_power = Self::calculate_voting_power(stake, storage_provided);

        Self {
            identity,
            stake,
            storage_provided,
            status: ValidatorStatus::Active,
            consensus_key,
            networking_key,
            rewards_key,
            voting_power,
            commission_rate,
            reputation: 100, // Start with perfect reputation
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            slash_count: 0,
            #[allow(deprecated)]
            jail_until: None,
            jail_status: JailStatus::Active,
        }
    }

    /// Calculate voting power based primarily on stake, with optional storage bonus
    fn calculate_voting_power(stake: u64, storage_provided: u64) -> u64 {
        // Primary voting power comes from stake (traditional validator model)
        let base_power = (stake as f64).sqrt();

        // Optional storage bonus (max 20% bonus for significant storage)
        let storage_bonus = if storage_provided > 0 {
            let storage_gb = storage_provided as f64 / (1024.0 * 1024.0 * 1024.0);
            (storage_gb.ln().max(0.0) * 0.1).min(0.2) // Logarithmic bonus, capped at 20%
        } else {
            0.0
        };

        let total_power = base_power * (1.0 + storage_bonus);
        total_power as u64
    }

    /// Update validator's voting power when stake or storage changes
    pub fn update_voting_power(&mut self) {
        self.voting_power = Self::calculate_voting_power(self.stake, self.storage_provided);
    }

    /// Check if validator is active and can participate in consensus
    pub fn can_participate(&self) -> bool {
        match self.status {
            ValidatorStatus::Active => {
                // Use recovery policy API to check jail status
                self.jail_status.is_active()
            }
            _ => false,
        }
    }

    /// Slash validator for misbehavior
    ///
    /// # Arguments
    /// * `slash_type` - Type of misbehavior
    /// * `slash_percentage` - Percentage of stake to slash
    /// * `current_block` - Current block height for jail tracking
    pub fn slash(
        &mut self,
        slash_type: SlashType,
        slash_percentage: u8,
        current_block: u64,
    ) -> anyhow::Result<u64> {
        let slash_amount = (self.stake * slash_percentage as u64) / 100;

        // Apply slashing
        self.stake = self.stake.saturating_sub(slash_amount);
        self.slash_count += 1;

        // Update reputation based on slash type
        let reputation_penalty = match slash_type {
            SlashType::DoubleSign => 20,
            SlashType::Liveness => 5,
            SlashType::InvalidProposal => 10,
            SlashType::InvalidVote => 5,
        };

        self.reputation = self.reputation.saturating_sub(reputation_penalty);

        // Apply recovery policy: determine jail status based on slash type
        match slash_type {
            // Safety violations result in permanent ban
            SlashType::DoubleSign => {
                self.status = ValidatorStatus::Slashed;
                self.jail_status = safety_ban_status(current_block, BanReason::DoubleSign);
                #[allow(deprecated)]
                {
                    self.jail_until = None; // Permanent ban, no release time
                }
                tracing::error!(
                    "🚫 Validator {:?} PERMANENTLY BANNED for double-sign at block {}",
                    self.identity,
                    current_block
                );
            }
            SlashType::InvalidProposal => {
                self.status = ValidatorStatus::Slashed;
                self.jail_status = safety_ban_status(current_block, BanReason::InvalidBlock);
                #[allow(deprecated)]
                {
                    self.jail_until = None; // Permanent ban, no release time
                }
                tracing::error!(
                    "🚫 Validator {:?} PERMANENTLY BANNED for invalid proposal at block {}",
                    self.identity,
                    current_block
                );
            }
            SlashType::InvalidVote => {
                self.status = ValidatorStatus::Slashed;
                self.jail_status = safety_ban_status(current_block, BanReason::ConflictingVote);
                #[allow(deprecated)]
                {
                    self.jail_until = None; // Permanent ban, no release time
                }
                tracing::error!(
                    "🚫 Validator {:?} PERMANENTLY BANNED for conflicting vote at block {}",
                    self.identity,
                    current_block
                );
            }
            // Liveness violations result in temporary jail
            SlashType::Liveness => {
                self.status = ValidatorStatus::Jailed;
                self.jail_status = liveness_jail_status(current_block);
                let eligible_block = self.jail_status.eligible_at_block().unwrap_or(0);
                #[allow(deprecated)]
                {
                    // Keep jail_until for backward compatibility, but it's deprecated
                    self.jail_until = Some(eligible_block);
                }
                tracing::warn!(
                    "⚠️  Validator {:?} jailed for liveness violation at block {} (eligible to unjail at block {})",
                    self.identity,
                    current_block,
                    eligible_block
                );
            }
        }

        // Update voting power after slashing
        self.update_voting_power();

        tracing::warn!(
            " Validator {:?} slashed {} SOV for {:?} (slash count: {})",
            self.identity,
            slash_amount,
            slash_type,
            self.slash_count
        );

        Ok(slash_amount)
    }

    /// Jail validator for a specified duration
    ///
    /// DEPRECATED: This method is deprecated in favor of using the slash() method
    /// with appropriate SlashType, which will automatically apply the correct
    /// jail status based on the recovery policy.
    #[deprecated(note = "Use slash() method instead, which applies recovery policy")]
    pub fn jail(&mut self, duration_seconds: u64) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.status = ValidatorStatus::Jailed;
        #[allow(deprecated)]
        {
            self.jail_until = Some(current_time + duration_seconds);
        }

        tracing::warn!(
            " Validator {:?} jailed until timestamp {}",
            self.identity,
            self.jail_until.unwrap()
        );
    }

    /// Release validator from jail if jail period has expired
    ///
    /// DEPRECATED: This method implements automatic time-based jail release,
    /// which violates the recovery policy requirement that validators must
    /// explicitly submit an unjail transaction. Use the unjail() method instead,
    /// which enforces all recovery invariants.
    #[deprecated(note = "Use unjail() method instead, which enforces recovery policy")]
    pub fn try_release_from_jail(&mut self) -> bool {
        #[allow(deprecated)]
        if let Some(jail_until) = self.jail_until {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if current_time >= jail_until {
                self.status = ValidatorStatus::Active;
                #[allow(deprecated)]
                {
                    self.jail_until = None;
                }

                tracing::info!("🔓 Validator {:?} released from jail", self.identity);

                return true;
            }
        }
        false
    }

    /// Attempt to unjail a validator by enforcing recovery policy invariants
    ///
    /// This method enforces all recovery invariants defined in the slashing module:
    /// - REC-INV-1: Safety-slashed validators CANNOT unjail (permanent ban)
    /// - REC-INV-2: Liveness-slashed validators MUST wait JAIL_EXIT_WAIT_BLOCKS
    /// - REC-INV-3: Unjail is only permitted if remaining stake >= MIN_STAKE_TO_UNJAIL
    /// - REC-INV-4: Slashed stake is NOT restored on unjail
    ///
    /// # Arguments
    /// * `current_block` - Current finalized block height
    ///
    /// # Returns
    /// * `Ok(())` - Validator successfully unjailed
    /// * `Err(_)` - Unjail request rejected with reason
    pub fn unjail(&mut self, current_block: u64) -> Result<(), crate::slashing::RecoveryError> {
        // Enforce recovery policy invariants
        check_unjail_eligibility(&self.jail_status, self.stake, current_block)?;

        // All checks passed - restore validator to active status
        self.status = ValidatorStatus::Active;
        self.jail_status = JailStatus::Active;
        #[allow(deprecated)]
        {
            self.jail_until = None;
        }

        tracing::info!(
            "🔓 Validator {:?} successfully unjailed at block {} (stake: {} SOV)",
            self.identity,
            current_block,
            self.stake
        );

        Ok(())
    }

    /// Update validator's last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if validator has been inactive for too long
    pub fn is_inactive(&self, max_inactive_seconds: u64) -> bool {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        current_time - self.last_activity > max_inactive_seconds
    }

    /// Calculate validator's effective reputation score
    pub fn effective_reputation(&self) -> f64 {
        let base_reputation = self.reputation as f64 / 100.0; // Normalize to 0-1

        // Apply penalties for slashing history
        let slash_penalty = (self.slash_count as f64) * 0.1;

        (base_reputation - slash_penalty).max(0.0).min(1.0)
    }

    /// Add stake to validator
    pub fn add_stake(&mut self, amount: u64) {
        self.stake += amount;
        self.update_voting_power();

        tracing::info!(
            "Validator {:?} added {} SOV stake (total: {} SOV)",
            self.identity,
            amount,
            self.stake
        );
    }

    /// Remove stake from validator (if not locked)
    pub fn remove_stake(&mut self, amount: u64) -> anyhow::Result<()> {
        if amount > self.stake {
            return Err(anyhow::anyhow!("Cannot remove more stake than available"));
        }

        // Check minimum stake requirement
        let min_stake = 1000 * 1_000_000; // 1000 SOV minimum
        if self.stake - amount < min_stake {
            return Err(anyhow::anyhow!(
                "Cannot reduce stake below minimum requirement"
            ));
        }

        self.stake -= amount;
        self.update_voting_power();

        tracing::info!(
            " Validator {:?} removed {} SOV stake (remaining: {} SOV)",
            self.identity,
            amount,
            self.stake
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slashing::{JAIL_EXIT_WAIT_BLOCKS, MIN_STAKE_TO_UNJAIL};
    use lib_crypto::Hash;

    fn create_test_validator() -> Validator {
        Validator::new(
            IdentityId::from(Hash([1u8; 32])),
            2000 * 1_000_000, // 2000 SOV
            0,
            vec![1, 2, 3], // consensus_key
            vec![4, 5, 6], // networking_key
            vec![7, 8, 9], // rewards_key
            10,            // commission_rate
        )
    }

    #[test]
    fn test_slash_liveness_creates_temporary_jail() {
        let mut validator = create_test_validator();
        let current_block = 100;

        let result = validator.slash(SlashType::Liveness, 1, current_block);
        assert!(result.is_ok());

        // Should be jailed, not slashed
        assert_eq!(validator.status, ValidatorStatus::Jailed);
        assert!(!validator.can_participate());

        // Should have liveness jail status
        assert!(validator.jail_status.is_liveness_jailed());
        assert!(!validator.jail_status.is_permanently_banned());

        // Should have correct eligible block
        let eligible_block = current_block + JAIL_EXIT_WAIT_BLOCKS;
        assert_eq!(
            validator.jail_status.eligible_at_block(),
            Some(eligible_block)
        );
    }

    #[test]
    fn test_slash_double_sign_creates_permanent_ban() {
        let mut validator = create_test_validator();
        let current_block = 100;

        let result = validator.slash(SlashType::DoubleSign, 10, current_block);
        assert!(result.is_ok());

        // Should be slashed, not just jailed
        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert!(!validator.can_participate());

        // Should have permanent ban status
        assert!(validator.jail_status.is_permanently_banned());
        assert!(!validator.jail_status.is_liveness_jailed());

        // No eligible block for permanent ban
        assert_eq!(validator.jail_status.eligible_at_block(), None);
    }

    #[test]
    fn test_slash_invalid_proposal_creates_permanent_ban() {
        let mut validator = create_test_validator();
        let current_block = 100;

        let result = validator.slash(SlashType::InvalidProposal, 2, current_block);
        assert!(result.is_ok());

        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert!(validator.jail_status.is_permanently_banned());
    }

    #[test]
    fn test_slash_invalid_vote_creates_permanent_ban() {
        let mut validator = create_test_validator();
        let current_block = 100;

        let result = validator.slash(SlashType::InvalidVote, 5, current_block);
        assert!(result.is_ok());

        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert!(validator.jail_status.is_permanently_banned());
    }

    #[test]
    fn test_unjail_enforces_wait_period() {
        let mut validator = create_test_validator();
        let jailed_at_block = 100;

        // Slash for liveness
        validator
            .slash(SlashType::Liveness, 1, jailed_at_block)
            .unwrap();

        // Try to unjail immediately - should fail
        let result = validator.unjail(jailed_at_block);
        assert!(result.is_err());

        // Try one block before eligible - should fail
        let eligible_block = jailed_at_block + JAIL_EXIT_WAIT_BLOCKS;
        let result = validator.unjail(eligible_block - 1);
        assert!(result.is_err());

        // Try at exactly eligible block - should succeed
        let result = validator.unjail(eligible_block);
        assert!(result.is_ok());
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert!(validator.can_participate());
    }

    #[test]
    fn test_unjail_enforces_minimum_stake() {
        let mut validator = create_test_validator();
        let jailed_at_block = 100;

        // Slash for liveness, reducing stake significantly
        // Start with 2000 SOV, slash 90%
        validator
            .slash(SlashType::Liveness, 90, jailed_at_block)
            .unwrap();

        // Validator now has 200 SOV, which is below MIN_STAKE_TO_UNJAIL (1000 SOV)
        assert!(validator.stake < MIN_STAKE_TO_UNJAIL);

        // Try to unjail after wait period - should fail due to insufficient stake
        let eligible_block = jailed_at_block + JAIL_EXIT_WAIT_BLOCKS;
        let result = validator.unjail(eligible_block);
        assert!(result.is_err());

        // Add more stake to meet minimum
        validator.add_stake(MIN_STAKE_TO_UNJAIL - validator.stake + 1);

        // Now unjail should succeed
        let result = validator.unjail(eligible_block);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unjail_rejects_permanently_banned() {
        let mut validator = create_test_validator();
        let banned_at_block = 100;

        // Slash for double-sign (permanent ban)
        validator
            .slash(SlashType::DoubleSign, 10, banned_at_block)
            .unwrap();

        // Try to unjail at any block - should always fail
        let result = validator.unjail(banned_at_block + 10000);
        assert!(result.is_err());

        // Should remain banned
        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert!(!validator.can_participate());
    }

    #[test]
    fn test_unjail_restores_stake_without_restoration() {
        let mut validator = create_test_validator();
        let jailed_at_block = 100;
        let initial_stake = validator.stake;

        // Slash for liveness (1%)
        validator
            .slash(SlashType::Liveness, 1, jailed_at_block)
            .unwrap();
        let slashed_stake = validator.stake;

        // Stake should be reduced
        assert!(slashed_stake < initial_stake);

        // Unjail after wait period
        let eligible_block = jailed_at_block + JAIL_EXIT_WAIT_BLOCKS;
        validator.unjail(eligible_block).unwrap();

        // Stake should remain at slashed level (no restoration)
        assert_eq!(validator.stake, slashed_stake);
        assert!(validator.stake < initial_stake);
    }

    #[test]
    fn test_can_participate_respects_jail_status() {
        let mut validator = create_test_validator();

        // Initially active
        assert!(validator.can_participate());

        // Jail for liveness
        validator.slash(SlashType::Liveness, 1, 100).unwrap();
        assert!(!validator.can_participate());

        // Unjail
        let eligible_block = 100 + JAIL_EXIT_WAIT_BLOCKS;
        validator.unjail(eligible_block).unwrap();
        assert!(validator.can_participate());
    }

    #[test]
    fn test_can_participate_rejects_permanently_banned() {
        let mut validator = create_test_validator();

        // Ban permanently
        validator.slash(SlashType::DoubleSign, 10, 100).unwrap();

        // Should never be able to participate again
        assert!(!validator.can_participate());

        // Even after a long time
        validator.status = ValidatorStatus::Active; // Artificially try to restore
        assert!(!validator.can_participate()); // Still banned due to jail_status
    }
}
