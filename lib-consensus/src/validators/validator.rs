//! Validator implementation

use crate::slashing::{JailStatus, BanReason, check_unjail_eligibility, liveness_jail_status, safety_ban_status};
use crate::types::{SlashType, ValidatorStatus};
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};

/// Consensus validator information
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
    /// Public key for consensus
    pub consensus_key: Vec<u8>,
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
    /// Create a new validator
    pub fn new(
        identity: IdentityId,
        stake: u64,
        storage_provided: u64,
        consensus_key: Vec<u8>,
        commission_rate: u8,
    ) -> Self {
        let voting_power = Self::calculate_voting_power(stake, storage_provided);

        Self {
            identity,
            stake,
            storage_provided,
            status: ValidatorStatus::Active,
            consensus_key,
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
    pub fn slash(&mut self, slash_type: SlashType, slash_percentage: u8, current_block: u64) -> anyhow::Result<u64> {
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
