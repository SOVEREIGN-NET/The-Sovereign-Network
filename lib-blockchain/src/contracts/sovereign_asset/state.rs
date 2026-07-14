//! Sovereign Asset module sub-state (ADR: docs/arch/sovereign-asset.md).

use serde::{Deserialize, Serialize};

use super::types::GovernanceVerifierKind;

/// Curve phase persisted in `asset_curve/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurvePhase {
    Curve,
    Graduated,
    Amm,
}

/// Heavy curve state keyed by `asset_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurveModuleState {
    pub phase: CurvePhase,
    pub reserve_balance: u128,
    pub treasury_balance: u128,
    pub threshold: u128,
    pub sell_enabled: bool,
    pub amm_pool_id: Option<[u8; 32]>,
}

impl Default for CurveModuleState {
    fn default() -> Self {
        Self {
            phase: CurvePhase::Curve,
            reserve_balance: 0,
            treasury_balance: 0,
            threshold: 0,
            sell_enabled: true,
            amm_pool_id: None,
        }
    }
}

/// Queued rewards policy update (decrease-only timelock per DAO P7 / Q5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRewardsPolicyUpdate {
    pub policy_cid: [u8; 32],
    pub policy_hash: [u8; 32],
    pub effective_height: u64,
}

/// Rewards delegate + policy refs in `asset_rewards/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsModuleState {
    pub spend_delegate_key_id: [u8; 32],
    pub policy_cid: [u8; 32],
    pub policy_hash: [u8; 32],
    pub nonce: u64,
    #[serde(default)]
    pub pending_policy: Option<PendingRewardsPolicyUpdate>,
}

/// Governance verifier persisted in `asset_governance/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceVerifierState {
    Single { signer_key_id: [u8; 32] },
    Multisig {
        signers: Vec<[u8; 32]>,
        threshold: u8,
    },
}

/// Queued creator → governance handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAuthorityTransfer {
    pub new_verifier: GovernanceVerifierState,
    pub effective_height: u64,
}

/// Full governance module state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GovernanceModuleState {
    pub verifier: Option<GovernanceVerifierState>,
    pub pending_transfer: Option<PendingAuthorityTransfer>,
}

impl GovernanceVerifierState {
    pub fn kind(&self) -> GovernanceVerifierKind {
        match self {
            GovernanceVerifierState::Single { .. } => GovernanceVerifierKind::Single,
            GovernanceVerifierState::Multisig { .. } => GovernanceVerifierKind::Multisig,
        }
    }

    pub fn signer_count(&self) -> u8 {
        match self {
            GovernanceVerifierState::Single { .. } => 1,
            GovernanceVerifierState::Multisig { signers, .. } => signers.len() as u8,
        }
    }

    pub fn threshold(&self) -> u8 {
        match self {
            GovernanceVerifierState::Single { .. } => 1,
            GovernanceVerifierState::Multisig { threshold, .. } => *threshold,
        }
    }
}

pub const GOVERNANCE_MIN_SIGNERS: usize = 1;
pub const GOVERNANCE_MULTISIG_MIN_SIGNERS: usize = 2;
pub const GOVERNANCE_MAX_SIGNERS: usize = 10;
pub const AUTHORITY_TRANSFER_TIMELOCK_BLOCKS: u64 = 7_200;

/// Timelock before a decrease-only rewards policy update becomes effective (DAO P7 / Q5).
pub const REWARDS_POLICY_DECREASE_TIMELOCK_BLOCKS: u64 = AUTHORITY_TRANSFER_TIMELOCK_BLOCKS;

/// Block height at which `activate_pending_authority_transfers` becomes consensus-active.
///
/// Before this height the pass is a no-op so replay and rolling deploy stay deterministic.
/// Coordinate via halt → staged deploy; live chain must have no queued `pending_transfer`
/// below this height (none expected until DAO launch governance ships).
#[cfg(test)]
pub const GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT: u64 = 0;
#[cfg(not(test))]
pub const GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT: u64 = 80_000;

/// Block height at which new `TokenCreation` transactions are rejected (use `AssetLaunch`).
///
/// Aligned with [`GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT`] so testnet replay below 80k stays
/// deterministic while post-cutover launches use the sovereign-asset write path only.
#[cfg(test)]
pub const TOKEN_CREATION_SUNSET_HEIGHT: u64 = u64::MAX;
#[cfg(not(test))]
pub const TOKEN_CREATION_SUNSET_HEIGHT: u64 = 80_000;

/// Returns true when `TokenCreation` may still be applied at `block_height` (replay / apply).
#[inline]
pub fn token_creation_apply_allowed_at_height(block_height: u64) -> bool {
    token_creation_apply_allowed_at_height_with_sunset(block_height, TOKEN_CREATION_SUNSET_HEIGHT)
}

/// Testable sunset gate (production sunset = 80_000).
#[inline]
pub fn token_creation_apply_allowed_at_height_with_sunset(
    block_height: u64,
    sunset_height: u64,
) -> bool {
    block_height < sunset_height
}

/// Returns true when new `TokenCreation` submissions are accepted at the given chain tip.
#[inline]
pub fn token_creation_submission_allowed_at_tip(chain_tip: u64) -> bool {
    token_creation_apply_allowed_at_height(chain_tip)
}

/// Epic Q1–Q3 / Q8 economic rules (mint class, treasury spend auth, reward liquidity, burn).
/// Inactive below [`GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT`] so replay matches pre-rules history.
#[inline]
pub fn economic_rules_active(block_height: u64) -> bool {
    block_height >= GOVERNANCE_TIMELOCK_ACTIVATION_HEIGHT
}

/// Default multisig threshold: floor(N/2) + 1.
pub fn default_governance_threshold(n: usize) -> u8 {
    ((n / 2) + 1) as u8
}

#[cfg(test)]
mod sunset_tests {
    use super::*;

    #[test]
    fn prod_token_creation_sunset_is_80k() {
        const PROD_SUNSET: u64 = 80_000;
        assert!(token_creation_apply_allowed_at_height_with_sunset(
            PROD_SUNSET - 1,
            PROD_SUNSET
        ));
        assert!(!token_creation_apply_allowed_at_height_with_sunset(
            PROD_SUNSET,
            PROD_SUNSET
        ));
    }

    #[test]
    fn test_build_never_sunsets_token_creation() {
        assert!(token_creation_apply_allowed_at_height(u64::MAX - 1));
    }
}

/// Validate governance verifier bounds at launch/upgrade.
pub fn validate_governance_verifier(verifier: &GovernanceVerifierState) -> Result<(), String> {
    match verifier {
        GovernanceVerifierState::Single { signer_key_id } => {
            if *signer_key_id == [0u8; 32] {
                return Err("governance single signer must be non-zero".to_string());
            }
        }
        GovernanceVerifierState::Multisig {
            signers,
            threshold,
        } => {
            if signers.len() < GOVERNANCE_MULTISIG_MIN_SIGNERS {
                return Err(format!(
                    "governance multisig requires at least {} signers",
                    GOVERNANCE_MULTISIG_MIN_SIGNERS
                ));
            }
            if signers.len() > GOVERNANCE_MAX_SIGNERS {
                return Err(format!(
                    "governance multisig allows at most {} signers",
                    GOVERNANCE_MAX_SIGNERS
                ));
            }
            if *threshold == 0 || (*threshold as usize) > signers.len() {
                return Err("governance threshold must be 1..=N".to_string());
            }
            let mut seen = std::collections::HashSet::new();
            for s in signers {
                if *s == [0u8; 32] {
                    return Err("governance signer key_id must be non-zero".to_string());
                }
                if !seen.insert(*s) {
                    return Err("duplicate governance signer key_id".to_string());
                }
            }
        }
    }
    Ok(())
}