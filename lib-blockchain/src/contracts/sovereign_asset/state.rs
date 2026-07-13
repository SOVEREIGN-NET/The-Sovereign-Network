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

/// Default multisig threshold: floor(N/2) + 1.
pub fn default_governance_threshold(n: usize) -> u8 {
    ((n / 2) + 1) as u8
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