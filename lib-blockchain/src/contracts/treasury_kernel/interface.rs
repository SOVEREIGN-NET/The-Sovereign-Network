//! Treasury Kernel Interface — Single Balance Mutation Authority
//!
//! Defines the interface through which ALL token balance mutations must pass.
//! Any entity wanting to mutate balances MUST go through this interface.
//!
//! # Consensus-Critical
//! All operations are deterministic. Integer math only.
//! State changes are atomic: either fully applied or fully rolled back.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Result type for Treasury Kernel operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelOpError {
    /// Caller is not authorized (not kernel or governance)
    Unauthorized,
    /// Kernel is paused (emergency governance action)
    Paused,
    /// Insufficient available balance for debit/lock
    InsufficientBalance,
    /// Insufficient locked balance for release
    InsufficientLockedBalance,
    /// Balance overflow on credit
    Overflow,
    /// Would exceed token max supply on mint
    ExceedsMaxSupply,
    /// Minting disabled (no kernel authority set on token)
    MintingDisabled,
    /// Mint/burn authorization not found
    MissingAuthorization,
    /// Governance delay period has not elapsed
    DelayNotElapsed,
    /// Authorization already consumed (idempotency guard)
    AuthorizationConsumed,
}

impl fmt::Display for KernelOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "Unauthorized: caller is not Treasury Kernel or governance"),
            Self::Paused => write!(f, "Treasury Kernel is paused"),
            Self::InsufficientBalance => write!(f, "Insufficient available balance"),
            Self::InsufficientLockedBalance => write!(f, "Insufficient locked balance"),
            Self::Overflow => write!(f, "Balance overflow"),
            Self::ExceedsMaxSupply => write!(f, "Would exceed maximum token supply"),
            Self::MintingDisabled => write!(f, "Minting disabled: no kernel authority set"),
            Self::MissingAuthorization => write!(f, "Mint/burn authorization not found"),
            Self::DelayNotElapsed => write!(f, "Governance delay period has not elapsed"),
            Self::AuthorizationConsumed => write!(f, "Authorization already consumed"),
        }
    }
}

/// Reason codes for credit operations (audit trail)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditReason {
    /// UBI distribution to citizen
    UbiDistribution,
    /// Fee distribution to pool
    FeeDistribution,
    /// Validator/infrastructure reward
    Reward,
    /// New token minting (increases supply)
    Mint,
    /// Transfer credit leg (balance already exists)
    Transfer,
}

/// Reason codes for debit operations (audit trail)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebitReason {
    /// Fee collection from transaction
    FeeCollection,
    /// Token burn (decreases supply)
    Burn,
    /// Slashing for misbehavior
    Slash,
    /// Transfer debit leg
    Transfer,
}

/// Reason codes for lock operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockReason {
    /// Staking lock
    Staking,
    /// Vesting schedule lock
    Vesting,
    /// Escrow lock
    Escrow,
}

/// Reason codes for release operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseReason {
    /// Unstaking release
    Unstaking,
    /// Vesting schedule release
    VestingRelease,
    /// Escrow completion release
    EscrowComplete,
}

impl fmt::Display for CreditReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UbiDistribution => write!(f, "UBI distribution"),
            Self::FeeDistribution => write!(f, "Fee distribution"),
            Self::Reward => write!(f, "Reward"),
            Self::Mint => write!(f, "Mint"),
            Self::Transfer => write!(f, "Transfer credit"),
        }
    }
}

impl fmt::Display for DebitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeeCollection => write!(f, "Fee collection"),
            Self::Burn => write!(f, "Burn"),
            Self::Slash => write!(f, "Slash"),
            Self::Transfer => write!(f, "Transfer debit"),
        }
    }
}

impl fmt::Display for LockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staking => write!(f, "Staking"),
            Self::Vesting => write!(f, "Vesting"),
            Self::Escrow => write!(f, "Escrow"),
        }
    }
}

impl fmt::Display for ReleaseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unstaking => write!(f, "Unstaking"),
            Self::VestingRelease => write!(f, "Vesting release"),
            Self::EscrowComplete => write!(f, "Escrow complete"),
        }
    }
}

// ─── Governance-Gated Mint/Burn Authorization (M2) ──────────────────────

/// Reason for governance-authorized minting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintReason {
    /// UBI distribution (auto-authorized by kernel at epoch boundaries)
    UbiDistribution,
    /// Welfare service funding (requires DAO proposal)
    WelfareFunding,
    /// Infrastructure rewards (requires DAO proposal)
    InfrastructureReward,
    /// Treasury allocation (requires DAO proposal)
    TreasuryAllocation,
    /// Emergency mint (requires DAO Emergency proposal + supermajority)
    Emergency,
}

impl fmt::Display for MintReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UbiDistribution => write!(f, "UBI distribution"),
            Self::WelfareFunding => write!(f, "Welfare funding"),
            Self::InfrastructureReward => write!(f, "Infrastructure reward"),
            Self::TreasuryAllocation => write!(f, "Treasury allocation"),
            Self::Emergency => write!(f, "Emergency"),
        }
    }
}

/// Governance-approved mint authorization record
///
/// Created when a DAO MintBurnAuthorization proposal passes.
/// Registered with the kernel; executable only after the delay period elapses.
/// Each authorization can be consumed exactly once (idempotency guard).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintAuthorization {
    /// DAO proposal ID that authorized this mint
    pub proposal_id: [u8; 32],
    /// Reason for minting
    pub reason: MintReason,
    /// Amount authorized to mint
    pub authorized_amount: u64,
    /// Recipient key_id (matches PublicKey.key_id)
    pub recipient_key_id: [u8; 32],
    /// Epoch at which authorization was granted
    pub authorized_at_epoch: u64,
    /// Minimum epoch at which mint can execute
    pub executable_after_epoch: u64,
    /// Whether this authorization has been consumed
    pub consumed: bool,
}

/// Governance-approved burn authorization record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnAuthorization {
    /// DAO proposal ID that authorized this burn
    pub proposal_id: [u8; 32],
    /// Amount authorized to burn
    pub authorized_amount: u64,
    /// Account to burn from (key_id)
    pub from_key_id: [u8; 32],
    /// Epoch at which authorization was granted
    pub authorized_at_epoch: u64,
    /// Minimum epoch at which burn can execute
    pub executable_after_epoch: u64,
    /// Whether this authorization has been consumed
    pub consumed: bool,
}
