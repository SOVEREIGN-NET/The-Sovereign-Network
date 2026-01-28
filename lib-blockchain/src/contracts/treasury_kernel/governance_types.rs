//! Governance Types - Treasury Governance Proposals and Actions
//!
//! Types for governance proposals that affect the Treasury Kernel.
//! All proposal execution is subject to timelock and consensus verification.
//!
//! # Proposal Lifecycle
//! ```text
//! Created → Voting → Approved → Timelock → Executable → Executed
//!                  ↘ Rejected
//!                  ↘ Expired
//! ```
//!
//! # Consensus-Critical
//! All types use deterministic serialization. BTreeMap for ordering.

use super::role_types::{IdentityId, RoleId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Proposal identifier (32 bytes)
pub type ProposalId = [u8; 32];

/// Treasury Governance Proposal
///
/// Represents a governance action affecting the Treasury Kernel.
/// Must be approved by governance vote before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryProposal {
    /// Unique proposal ID
    pub proposal_id: ProposalId,
    /// Type of action to execute
    pub action: TreasuryAction,
    /// Epoch when proposal was created
    pub created_at_epoch: u64,
    /// Epoch when voting ends
    pub voting_ends_epoch: u64,
    /// Current status
    pub status: ProposalStatus,
    /// Epoch when proposal was approved (if applicable)
    pub approved_at_epoch: Option<u64>,
    /// Epoch when timelock expires (if applicable)
    pub timelock_expires_epoch: Option<u64>,
    /// Epoch when executed (if applicable)
    pub executed_at_epoch: Option<u64>,
    /// Proposer identity
    pub proposer: IdentityId,
    /// Description/rationale
    pub description: String,
}

impl TreasuryProposal {
    /// Create a new proposal
    pub fn new(
        proposal_id: ProposalId,
        action: TreasuryAction,
        created_at_epoch: u64,
        voting_duration_epochs: u64,
        proposer: IdentityId,
        description: String,
    ) -> Self {
        Self {
            proposal_id,
            action,
            created_at_epoch,
            voting_ends_epoch: created_at_epoch.saturating_add(voting_duration_epochs),
            status: ProposalStatus::Voting,
            approved_at_epoch: None,
            timelock_expires_epoch: None,
            executed_at_epoch: None,
            proposer,
            description,
        }
    }

    /// Mark proposal as approved
    pub fn approve(&mut self, epoch: u64, timelock_epochs: u64) {
        self.status = ProposalStatus::Approved;
        self.approved_at_epoch = Some(epoch);
        self.timelock_expires_epoch = Some(epoch.saturating_add(timelock_epochs));
    }

    /// Mark proposal as rejected
    pub fn reject(&mut self) {
        self.status = ProposalStatus::Rejected;
    }

    /// Mark proposal as expired
    pub fn expire(&mut self) {
        self.status = ProposalStatus::Expired;
    }

    /// Mark proposal as executed
    pub fn execute(&mut self, epoch: u64) {
        self.status = ProposalStatus::Executed;
        self.executed_at_epoch = Some(epoch);
    }

    /// Check if proposal is executable
    pub fn is_executable(&self, current_epoch: u64) -> bool {
        self.status == ProposalStatus::Approved
            && self.timelock_expires_epoch.map_or(false, |e| current_epoch >= e)
    }

    /// Check if proposal has expired
    pub fn has_expired(&self, current_epoch: u64) -> bool {
        match self.status {
            ProposalStatus::Voting => current_epoch > self.voting_ends_epoch,
            ProposalStatus::Approved => {
                // Approved proposals expire if not executed within grace period
                self.timelock_expires_epoch
                    .map_or(false, |e| current_epoch > e.saturating_add(EXECUTION_GRACE_EPOCHS))
            }
            _ => false,
        }
    }
}

/// Grace period for executing approved proposals (epochs after timelock)
pub const EXECUTION_GRACE_EPOCHS: u64 = 4;

/// Status of a governance proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal is being voted on
    Voting,
    /// Proposal was approved, in timelock
    Approved,
    /// Proposal was rejected
    Rejected,
    /// Proposal expired without quorum or execution
    Expired,
    /// Proposal was executed
    Executed,
}

impl fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Voting => write!(f, "Voting"),
            Self::Approved => write!(f, "Approved"),
            Self::Rejected => write!(f, "Rejected"),
            Self::Expired => write!(f, "Expired"),
            Self::Executed => write!(f, "Executed"),
        }
    }
}

/// Treasury actions that can be proposed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreasuryAction {
    /// Mint tokens to an address
    Mint {
        recipient: IdentityId,
        amount: u64,
        reason: MintReason,
    },
    /// Burn tokens from treasury reserve
    Burn {
        amount: u64,
        reason: BurnReason,
    },
    /// Update role cap
    UpdateRoleCap {
        role_id: RoleId,
        new_annual_cap: Option<u64>,
        new_lifetime_cap: Option<Option<u64>>,
        new_per_epoch_cap: Option<u64>,
    },
    /// Create a new role definition
    CreateRole {
        role_id: RoleId,
        name: String,
        annual_cap: u64,
        lifetime_cap: Option<u64>,
        per_epoch_cap: u64,
    },
    /// Deactivate a role (no new assignments)
    DeactivateRole {
        role_id: RoleId,
    },
    /// Update global parameters
    UpdateParameter {
        parameter: TreasuryParameter,
        new_value: u64,
    },
    /// Emergency pause all operations
    EmergencyPause,
    /// Resume from emergency pause
    EmergencyResume,
    /// Update compensation config
    UpdateCompensationRate {
        role_id: RoleId,
        new_rate: u64,
    },
    /// Grant role to identity
    GrantRole {
        identity_id: IdentityId,
        role_id: RoleId,
    },
    /// Revoke role from identity
    RevokeRole {
        identity_id: IdentityId,
        role_id: RoleId,
    },
}

impl fmt::Display for TreasuryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mint { amount, reason, .. } => {
                write!(f, "Mint {} for {:?}", amount, reason)
            }
            Self::Burn { amount, reason } => {
                write!(f, "Burn {} for {:?}", amount, reason)
            }
            Self::UpdateRoleCap { role_id, .. } => {
                write!(f, "UpdateRoleCap for role {:?}", &role_id[..4])
            }
            Self::CreateRole { name, .. } => {
                write!(f, "CreateRole: {}", name)
            }
            Self::DeactivateRole { role_id } => {
                write!(f, "DeactivateRole: {:?}", &role_id[..4])
            }
            Self::UpdateParameter { parameter, new_value } => {
                write!(f, "UpdateParameter: {} = {}", parameter, new_value)
            }
            Self::EmergencyPause => write!(f, "EmergencyPause"),
            Self::EmergencyResume => write!(f, "EmergencyResume"),
            Self::UpdateCompensationRate { role_id, new_rate } => {
                write!(f, "UpdateRate for {:?} to {}", &role_id[..4], new_rate)
            }
            Self::GrantRole { identity_id, role_id } => {
                write!(f, "GrantRole {:?} to {:?}", &role_id[..4], &identity_id[..4])
            }
            Self::RevokeRole { identity_id, role_id } => {
                write!(f, "RevokeRole {:?} from {:?}", &role_id[..4], &identity_id[..4])
            }
        }
    }
}

/// Governance-controlled treasury parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TreasuryParameter {
    /// Mint delay in epochs
    MintDelayEpochs,
    /// Maximum UBI pool per epoch
    MaxUbiPoolPerEpoch,
    /// Default voting duration
    DefaultVotingDurationEpochs,
    /// Default timelock duration
    DefaultTimelockEpochs,
    /// Maximum payout per epoch per assignment
    MaxEpochPayout,
    /// Minimum payout threshold
    MinPayoutThreshold,
}

impl fmt::Display for TreasuryParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MintDelayEpochs => write!(f, "MintDelayEpochs"),
            Self::MaxUbiPoolPerEpoch => write!(f, "MaxUbiPoolPerEpoch"),
            Self::DefaultVotingDurationEpochs => write!(f, "DefaultVotingDurationEpochs"),
            Self::DefaultTimelockEpochs => write!(f, "DefaultTimelockEpochs"),
            Self::MaxEpochPayout => write!(f, "MaxEpochPayout"),
            Self::MinPayoutThreshold => write!(f, "MinPayoutThreshold"),
        }
    }
}

/// Reasons for governance-authorized minting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintReason {
    /// Treasury reserve allocation
    TreasuryAllocation,
    /// Grant or subsidy
    GrantSubsidy,
    /// Ecosystem fund allocation
    EcosystemFund,
    /// Emergency liquidity
    EmergencyLiquidity,
    /// Migration from old system
    Migration,
}

impl fmt::Display for MintReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TreasuryAllocation => write!(f, "TreasuryAllocation"),
            Self::GrantSubsidy => write!(f, "GrantSubsidy"),
            Self::EcosystemFund => write!(f, "EcosystemFund"),
            Self::EmergencyLiquidity => write!(f, "EmergencyLiquidity"),
            Self::Migration => write!(f, "Migration"),
        }
    }
}

/// Reasons for governance-authorized burning
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BurnReason {
    /// Excess reserve reduction
    ExcessReduction,
    /// Fee burning mechanism
    FeeBurn,
    /// Supply adjustment
    SupplyAdjustment,
    /// Penalty enforcement
    Penalty,
}

impl fmt::Display for BurnReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExcessReduction => write!(f, "ExcessReduction"),
            Self::FeeBurn => write!(f, "FeeBurn"),
            Self::SupplyAdjustment => write!(f, "SupplyAdjustment"),
            Self::Penalty => write!(f, "Penalty"),
        }
    }
}

/// Governance execution error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// Proposal not found
    ProposalNotFound(ProposalId),
    /// Proposal already exists
    ProposalAlreadyExists(ProposalId),
    /// Proposal not in expected status
    InvalidProposalStatus {
        proposal_id: ProposalId,
        expected: ProposalStatus,
        actual: ProposalStatus,
    },
    /// Timelock not expired
    TimelockNotExpired {
        proposal_id: ProposalId,
        expires_epoch: u64,
        current_epoch: u64,
    },
    /// Proposal expired
    ProposalExpired(ProposalId),
    /// Not authorized to create proposal
    NotAuthorized,
    /// Invalid action parameters
    InvalidActionParameters(String),
    /// Execution failed
    ExecutionFailed(String),
    /// System is paused
    SystemPaused,
    /// System is not paused (for resume)
    SystemNotPaused,
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProposalNotFound(id) => {
                write!(f, "Proposal not found: {:?}", &id[..4])
            }
            Self::ProposalAlreadyExists(id) => {
                write!(f, "Proposal already exists: {:?}", &id[..4])
            }
            Self::InvalidProposalStatus { proposal_id, expected, actual } => {
                write!(
                    f,
                    "Invalid status for proposal {:?}: expected {}, got {}",
                    &proposal_id[..4], expected, actual
                )
            }
            Self::TimelockNotExpired { proposal_id, expires_epoch, current_epoch } => {
                write!(
                    f,
                    "Timelock not expired for {:?}: expires at {}, current {}",
                    &proposal_id[..4], expires_epoch, current_epoch
                )
            }
            Self::ProposalExpired(id) => {
                write!(f, "Proposal expired: {:?}", &id[..4])
            }
            Self::NotAuthorized => write!(f, "Not authorized to create proposal"),
            Self::InvalidActionParameters(msg) => {
                write!(f, "Invalid action parameters: {}", msg)
            }
            Self::ExecutionFailed(msg) => {
                write!(f, "Execution failed: {}", msg)
            }
            Self::SystemPaused => write!(f, "System is paused"),
            Self::SystemNotPaused => write!(f, "System is not paused"),
        }
    }
}

impl std::error::Error for GovernanceError {}

/// Result of proposal execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Proposal that was executed
    pub proposal_id: ProposalId,
    /// Epoch when executed
    pub executed_at_epoch: u64,
    /// Action that was executed
    pub action: TreasuryAction,
    /// Whether execution succeeded
    pub success: bool,
    /// Details about the execution
    pub details: String,
}

impl ExecutionResult {
    /// Create a successful result
    pub fn success(proposal_id: ProposalId, epoch: u64, action: TreasuryAction) -> Self {
        Self {
            proposal_id,
            executed_at_epoch: epoch,
            action: action.clone(),
            success: true,
            details: format!("Successfully executed: {}", action),
        }
    }

    /// Create a failed result
    pub fn failure(proposal_id: ProposalId, epoch: u64, action: TreasuryAction, reason: &str) -> Self {
        Self {
            proposal_id,
            executed_at_epoch: epoch,
            action,
            success: false,
            details: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_proposal_id() -> ProposalId {
        [1u8; 32]
    }

    fn test_identity_id() -> IdentityId {
        [2u8; 32]
    }

    fn test_role_id() -> RoleId {
        [3u8; 32]
    }

    #[test]
    fn test_proposal_lifecycle() {
        let mut proposal = TreasuryProposal::new(
            test_proposal_id(),
            TreasuryAction::Mint {
                recipient: test_identity_id(),
                amount: 100_000,
                reason: MintReason::TreasuryAllocation,
            },
            1, // created at epoch 1
            2, // voting lasts 2 epochs
            test_identity_id(),
            "Test proposal".to_string(),
        );

        // Initial state
        assert_eq!(proposal.status, ProposalStatus::Voting);
        assert_eq!(proposal.voting_ends_epoch, 3);
        assert!(!proposal.is_executable(1));

        // Approve with 2-epoch timelock
        proposal.approve(3, 2);
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert_eq!(proposal.approved_at_epoch, Some(3));
        assert_eq!(proposal.timelock_expires_epoch, Some(5));

        // Not yet executable (timelock)
        assert!(!proposal.is_executable(4));

        // Now executable
        assert!(proposal.is_executable(5));

        // Execute
        proposal.execute(5);
        assert_eq!(proposal.status, ProposalStatus::Executed);
        assert_eq!(proposal.executed_at_epoch, Some(5));
    }

    #[test]
    fn test_proposal_rejection() {
        let mut proposal = TreasuryProposal::new(
            test_proposal_id(),
            TreasuryAction::EmergencyPause,
            1,
            2,
            test_identity_id(),
            "Test".to_string(),
        );

        proposal.reject();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
        assert!(!proposal.is_executable(10));
    }

    #[test]
    fn test_proposal_expiration() {
        let proposal = TreasuryProposal::new(
            test_proposal_id(),
            TreasuryAction::EmergencyPause,
            1,
            2,
            test_identity_id(),
            "Test".to_string(),
        );

        // Voting period hasn't ended
        assert!(!proposal.has_expired(2));

        // Voting period ended without approval
        assert!(proposal.has_expired(4));
    }

    #[test]
    fn test_execution_result() {
        let result = ExecutionResult::success(
            test_proposal_id(),
            5,
            TreasuryAction::Mint {
                recipient: test_identity_id(),
                amount: 1000,
                reason: MintReason::GrantSubsidy,
            },
        );

        assert!(result.success);
        assert_eq!(result.executed_at_epoch, 5);
    }

    #[test]
    fn test_treasury_action_display() {
        let mint = TreasuryAction::Mint {
            recipient: test_identity_id(),
            amount: 1000,
            reason: MintReason::TreasuryAllocation,
        };
        assert!(format!("{}", mint).contains("Mint"));

        let pause = TreasuryAction::EmergencyPause;
        assert_eq!(format!("{}", pause), "EmergencyPause");
    }

    #[test]
    fn test_update_role_cap() {
        let action = TreasuryAction::UpdateRoleCap {
            role_id: test_role_id(),
            new_annual_cap: Some(200_000),
            new_lifetime_cap: Some(Some(1_000_000)),
            new_per_epoch_cap: Some(20_000),
        };

        if let TreasuryAction::UpdateRoleCap { new_annual_cap, .. } = action {
            assert_eq!(new_annual_cap, Some(200_000));
        }
    }

    #[test]
    fn test_governance_error_display() {
        let err = GovernanceError::TimelockNotExpired {
            proposal_id: test_proposal_id(),
            expires_epoch: 10,
            current_epoch: 5,
        };

        assert!(format!("{}", err).contains("expires at 10"));
    }
}
