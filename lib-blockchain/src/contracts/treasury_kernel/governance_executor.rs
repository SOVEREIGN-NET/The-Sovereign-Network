//! Governance Executor - Execute Approved Treasury Proposals
//!
//! The Governance Executor manages the lifecycle and execution of
//! treasury governance proposals. It enforces timelocks, validates
//! approvals, and executes actions through the Treasury Kernel.
//!
//! # Execution Flow
//! ```text
//! 1. Proposal Created (by DAO vote)
//! 2. Voting Period
//! 3. Approval (if passes)
//! 4. Timelock Period (safety delay)
//! 5. Execution Window
//! 6. Execution or Expiration
//! ```
//!
//! # Consensus-Critical
//! All state uses BTreeMap for deterministic iteration.
//! Execution results are idempotent - same proposal executes only once.

use super::governance_types::{
    ExecutionResult, GovernanceError, ProposalId, ProposalStatus,
    TreasuryAction, TreasuryParameter, TreasuryProposal, EXECUTION_GRACE_EPOCHS,
};
use super::role_types::{IdentityId, RoleId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Default voting duration in epochs
pub const DEFAULT_VOTING_DURATION_EPOCHS: u64 = 2;

/// Default timelock duration in epochs
pub const DEFAULT_TIMELOCK_EPOCHS: u64 = 1;

/// Governance Executor - manages proposal lifecycle
///
/// Stores proposals and handles execution. All mutations are
/// consensus-critical and must be persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceExecutor {
    /// Active proposals (pending, approved, in timelock)
    proposals: BTreeMap<ProposalId, TreasuryProposal>,

    /// Executed proposal IDs (for idempotency)
    executed: BTreeMap<ProposalId, ExecutionResult>,

    /// Voting duration in epochs (configurable)
    voting_duration_epochs: u64,

    /// Timelock duration in epochs (configurable)
    timelock_epochs: u64,

    /// Configurable parameters
    parameters: BTreeMap<TreasuryParameter, u64>,
}

impl GovernanceExecutor {
    /// Create a new governance executor
    pub fn new() -> Self {
        let mut parameters = BTreeMap::new();
        parameters.insert(TreasuryParameter::MintDelayEpochs, 1);
        parameters.insert(TreasuryParameter::MaxUbiPoolPerEpoch, 1_000_000);
        parameters.insert(TreasuryParameter::DefaultVotingDurationEpochs, DEFAULT_VOTING_DURATION_EPOCHS);
        parameters.insert(TreasuryParameter::DefaultTimelockEpochs, DEFAULT_TIMELOCK_EPOCHS);
        parameters.insert(TreasuryParameter::MaxEpochPayout, 100_000);
        parameters.insert(TreasuryParameter::MinPayoutThreshold, 1);

        Self {
            proposals: BTreeMap::new(),
            executed: BTreeMap::new(),
            voting_duration_epochs: DEFAULT_VOTING_DURATION_EPOCHS,
            timelock_epochs: DEFAULT_TIMELOCK_EPOCHS,
            parameters,
        }
    }

    /// Create a new proposal
    ///
    /// # Arguments
    /// * `proposal_id` - Unique proposal ID
    /// * `action` - Action to execute when approved
    /// * `current_epoch` - Current epoch
    /// * `proposer` - Identity creating the proposal
    /// * `description` - Proposal description
    ///
    /// # Returns
    /// Ok(()) if created, Err if proposal ID exists
    pub fn create_proposal(
        &mut self,
        proposal_id: ProposalId,
        action: TreasuryAction,
        current_epoch: u64,
        proposer: IdentityId,
        description: String,
    ) -> Result<(), GovernanceError> {
        // Check for duplicate
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::ProposalAlreadyExists(proposal_id));
        }

        // Validate action parameters
        self.validate_action(&action)?;

        // Create proposal
        let proposal = TreasuryProposal::new(
            proposal_id,
            action,
            current_epoch,
            self.voting_duration_epochs,
            proposer,
            description,
        );

        self.proposals.insert(proposal_id, proposal);
        Ok(())
    }

    /// Validate action parameters
    fn validate_action(&self, action: &TreasuryAction) -> Result<(), GovernanceError> {
        match action {
            TreasuryAction::Mint { amount, .. } => {
                if *amount == 0 {
                    return Err(GovernanceError::InvalidActionParameters(
                        "Mint amount cannot be zero".to_string(),
                    ));
                }
            }
            TreasuryAction::Burn { amount, .. } => {
                if *amount == 0 {
                    return Err(GovernanceError::InvalidActionParameters(
                        "Burn amount cannot be zero".to_string(),
                    ));
                }
            }
            TreasuryAction::CreateRole { name, annual_cap, per_epoch_cap, .. } => {
                if name.is_empty() {
                    return Err(GovernanceError::InvalidActionParameters(
                        "Role name cannot be empty".to_string(),
                    ));
                }
                if *annual_cap == 0 || *per_epoch_cap == 0 {
                    return Err(GovernanceError::InvalidActionParameters(
                        "Caps cannot be zero".to_string(),
                    ));
                }
            }
            TreasuryAction::UpdateParameter { new_value, .. } => {
                if *new_value == 0 {
                    return Err(GovernanceError::InvalidActionParameters(
                        "Parameter value cannot be zero".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Approve a proposal (called when DAO vote passes)
    ///
    /// # Arguments
    /// * `proposal_id` - Proposal to approve
    /// * `current_epoch` - Current epoch
    ///
    /// # Returns
    /// Ok(()) if approved, Err if invalid state
    pub fn approve_proposal(
        &mut self,
        proposal_id: &ProposalId,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(*proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::InvalidProposalStatus {
                proposal_id: *proposal_id,
                expected: ProposalStatus::Voting,
                actual: proposal.status,
            });
        }

        proposal.approve(current_epoch, self.timelock_epochs);
        Ok(())
    }

    /// Reject a proposal
    ///
    /// # Arguments
    /// * `proposal_id` - Proposal to reject
    pub fn reject_proposal(&mut self, proposal_id: &ProposalId) -> Result<(), GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(*proposal_id))?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::InvalidProposalStatus {
                proposal_id: *proposal_id,
                expected: ProposalStatus::Voting,
                actual: proposal.status,
            });
        }

        proposal.reject();
        Ok(())
    }

    /// Check if a proposal is ready for execution
    pub fn is_executable(&self, proposal_id: &ProposalId, current_epoch: u64) -> bool {
        self.proposals.get(proposal_id)
            .map_or(false, |p| p.is_executable(current_epoch))
    }

    /// Execute an approved proposal
    ///
    /// # Arguments
    /// * `proposal_id` - Proposal to execute
    /// * `current_epoch` - Current epoch
    ///
    /// # Returns
    /// The action to execute (caller must apply to kernel)
    pub fn begin_execution(
        &mut self,
        proposal_id: &ProposalId,
        current_epoch: u64,
    ) -> Result<TreasuryAction, GovernanceError> {
        // Check already executed
        if self.executed.contains_key(proposal_id) {
            return Err(GovernanceError::InvalidProposalStatus {
                proposal_id: *proposal_id,
                expected: ProposalStatus::Approved,
                actual: ProposalStatus::Executed,
            });
        }

        let proposal = self.proposals.get(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(*proposal_id))?;

        // Check status
        if proposal.status != ProposalStatus::Approved {
            return Err(GovernanceError::InvalidProposalStatus {
                proposal_id: *proposal_id,
                expected: ProposalStatus::Approved,
                actual: proposal.status,
            });
        }

        // Check timelock
        if let Some(expires) = proposal.timelock_expires_epoch {
            if current_epoch < expires {
                return Err(GovernanceError::TimelockNotExpired {
                    proposal_id: *proposal_id,
                    expires_epoch: expires,
                    current_epoch,
                });
            }
        }

        // Check expiration
        if proposal.has_expired(current_epoch) {
            return Err(GovernanceError::ProposalExpired(*proposal_id));
        }

        Ok(proposal.action.clone())
    }

    /// Complete execution (mark as executed after kernel applies changes)
    pub fn complete_execution(
        &mut self,
        proposal_id: &ProposalId,
        current_epoch: u64,
        success: bool,
        details: Option<&str>,
    ) -> Result<ExecutionResult, GovernanceError> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(*proposal_id))?;

        let result = if success {
            proposal.execute(current_epoch);
            ExecutionResult::success(*proposal_id, current_epoch, proposal.action.clone())
        } else {
            ExecutionResult::failure(
                *proposal_id,
                current_epoch,
                proposal.action.clone(),
                details.unwrap_or("Execution failed"),
            )
        };

        self.executed.insert(*proposal_id, result.clone());

        // Update parameters if this was a parameter update
        if success {
            if let TreasuryAction::UpdateParameter { parameter, new_value } = &proposal.action {
                self.parameters.insert(*parameter, *new_value);
            }
        }

        Ok(result)
    }

    /// Process epoch changes - expire old proposals
    pub fn process_epoch(&mut self, current_epoch: u64) {
        let expired_ids: Vec<ProposalId> = self.proposals.iter()
            .filter(|(_, p)| p.has_expired(current_epoch))
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            if let Some(proposal) = self.proposals.get_mut(&id) {
                proposal.expire();
            }
        }
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: &ProposalId) -> Option<&TreasuryProposal> {
        self.proposals.get(proposal_id)
    }

    /// Get all proposals in voting phase
    pub fn get_voting_proposals(&self) -> Vec<&TreasuryProposal> {
        self.proposals.values()
            .filter(|p| p.status == ProposalStatus::Voting)
            .collect()
    }

    /// Get all executable proposals
    pub fn get_executable_proposals(&self, current_epoch: u64) -> Vec<&TreasuryProposal> {
        self.proposals.values()
            .filter(|p| p.is_executable(current_epoch))
            .collect()
    }

    /// Get all proposals requiring execution (in timelock)
    pub fn get_pending_execution(&self) -> Vec<&TreasuryProposal> {
        self.proposals.values()
            .filter(|p| p.status == ProposalStatus::Approved)
            .collect()
    }

    /// Get execution result for a proposal
    pub fn get_execution_result(&self, proposal_id: &ProposalId) -> Option<&ExecutionResult> {
        self.executed.get(proposal_id)
    }

    /// Get parameter value
    pub fn get_parameter(&self, parameter: TreasuryParameter) -> u64 {
        self.parameters.get(&parameter).copied().unwrap_or(0)
    }

    /// Get all parameters
    pub fn get_all_parameters(&self) -> &BTreeMap<TreasuryParameter, u64> {
        &self.parameters
    }

    /// Set timelock duration (for testing or emergency)
    pub fn set_timelock_epochs(&mut self, epochs: u64) {
        self.timelock_epochs = epochs;
    }

    /// Set voting duration
    pub fn set_voting_duration_epochs(&mut self, epochs: u64) {
        self.voting_duration_epochs = epochs;
    }

    /// Get proposal count by status
    pub fn proposal_count(&self, status: ProposalStatus) -> usize {
        self.proposals.values().filter(|p| p.status == status).count()
    }

    /// Get total execution count
    pub fn execution_count(&self) -> usize {
        self.executed.len()
    }

    /// Clean up old executed proposals (keep last N)
    pub fn cleanup_executed(&mut self, keep_last: usize) {
        if self.executed.len() > keep_last {
            let to_remove: Vec<ProposalId> = self.executed.keys()
                .take(self.executed.len() - keep_last)
                .copied()
                .collect();

            for id in to_remove {
                self.executed.remove(&id);
            }
        }
    }
}

impl Default for GovernanceExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::governance_types::MintReason;

    fn test_proposal_id(n: u8) -> ProposalId {
        [n; 32]
    }

    fn test_identity_id() -> IdentityId {
        [10u8; 32]
    }

    fn test_role_id() -> RoleId {
        [20u8; 32]
    }

    #[test]
    fn test_create_and_approve_proposal() {
        let mut executor = GovernanceExecutor::new();

        // Create proposal
        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::Mint {
                recipient: test_identity_id(),
                amount: 10_000,
                reason: MintReason::TreasuryAllocation,
            },
            1, // epoch 1
            test_identity_id(),
            "Test mint".to_string(),
        ).unwrap();

        // Check it's in voting
        let proposal = executor.get_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Voting);

        // Approve
        executor.approve_proposal(&test_proposal_id(1), 3).unwrap();

        // Check it's approved
        let proposal = executor.get_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Approved);
        assert!(proposal.timelock_expires_epoch.is_some());
    }

    #[test]
    fn test_reject_proposal() {
        let mut executor = GovernanceExecutor::new();

        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyPause,
            1,
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        executor.reject_proposal(&test_proposal_id(1)).unwrap();

        let proposal = executor.get_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_execution_flow() {
        let mut executor = GovernanceExecutor::new();
        executor.set_timelock_epochs(1);

        // Create
        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::Mint {
                recipient: test_identity_id(),
                amount: 10_000,
                reason: MintReason::TreasuryAllocation,
            },
            1,
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        // Approve at epoch 3
        executor.approve_proposal(&test_proposal_id(1), 3).unwrap();

        // Not executable yet (epoch 3, timelock expires epoch 4)
        assert!(!executor.is_executable(&test_proposal_id(1), 3));

        // Executable at epoch 4
        assert!(executor.is_executable(&test_proposal_id(1), 4));

        // Begin execution
        let action = executor.begin_execution(&test_proposal_id(1), 4).unwrap();
        assert!(matches!(action, TreasuryAction::Mint { .. }));

        // Complete execution
        let result = executor.complete_execution(&test_proposal_id(1), 4, true, None).unwrap();
        assert!(result.success);

        // Check it's marked executed
        let proposal = executor.get_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    #[test]
    fn test_timelock_not_expired() {
        let mut executor = GovernanceExecutor::new();
        executor.set_timelock_epochs(2);

        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyPause,
            1,
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        executor.approve_proposal(&test_proposal_id(1), 3).unwrap();

        // Try to execute before timelock expires
        let result = executor.begin_execution(&test_proposal_id(1), 4);
        assert!(matches!(result, Err(GovernanceError::TimelockNotExpired { .. })));
    }

    #[test]
    fn test_proposal_expiration() {
        let mut executor = GovernanceExecutor::new();
        executor.set_voting_duration_epochs(2);

        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyPause,
            1, // created epoch 1
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        // Process at epoch 5 (well past voting end of epoch 3)
        executor.process_epoch(5);

        let proposal = executor.get_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Expired);
    }

    #[test]
    fn test_duplicate_proposal_fails() {
        let mut executor = GovernanceExecutor::new();

        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyPause,
            1,
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        let result = executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyResume,
            2,
            test_identity_id(),
            "Duplicate".to_string(),
        );

        assert!(matches!(result, Err(GovernanceError::ProposalAlreadyExists(_))));
    }

    #[test]
    fn test_invalid_mint_amount() {
        let mut executor = GovernanceExecutor::new();

        let result = executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::Mint {
                recipient: test_identity_id(),
                amount: 0, // Invalid
                reason: MintReason::TreasuryAllocation,
            },
            1,
            test_identity_id(),
            "Test".to_string(),
        );

        assert!(matches!(result, Err(GovernanceError::InvalidActionParameters(_))));
    }

    #[test]
    fn test_parameter_update() {
        let mut executor = GovernanceExecutor::new();
        executor.set_timelock_epochs(0); // Instant execution for test

        // Create parameter update proposal
        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::UpdateParameter {
                parameter: TreasuryParameter::MaxEpochPayout,
                new_value: 200_000,
            },
            1,
            test_identity_id(),
            "Increase max payout".to_string(),
        ).unwrap();

        // Approve and execute
        executor.approve_proposal(&test_proposal_id(1), 2).unwrap();
        let _ = executor.begin_execution(&test_proposal_id(1), 2).unwrap();
        executor.complete_execution(&test_proposal_id(1), 2, true, None).unwrap();

        // Check parameter was updated
        assert_eq!(executor.get_parameter(TreasuryParameter::MaxEpochPayout), 200_000);
    }

    #[test]
    fn test_get_executable_proposals() {
        let mut executor = GovernanceExecutor::new();
        executor.set_timelock_epochs(1);

        // Create and approve two proposals
        for i in 1..=2 {
            executor.create_proposal(
                test_proposal_id(i),
                TreasuryAction::EmergencyPause,
                1,
                test_identity_id(),
                format!("Test {}", i),
            ).unwrap();
            executor.approve_proposal(&test_proposal_id(i), 2).unwrap();
        }

        // Both should be executable at epoch 3
        let executable = executor.get_executable_proposals(3);
        assert_eq!(executable.len(), 2);
    }

    #[test]
    fn test_idempotent_execution() {
        let mut executor = GovernanceExecutor::new();
        executor.set_timelock_epochs(0);

        executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::EmergencyPause,
            1,
            test_identity_id(),
            "Test".to_string(),
        ).unwrap();

        executor.approve_proposal(&test_proposal_id(1), 2).unwrap();

        // First execution succeeds
        let _ = executor.begin_execution(&test_proposal_id(1), 2).unwrap();
        executor.complete_execution(&test_proposal_id(1), 2, true, None).unwrap();

        // Second execution fails (already executed)
        let result = executor.begin_execution(&test_proposal_id(1), 3);
        assert!(matches!(result, Err(GovernanceError::InvalidProposalStatus { .. })));
    }

    #[test]
    fn test_proposal_counts() {
        let mut executor = GovernanceExecutor::new();

        // Create 3 proposals
        for i in 1..=3 {
            executor.create_proposal(
                test_proposal_id(i),
                TreasuryAction::EmergencyPause,
                1,
                test_identity_id(),
                format!("Test {}", i),
            ).unwrap();
        }

        assert_eq!(executor.proposal_count(ProposalStatus::Voting), 3);

        // Reject one
        executor.reject_proposal(&test_proposal_id(1)).unwrap();
        assert_eq!(executor.proposal_count(ProposalStatus::Voting), 2);
        assert_eq!(executor.proposal_count(ProposalStatus::Rejected), 1);
    }

    #[test]
    fn test_create_role_validation() {
        let mut executor = GovernanceExecutor::new();

        // Empty name should fail
        let result = executor.create_proposal(
            test_proposal_id(1),
            TreasuryAction::CreateRole {
                role_id: test_role_id(),
                name: "".to_string(),
                annual_cap: 100_000,
                lifetime_cap: None,
                per_epoch_cap: 10_000,
            },
            1,
            test_identity_id(),
            "Test".to_string(),
        );

        assert!(matches!(result, Err(GovernanceError::InvalidActionParameters(_))));
    }
}
