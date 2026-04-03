//! Governance Contracts Module
//!
//! This module contains all governance-related contracts for the SOV economic system:
//!
//! - `entity_registry`: DOC 01 - Phase 0 Primitives & Fiduciary Mapping
//! - `governance`: DOC 02 - Governance & Treasury Rails (Week 2)
//! - `sunset`: DOC 03 - CBE Sunset Contract (Week 3)
//! - `voting`: DOC 05 - Voting Primitives (TODO)
//! - `compensation_attestor`: DOC 06 - Compensation Fairness (TODO)

pub mod citizen_role;
pub mod entity_registry;
pub mod governance;
pub mod sunset;

// Re-export key types
pub use citizen_role::{CitizenRegistry, CitizenRole, CitizenRoleError, RegistryStats};
pub use entity_registry::{EntityRegistry, EntityRegistryError, EntityType, Role};
pub use governance::{
    Governance, GovernanceError, Proposal, ProposalCategory, ProposalStatus, Vote, VoteType,
    MAJORITY_THRESHOLD_BASIS_POINTS, MIN_VOTING_POWER_FOR_PROPOSAL,
    SUPERMAJORITY_THRESHOLD_BASIS_POINTS, TIMELOCK_DELAY_SECONDS, VOTING_PERIOD_SECONDS,
};
pub use sunset::{
    SpendingPolicy, StateTransitionProposal, Sunset, SunsetError, SunsetState,
    FINAL_PAYOUT_TO_NONPROFIT_PERCENTAGE, RESTRICTED_MIN_DURATION,
    SUNSET_STATE_TRANSITION_TIMELOCK, WIND_DOWN_MIN_DURATION,
};
