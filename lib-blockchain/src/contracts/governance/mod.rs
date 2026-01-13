//! Governance Contracts Module
//!
//! This module contains all governance-related contracts for the SOV economic system:
//!
//! - `entity_registry`: DOC 01 - Phase 0 Primitives & Fiduciary Mapping
//! - `governance`: DOC 02 - Governance & Treasury Rails (Week 2)
//! - `sunset`: DOC 03 - CBE Sunset Contract (TODO)
//! - `voting`: DOC 05 - Voting Primitives (TODO)
//! - `compensation_attestor`: DOC 06 - Compensation Fairness (TODO)

pub mod entity_registry;
pub mod governance;

// Re-export key types
pub use entity_registry::{EntityRegistry, EntityType, Role, EntityRegistryError};
pub use governance::{
    Governance, Proposal, Vote,
    GovernanceError, ProposalStatus, VoteType, ProposalCategory,
    VOTING_PERIOD_SECONDS, TIMELOCK_DELAY_SECONDS,
    MAJORITY_THRESHOLD_BASIS_POINTS, SUPERMAJORITY_THRESHOLD_BASIS_POINTS,
    MIN_VOTING_POWER_FOR_PROPOSAL,
};
