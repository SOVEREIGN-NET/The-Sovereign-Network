//! DAO Registry Contract Module
//!
//! Constitutional ledger for DAO identity and registration.
//! Provides append-only, deterministic DAO registration with immutable identity.

pub mod registry;

// Re-export core types and functions
pub use registry::{DAORegistry, DAOEntry, derive_dao_id};

// Re-export Phase 3 sector claim types (Issue #658)
pub use registry::{
    SectorClaim, SectorClaimStatus, ApprovalVerifierType,
};
