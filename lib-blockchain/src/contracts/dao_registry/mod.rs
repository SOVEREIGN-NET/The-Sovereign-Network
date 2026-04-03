//! DAO Registry Contract Module
//!
//! Constitutional ledger for DAO identity and registration.
//! Provides append-only, deterministic DAO registration with immutable identity.

pub mod registry;

// Re-export core types and functions
pub use registry::{derive_dao_id, DAOEntry, DAORegistry};

// Re-export Phase 3 sector claim types (Issue #658)
pub use registry::{ApprovalVerifierType, SectorClaim, SectorClaimStatus};
