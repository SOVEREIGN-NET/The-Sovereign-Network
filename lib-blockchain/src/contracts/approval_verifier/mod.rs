//! Approval Verifier Framework (Issue #658)
//!
//! This module provides a trait-based framework for verifying DAO approval
//! of welfare subdomain issuance. Different DAOs may use different approval
//! mechanisms (governance votes, multisig, delegated verifiers).
//!
//! # Architecture
//!
//! ```text
//! IssuanceApprovalVerifier (trait)
//!       │
//!       ├── GovernanceVoteVerifier (on-chain proposal verification)
//!       │
//!       ├── MultisigVerifier (threshold signature verification)
//!       │
//!       └── DelegatedVerifier (external verifier contract)
//! ```
//!
//! # Usage
//!
//! DAOs register their preferred approval mechanism when binding to a sector.
//! The WelfareIssuerAdapter routes approval verification through the
//! appropriate verifier implementation.

pub mod traits;
pub mod governance_vote;
pub mod multisig;
pub mod delegated;

pub use traits::{
    ApprovalProof, IssuanceApprovalVerifier, IssuanceRequest, VerificationError,
    VerificationResult,
};
pub use governance_vote::GovernanceVoteVerifier;
pub use multisig::MultisigVerifier;
pub use delegated::DelegatedVerifier;
