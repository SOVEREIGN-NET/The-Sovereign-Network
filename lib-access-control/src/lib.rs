//! Sovereign Network Access Control Layer
//!
//! Centralized, relationship-aware policy engine for identity and resource access.
//!
//! Non-negotiable invariants:
//! - No raw identity objects leave the core. Only scoped views are returned.
//! - Every read requires a principal. Even system calls declare identity.
//! - Access is evaluated per (principal, subject, domain, operation).
//! - Graph traversal is protected, not just individual fields.
//! - Default = DENY. No implicit allow anywhere.
//! - Every decision produces a machine-readable reason code.

pub mod decision;
pub mod grant;
pub mod grant_auth;
pub mod grant_registry;
pub mod policy;
pub mod principal;
pub mod types;

#[cfg(test)]
mod matrix_tests;

pub use decision::{AccessDecision, ReasonCode};
pub use grant::{grants_allow, ScopedGrant, MAX_GRANTS_PER_PRINCIPAL};
pub use grant_auth::{
    grant_exercise_message, protocol_may_offer, verify_grant_proof, DevOkVerifier,
    GrantAuthDescriptor, GrantAuthError, GrantAuthScheme, GrantClass, GrantExerciseProof,
    GrantRecord, GrantSignatureVerifier, GrantStatus, IssuerKind, RejectAllVerifier,
    GRANT_PROOF_MAX_SKEW_SECS,
};
pub use grant_registry::GrantRegistry;
pub use policy::{check_graph_edge, AccessPolicy};
pub use principal::SecurityPrincipal;
pub use types::{
    AccessDomain, AccessOperation, Capability, Did, Role, SubjectRelation,
};
