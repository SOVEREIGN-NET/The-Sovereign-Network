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
pub mod policy;
pub mod principal;
pub mod types;

pub use decision::{AccessDecision, ReasonCode};
pub use policy::AccessPolicy;
pub use principal::SecurityPrincipal;
pub use types::{
    AccessDomain, AccessOperation, Capability, Did, Role, SubjectRelation,
};
