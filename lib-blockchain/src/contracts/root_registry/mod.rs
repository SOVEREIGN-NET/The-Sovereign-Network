//! Root Registry Contract Module
//!
//! [Issue #655] Phase 0: Domain Reservation Enforcement
//!
//! Authoritative `.sov` naming system registry implementing:
//! - Reserved welfare namespaces ({food,health,edu,housing,energy}.dao.sov)
//! - `dao.` subdomain semantics
//! - Hierarchical delegation
//! - Verification levels (L0-L3)
//! - State lifecycle management
//! - Fee routing integration
//!
//! # Architecture
//!
//! This module provides the foundational types and invariants for the `.sov`
//! naming system. It enforces:
//!
//! - **Root Authority**: RootGovernance for normal operations, EmergencyMultisig
//!   for break-glass scenarios only
//! - **Reserved Namespaces**: Welfare sectors cannot be squatted commercially
//! - **Verification Requirements**: L2 for commercial, L1 for welfare delegated,
//!   L3 for constitutional actors
//! - **State Lifecycle**: Active → Expired → Released with proper grace periods
//!
//! # Components
//!
//! - [`types`]: Core state model (NameRecord, NameStatus, NameClassification)
//! - [`validation`]: Name parsing, classification, and verification
//! - [`operations`]: Operation guards and invariant enforcement
//! - [`core`]: RootRegistry implementation with in-memory storage
//! - [`namespace_policy`]: Namespace policy enforcement
//! - [`delegation_tree`]: Parent-child relationship tracking
//!
//! # Related Modules (to be implemented)
//!
//! - `commercial_registry`: Open registration under policy
//! - `welfare_dao_registry`: Per-sector registries
//! - `dao_prefix_router`: Enforces dao. convention
//! - `verification_module`: VC anchoring, attestations

pub mod types;
pub mod validation;
pub mod operations;
pub mod core;
pub mod namespace_policy;
pub mod delegation_tree;

#[cfg(test)]
mod tests;

// Re-export core registry
pub use core::{RootRegistry, CoreNameRecord, CoreStoredRecord};

// Re-export core types
pub use types::{
    // Core identity types
    PublicKey, Address, NameHash, DaoId, BlockHeight, Timestamp,

    // Verification
    VerificationLevel,

    // Classification
    NameClassification,
    NameClass, ReservedReason,

    // Status and lifecycle
    NameStatus, SuspensionReason, SuspensionAuthority,
    ReasonCode, AppealStatus, RevokedRecord,

    // Governance
    GovernanceRecord, VCReference,

    // History
    TransferRecord, RenewalRecord,

    // Zone controller
    ZoneController,

    // Core record
    NameRecord,

    // Legacy/Storage
    LegacyDomainRecord, StoredRecord,

    // Welfare
    WelfareSector, WELFARE_SECTORS,

    // Utility functions
    normalize_name, hash_name, is_zero_name_hash,

    // Constants
    timing, limits,
};

// Re-export validation functions
pub use validation::{
    ValidationError, ValidationResult,
    ParsedName,
    parse_and_validate,
    validate_verification_level,
    is_high_risk_label,
    check_high_risk_labels,
    compute_name_hash,
};

// Re-export operations
pub use operations::{
    OperationError, OperationResult,
    RegisterGuard, RenewGuard, TransferGuard, DelegateGuard, RevokeGuard,
    RevocationRequester, ResolutionResult,
};

// Re-export namespace policy
pub use namespace_policy::NamespacePolicy;

// Re-export delegation tree
pub use delegation_tree::DelegationTree;
