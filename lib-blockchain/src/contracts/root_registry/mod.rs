//! Root Registry Contract Module
//!
//! [Issue #655] Phase 0: Domain Reservation Enforcement
//! [Issue #657] Phase 2: dao. Prefix Enforcement - Architectural Decisions
//!
//! Authoritative `.sov` naming system registry implementing:
//! - Reserved welfare namespaces ({food,health,edu,housing,energy}.dao.sov)
//! - `dao.` subdomain semantics (Phase 2: virtual resolution)
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
//! - **dao. Prefix Enforcement (Phase 2)**: dao.X is virtual, never stored
//!
//! # Components
//!
//! - [`types`]: Core state model (NameRecord, NameStatus, NameClassification)
//! - [`validation`]: Name parsing, classification, and verification
//! - [`operations`]: Operation guards and invariant enforcement
//! - [`core`]: RootRegistry implementation with in-memory storage
//! - [`namespace_policy`]: Namespace policy enforcement
//! - [`delegation_tree`]: Parent-child relationship tracking
//! - [`dao_prefix_router`]: Phase 2 - Virtual dao.X resolution (Issue #657)
//!
//! # Related Modules (to be implemented)
//!
//! - `commercial_registry`: Open registration under policy
//! - `welfare_dao_registry`: Per-sector registries
//! - `verification_module`: VC anchoring, attestations

pub mod core;
pub mod dao_prefix_router;
pub mod delegation_tree;
pub mod namespace_policy;
pub mod operations;
pub mod types;
pub mod validation;
pub mod welfare_issuer_adapter;

#[cfg(test)]
mod tests;

// Re-export core registry
pub use core::{CoreNameRecord, CoreStoredRecord, RootRegistry};

// Re-export core types
pub use types::{
    hash_name,
    is_zero_name_hash,

    limits,
    // Utility functions
    normalize_name,
    // Constants
    timing,
    Address,
    AppealStatus,
    BlockHeight,
    CustodianId,
    DaoId,
    DelegateTarget,
    EffectiveStatus,
    GovernanceDelegation,
    GovernancePointer,
    // Governance (Phase 2: Issue #657)
    GovernanceRecord,
    GovernanceResolution,
    GovernanceStatus,
    // Legacy/Storage
    LegacyDomainRecord,
    LifecycleFields,

    LifecycleParams,
    NameClass,
    // Classification
    NameClassification,
    NameHash,
    // Core record
    NameRecord,

    // Status and lifecycle
    NameStatus,
    // Core identity types
    PublicKey,
    ReasonCode,
    RenewalRecord,

    ReservedReason,

    ResolutionResult as TypesResolutionResult,

    RevokedRecord,
    StoredRecord,

    SuspensionAuthority,
    SuspensionReason,
    Timestamp,

    // History
    TransferRecord,
    VCReference,
    VerificationError,
    // Verification
    VerificationLevel,
    VerificationProof,
    // Welfare
    WelfareSector,
    ZkProofData,

    // Zone controller
    ZoneController,

    WELFARE_SECTORS,
};

// Re-export validation functions
pub use validation::{
    check_high_risk_labels, compute_name_hash, is_high_risk_label, parse_and_validate,
    validate_verification_level, ParsedName, ValidationError, ValidationResult,
};

// Re-export operations
pub use operations::{
    DelegateGuard, OperationError, OperationResult, RegisterGuard, RenewGuard, ResolutionResult,
    RevocationRequester, RevokeGuard, TransferGuard,
};

// Re-export namespace policy
pub use namespace_policy::NamespacePolicy;

// Re-export delegation tree
pub use delegation_tree::DelegationTree;

// Re-export dao prefix router (Phase 2: Issue #657)
pub use dao_prefix_router::{DaoPrefixRegistrationError, DaoPrefixRouter};

// Re-export welfare issuer adapter (Phase 3: Issue #658)
pub use welfare_issuer_adapter::{
    BindingStatus, DaoVerificationPolicy, IssuanceResult, PendingClaim, SectorBinding,
    SuspensionReason as WelfareSuspensionReason, WelfareIssuerAdapter, WelfareIssuerError,
    WelfareMetadata,
};
