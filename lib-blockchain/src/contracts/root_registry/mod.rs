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

// Re-export core types
pub use types::{
    // Core identity types
    PublicKey, Address, NameHash, DaoId, BlockHeight, Timestamp,

    // Verification
    VerificationLevel,

    // Classification
    NameClassification,

    // Status and lifecycle
    NameStatus, SuspensionReason, SuspensionAuthority,
    ReasonCode, AppealStatus, RevokedRecord,

    // Governance
    GovernanceRecord, VCReference,

    // History
    TransferRecord, RenewalRecord,

    // Core record
    NameRecord,

    // Welfare
    WelfareSector, WELFARE_SECTORS,

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

