//! Domain Name Types and State Model
//!
//! [Issue #655] Phase 0: Domain Reservation Enforcement - State Model
//!
//! This module defines the core types for the `.sov` naming system including:
//! - Name records and ownership
//! - Name classification (Reserved, Commercial, Welfare)
//! - Verification levels (L0-L3)
//! - State lifecycle management
//! - Governance pointers for dao.X resolution

use lib_types::primitives::BlockHeight;
use serde::{Deserialize, Serialize};

// ============================================================================
// Core Identity Types
// ============================================================================

/// 32-byte public key for owner/controller identification
pub type PublicKey = [u8; 32];

/// Contract address for on-chain governance
pub type Address = [u8; 32];

/// 32-byte name hash (BLAKE3)
pub type NameHash = [u8; 32];

/// DAO identifier
pub type DaoId = [u8; 32];


/// Unix timestamp in seconds
pub type Timestamp = u64;

// ============================================================================
// Verification Levels
// ============================================================================

/// Verification level for identity authentication
///
/// # Levels
/// - L0: Unverified - Not allowed for any `.sov` root issuance
/// - L1: Natural Person / Basic DID - Wallet-bound DID + liveness/anti-sybil signal
/// - L2: Verified Entity - Legal entity verification anchored via VC
/// - L3: Constitutional Actor - Core Welfare DAO or Root-level institution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationLevel {
    /// Unverified - Not allowed for any `.sov` root issuance
    L0Unverified,
    /// Natural Person / Basic DID - Wallet-bound DID + liveness/anti-sybil
    L1BasicDID,
    /// Verified Entity - Legal entity verification anchored via VC
    L2VerifiedEntity,
    /// Constitutional Actor - Core Welfare DAO or Root-level institution
    L3ConstitutionalActor,
}

impl VerificationLevel {
    /// Check if this level meets or exceeds the minimum required level
    pub fn meets_minimum(&self, minimum: VerificationLevel) -> bool {
        self.as_u8() >= minimum.as_u8()
    }

    /// Convert to numeric level for comparison
    pub fn as_u8(&self) -> u8 {
        match self {
            VerificationLevel::L0Unverified => 0,
            VerificationLevel::L1BasicDID => 1,
            VerificationLevel::L2VerifiedEntity => 2,
            VerificationLevel::L3ConstitutionalActor => 3,
        }
    }
}

impl Default for VerificationLevel {
    fn default() -> Self {
        VerificationLevel::L0Unverified
    }
}

// ============================================================================
// Phase 5: Verification Proof Types
// ============================================================================

/// ZK proof data (minimal representation; actual format provided by lib-proofs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofData {
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

/// Verification proof for .sov domain registration operations
///
/// [Phase 5] Required for all .sov root issuance. Proves possession of
/// identity credentials meeting the required verification level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProof {
    pub credential_ref: [u8; 32],
    pub zk_proof: ZkProofData,
    /// Context hash: hash(domain_name || operation || nonce) — prevents replay
    pub context: [u8; 32],
    pub nonce: u64,
}

impl VerificationProof {
    pub fn new(
        credential_ref: [u8; 32],
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
        context: [u8; 32],
        nonce: u64,
    ) -> Self {
        Self {
            credential_ref,
            zk_proof: ZkProofData { proof_data, public_inputs },
            context,
            nonce,
        }
    }

    pub fn has_proof_data(&self) -> bool {
        !self.zk_proof.proof_data.is_empty()
    }
}

/// Errors related to domain verification
///
/// [Phase 5] Explicit, typed errors for verification failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationError {
    InsufficientLevel { required: VerificationLevel, provided: VerificationLevel },
    MissingProof,
    InvalidProof { reason: String },
    CredentialExpired { expired_at: Timestamp },
    ContextMismatch,
    L0NotAllowedForSov,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InsufficientLevel { required, provided } => {
                write!(f, "Insufficient verification level: required {:?}, provided {:?}", required, provided)
            }
            VerificationError::MissingProof => {
                write!(f, "Verification proof required for .sov domain registration")
            }
            VerificationError::InvalidProof { reason } => {
                write!(f, "Invalid verification proof: {}", reason)
            }
            VerificationError::CredentialExpired { expired_at } => {
                write!(f, "Credential expired at timestamp {}", expired_at)
            }
            VerificationError::ContextMismatch => {
                write!(f, "Verification proof context mismatch (possible replay)")
            }
            VerificationError::L0NotAllowedForSov => {
                write!(f, "L0 (unverified) identities cannot register .sov domains")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

// ============================================================================
// Name Classification
// ============================================================================

/// Classification of a domain name determining its registration rules
///
/// # Classifications
/// - ReservedWelfare: {food,health,edu,housing,energy}.dao.sov - Only RootGovernance
/// - ReservedMeta: dao.sov - Unregistrable, points to RootGovernance
/// - ReservedByRule: dao.X for any X - Controller of X.sov
/// - WelfareDelegated: *.food.sov, *.health.sov, etc. - Respective Welfare DAO
/// - Commercial: Everything else under .sov - CommercialRegistry with L2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NameClassification {
    /// Reserved Welfare sector roots: {food,health,edu,housing,energy}.dao.sov
    ReservedWelfare,
    /// Reserved meta-governance: dao.sov (unregistrable)
    ReservedMeta,
    /// Reserved by rule: dao.X for any X (controller of X.sov)
    ReservedByRule,
    /// Welfare delegated subdomains: *.food.sov, *.health.sov, etc.
    WelfareDelegated,
    /// Commercial domains: Everything else under .sov
    Commercial,
}

impl NameClassification {
    /// Get the minimum verification level required for this classification
    pub fn minimum_verification_level(&self) -> VerificationLevel {
        match self {
            NameClassification::ReservedWelfare => VerificationLevel::L3ConstitutionalActor,
            NameClassification::ReservedMeta => VerificationLevel::L3ConstitutionalActor, // N/A in practice
            NameClassification::ReservedByRule => VerificationLevel::L1BasicDID, // Inherits from parent
            NameClassification::WelfareDelegated => VerificationLevel::L1BasicDID, // L1 floor, sector can raise
            NameClassification::Commercial => VerificationLevel::L2VerifiedEntity,
        }
    }

    /// Check if this classification allows commercial registration
    pub fn allows_commercial_registration(&self) -> bool {
        matches!(self, NameClassification::Commercial)
    }

    /// Check if this is a reserved classification
    pub fn is_reserved(&self) -> bool {
        matches!(
            self,
            NameClassification::ReservedWelfare
                | NameClassification::ReservedMeta
                | NameClassification::ReservedByRule
        )
    }
}

// ============================================================================
// Alternative Classification (for RootRegistry core)
// ============================================================================

/// Reason for reservation in NameClass
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservedReason {
    MetaGovernance,
    WelfareRoot,
    GovernanceAdded,
    HighRiskLabel,
}

/// Alternative name classification used by RootRegistry core
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameClass {
    Reserved { reason: ReservedReason },
    Commercial { min_verification: VerificationLevel },
    WelfareChild {
        sector: WelfareSector,
        zone_root_hash: NameHash,
    },
    DaoPrefixed { parent_hash: NameHash },
}

// ============================================================================
// Name Status and Lifecycle
// ============================================================================

/// Reason for domain suspension
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspensionReason {
    /// Dispute filed against the domain
    Dispute { dispute_id: [u8; 32] },
    /// Policy violation detected
    PolicyViolation { violation_code: String },
    /// Emergency suspension by multisig
    Emergency { reason: String },
    /// Governance action pending
    GovernancePending { proposal_id: [u8; 32] },
}

/// Authority that can suspend a domain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspensionAuthority {
    /// Root governance (on-chain, timelocked)
    RootGovernance,
    /// Emergency multisig (break-glass only)
    EmergencyMultisig,
    /// Dispute resolution module
    DisputeModule,
    /// Issuing Welfare DAO (for welfare delegations)
    WelfareDao { dao_id: [u8; 32] },
}

/// Reason code for revocation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonCode {
    /// Owner voluntarily released
    OwnerVoluntary,
    /// Policy violation confirmed
    PolicyViolation,
    /// Dispute resolution outcome
    DisputeOutcome,
    /// Constitutional breach
    ConstitutionalBreach,
    /// Parent domain revoked
    ParentRevoked,
    /// Expiration without renewal
    ExpirationLapsed,
}

/// Appeal status for revocation appeals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppealStatus {
    /// Appeal filed, pending review
    Pending { filed_at: Timestamp },
    /// Appeal under active review
    UnderReview { reviewer: Address },
    /// Appeal approved, domain restored
    Approved { decided_at: Timestamp },
    /// Appeal rejected
    Rejected { decided_at: Timestamp, reason: String },
    /// Appeal withdrawn by owner
    Withdrawn { withdrawn_at: Timestamp },
}

/// Record stored when a domain is revoked (tombstone)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedRecord {
    /// When the domain was revoked
    pub revoked_at: Timestamp,
    /// Reason for revocation
    pub reason_code: ReasonCode,
    /// Authority that performed the revocation
    pub revoking_authority: Address,
    /// Appeal status if an appeal was filed
    pub appeal_status: Option<AppealStatus>,
}

/// Current status of a name in its lifecycle
///
/// # State Transitions
/// ```text
/// Revocation path:
///   Active → [Suspended] → RevocationPending (7d grace) → Revoked
///
/// Expiration path:
///   Active → Expired (30d grace) → Released/Available
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameStatus {
    /// Domain is active and operational
    Active,
    /// Domain is suspended (temporary, reversible)
    Suspended { reason: SuspensionReason },
    /// Domain suspended due to parent state change
    SuspendedByParent,
    /// Domain is pending revocation with grace period
    RevocationPending {
        /// When the grace period ends
        grace_ends: Timestamp,
        /// Optional appeal ID if appeal filed
        appeal_id: Option<[u8; 32]>,
    },
    /// Domain has been revoked (with tombstone record)
    Revoked { tombstone: RevokedRecord },
    /// Domain has expired but is in grace period
    Expired {
        /// When the grace period ends
        grace_ends: Timestamp,
    },
    /// Domain has been released and is available for registration
    Released,
}

impl NameStatus {
    /// Check if the domain is in an active/usable state
    pub fn is_active(&self) -> bool {
        matches!(self, NameStatus::Active)
    }

    /// Check if the domain can be renewed
    pub fn can_renew(&self) -> bool {
        matches!(self, NameStatus::Active | NameStatus::Expired { .. })
    }

    /// Check if the domain can be transferred
    pub fn can_transfer(&self) -> bool {
        matches!(self, NameStatus::Active)
    }

    /// Check if the domain is in any suspended state
    pub fn is_suspended(&self) -> bool {
        matches!(
            self,
            NameStatus::Suspended { .. }
                | NameStatus::SuspendedByParent
                | NameStatus::RevocationPending { .. }
        )
    }

    /// Check if the domain is available for new registration
    pub fn is_available(&self) -> bool {
        matches!(self, NameStatus::Released)
    }
}

impl Default for NameStatus {
    fn default() -> Self {
        NameStatus::Released
    }
}

// ============================================================================
// Effective Status (Phase 6: Derived Lifecycle State)
// ============================================================================

/// Effective status derived from timestamps + explicit states
///
/// # Phase 6: Hybrid State Model
/// This is the **derived** status computed from:
/// 1. Explicit governance states (suspension, revocation)
/// 2. Timestamp-derived lifecycle (expiry, grace periods)
///
/// Unlike `NameStatus` which is stored, `EffectiveStatus` is computed
/// at query time via `effective_status(current_height)`.
///
/// # Resolver Semantics
/// | Status              | Content | Operations Allowed      |
/// |---------------------|---------|-------------------------|
/// | Active              | Enabled | Transfer, Renew, Update |
/// | ExpiredInGrace      | Disabled| Renew only              |
/// | RevokedInGrace      | Disabled| Appeal only             |
/// | Suspended           | Disabled| None (governance)       |
/// | ReturnedToGovernance| None    | Custodian only          |
/// | Released            | None    | New registration        |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EffectiveStatus {
    /// Domain is active and fully operational
    Active,
    /// Domain has expired but is within grace period
    /// Content serving disabled, renewal allowed with penalty
    ExpiredInGrace,
    /// Domain is pending revocation with grace period for appeal
    /// Content serving disabled, operations blocked
    RevokedInGrace,
    /// Domain is suspended (governance action)
    /// Content serving disabled until lifted
    Suspended,
    /// Domain returned to governance custodian (welfare/reserved)
    /// No content, awaiting custodian action
    ReturnedToGovernance,
    /// Domain released and available for registration (commercial)
    /// NXDOMAIN equivalent
    Released,
}

impl EffectiveStatus {
    /// Check if domain content should be served
    pub fn is_content_enabled(&self) -> bool {
        matches!(self, EffectiveStatus::Active)
    }

    /// Check if domain can be renewed
    pub fn can_renew(&self) -> bool {
        matches!(self, EffectiveStatus::Active | EffectiveStatus::ExpiredInGrace)
    }

    /// Check if domain can be transferred
    pub fn can_transfer(&self) -> bool {
        matches!(self, EffectiveStatus::Active)
    }

    /// Check if domain is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, EffectiveStatus::Released | EffectiveStatus::ReturnedToGovernance)
    }

    /// Check if domain is available for new registration
    pub fn is_available_for_registration(&self) -> bool {
        matches!(self, EffectiveStatus::Released)
    }
}

// ============================================================================
// Lifecycle Fields Trait (Phase 6: Shared Lifecycle Logic)
// ============================================================================

/// Trait for types that have lifecycle fields and can compute effective status
///
/// # Phase 6: Shared Lifecycle Logic
/// This trait unifies lifecycle method implementations across `NameRecord` and
/// `CoreNameRecord`, eliminating code duplication while maintaining type safety.
///
/// Implementors must provide access to their lifecycle fields and specify
/// how to determine terminal status based on domain classification.
pub trait LifecycleFields {
    /// Get current explicit status
    fn status(&self) -> &NameStatus;
    /// Get expiry height
    fn expires_at_height(&self) -> BlockHeight;
    /// Get renewal window start height
    fn renewal_window_start_height(&self) -> BlockHeight;
    /// Get grace period end height
    fn renew_grace_until_height(&self) -> BlockHeight;
    /// Get revocation grace end height (if in revocation)
    fn revoke_grace_until_height(&self) -> Option<BlockHeight>;
    /// Get custodian (if returned to governance)
    fn custodian(&self) -> Option<&CustodianId>;
    /// Determine terminal status based on classification (Released vs ReturnedToGovernance)
    fn terminal_status_for_classification(&self) -> EffectiveStatus;

    /// Compute the effective status from timestamps + explicit states
    ///
    /// # Phase 6: Hybrid State Model
    /// Order of evaluation matters - evaluate top to bottom:
    /// 1. Terminal states (Released, ReturnedToGovernance)
    /// 2. Revocation path (governance-initiated)
    /// 3. Suspension (dominates resolution)
    /// 4. Normal expiry path
    ///
    /// # Invariant L6: No Zombies
    /// This function is called on every touch to ensure deterministic transitions.
    fn effective_status(&self, current_height: BlockHeight) -> EffectiveStatus {
        // 1. Terminal states - already finalized
        if matches!(self.status(), NameStatus::Released) {
            return EffectiveStatus::Released;
        }
        if self.custodian().is_some() && matches!(self.status(), NameStatus::Revoked { .. }) {
            return EffectiveStatus::ReturnedToGovernance;
        }

        // 2. Revocation path (governance-initiated)
        if matches!(self.status(), NameStatus::RevocationPending { .. }) {
            if let Some(grace_until) = self.revoke_grace_until_height() {
                if current_height <= grace_until {
                    return EffectiveStatus::RevokedInGrace;
                } else {
                    // Past revocation grace - needs finalization
                    return self.terminal_status_for_classification();
                }
            }
        }

        // 3. Suspension dominates resolution (may also be expired)
        if matches!(self.status(), NameStatus::Suspended { .. } | NameStatus::SuspendedByParent) {
            return EffectiveStatus::Suspended;
        }

        // 4. Normal expiry path
        if current_height <= self.expires_at_height() {
            EffectiveStatus::Active
        } else if current_height <= self.renew_grace_until_height() {
            EffectiveStatus::ExpiredInGrace
        } else {
            // Past grace period - needs finalization
            self.terminal_status_for_classification()
        }
    }

    /// Check if this domain is in its grace period (block height)
    fn is_in_grace_period(&self, current_height: BlockHeight) -> bool {
        current_height > self.expires_at_height()
            && current_height <= self.renew_grace_until_height()
    }

    /// Check if this domain has expired (past grace period)
    fn has_fully_expired(&self, current_height: BlockHeight) -> bool {
        current_height > self.renew_grace_until_height()
    }

    /// Check if domain can be renewed at current height
    fn can_renew_at(&self, current_height: BlockHeight) -> bool {
        let effective = self.effective_status(current_height);
        effective.can_renew()
            && current_height >= self.renewal_window_start_height()
    }

    /// Calculate renewal fee with optional late penalty
    ///
    /// # Invariant L8
    /// Renewal in grace incurs penalty fee (standard + late_penalty_percent).
    fn calculate_renewal_fee(
        &self,
        current_height: BlockHeight,
        base_fee: u64,
        late_penalty_percent: u8,
    ) -> u64 {
        if current_height <= self.expires_at_height() {
            // Before expiry: standard fee
            base_fee
        } else if current_height <= self.renew_grace_until_height() {
            // In grace period: standard + penalty
            let penalty = base_fee * late_penalty_percent as u64 / 100;
            base_fee.saturating_add(penalty)
        } else {
            // Past grace: cannot renew
            0
        }
    }
}

/// Macro to implement the common LifecycleFields accessors for a type.
///
/// This eliminates duplication between CoreNameRecord and NameRecord implementations.
/// The `terminal_expr` parameter is a closure/expression that returns the terminal status.
#[macro_export]
macro_rules! impl_lifecycle_fields_accessors {
    ($type:ty, $terminal_expr:expr) => {
        impl LifecycleFields for $type {
            fn status(&self) -> &NameStatus {
                &self.status
            }

            fn expires_at_height(&self) -> BlockHeight {
                self.expires_at_height
            }

            fn renewal_window_start_height(&self) -> BlockHeight {
                self.renewal_window_start_height
            }

            fn renew_grace_until_height(&self) -> BlockHeight {
                self.renew_grace_until_height
            }

            fn revoke_grace_until_height(&self) -> Option<BlockHeight> {
                self.revoke_grace_until_height
            }

            fn custodian(&self) -> Option<&CustodianId> {
                self.custodian.as_ref()
            }

            fn terminal_status_for_classification(&self) -> EffectiveStatus {
                #[allow(clippy::redundant_closure_call)]
                ($terminal_expr)(self)
            }
        }
    };
}

// Use the macro for NameRecord implementation
impl_lifecycle_fields_accessors!(NameRecord, |record: &NameRecord| {
    match record.classification {
        NameClassification::Commercial => EffectiveStatus::Released,
        _ => EffectiveStatus::ReturnedToGovernance,
    }
});

impl From<NameStatus> for EffectiveStatus {
    /// Convert NameStatus to EffectiveStatus (basic conversion)
    ///
    /// # Warning
    /// This conversion does NOT have access to the custodian field, so it cannot
    /// distinguish between Released and ReturnedToGovernance for Revoked status.
    /// For accurate lifecycle state, use `NameRecord::effective_status(height)` or
    /// `CoreNameRecord::effective_status(height)` instead.
    fn from(status: NameStatus) -> Self {
        match status {
            NameStatus::Active => EffectiveStatus::Active,
            NameStatus::Suspended { .. } => EffectiveStatus::Suspended,
            NameStatus::SuspendedByParent => EffectiveStatus::Suspended,
            NameStatus::RevocationPending { .. } => EffectiveStatus::RevokedInGrace,
            // Note: This assumes Released; use effective_status() for custodian-aware logic
            NameStatus::Revoked { .. } => EffectiveStatus::Released,
            NameStatus::Expired { .. } => EffectiveStatus::ExpiredInGrace,
            NameStatus::Released => EffectiveStatus::Released,
        }
    }
}

// ============================================================================
// Custodian Types (Phase 6: Post-Grace Governance)
// ============================================================================

/// Custodian identifier for domains returned to governance
///
/// # Phase 6: Post-Grace Behavior
/// - Commercial domains → Released (available for registration)
/// - Welfare children → Return to sector DAO control
/// - Reserved/Welfare roots → Return to RootGovernance control
///
/// # Invariant L3, L4
/// Post-grace finalization depends on domain classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CustodianId {
    /// Root governance (for reserved roots, welfare sector roots)
    RootGovernance,
    /// Sector DAO (for welfare children like *.food.sov)
    SectorDao(DaoId),
}

impl CustodianId {
    /// Check if this is root governance
    pub fn is_root_governance(&self) -> bool {
        matches!(self, CustodianId::RootGovernance)
    }

    /// Get the DAO ID if this is a sector DAO custodian
    pub fn sector_dao_id(&self) -> Option<&DaoId> {
        match self {
            CustodianId::SectorDao(id) => Some(id),
            _ => None,
        }
    }
}

// ============================================================================
// Lifecycle Parameters (Phase 6: Governable Durations)
// ============================================================================

/// Governable lifecycle parameters
///
/// # Phase 6: Governance Control
/// These parameters can be modified via RootGovernance proposal
/// with timelock, but cannot go below constitutional floors.
///
/// # Invariant L7
/// Grace durations are governable but have constitutional floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleParams {
    /// Renewal window before expiry (in blocks)
    pub renewal_window_blocks: BlockHeight,
    /// Expiration grace period (in blocks)
    pub expiry_grace_blocks: BlockHeight,
    /// Revocation grace period (in blocks)
    pub revocation_grace_blocks: BlockHeight,
    /// Late renewal penalty percentage (0-50)
    pub late_renewal_penalty_percent: u8,
}

impl LifecycleParams {
    /// Create new params, enforcing constitutional floors
    pub fn new(
        renewal_window_blocks: BlockHeight,
        expiry_grace_blocks: BlockHeight,
        revocation_grace_blocks: BlockHeight,
        late_renewal_penalty_percent: u8,
    ) -> Self {
        Self {
            renewal_window_blocks,
            expiry_grace_blocks: expiry_grace_blocks.max(timing::MIN_EXPIRATION_GRACE_BLOCKS),
            revocation_grace_blocks: revocation_grace_blocks.max(timing::MIN_REVOCATION_GRACE_BLOCKS),
            late_renewal_penalty_percent: late_renewal_penalty_percent.min(timing::MAX_LATE_RENEWAL_PENALTY_PERCENT),
        }
    }

    /// Validate params against constitutional floors
    pub fn validate(&self) -> Result<(), String> {
        if self.expiry_grace_blocks < timing::MIN_EXPIRATION_GRACE_BLOCKS {
            return Err(format!(
                "Expiry grace {} below constitutional floor {}",
                self.expiry_grace_blocks,
                timing::MIN_EXPIRATION_GRACE_BLOCKS
            ));
        }
        if self.revocation_grace_blocks < timing::MIN_REVOCATION_GRACE_BLOCKS {
            return Err(format!(
                "Revocation grace {} below constitutional floor {}",
                self.revocation_grace_blocks,
                timing::MIN_REVOCATION_GRACE_BLOCKS
            ));
        }
        if self.late_renewal_penalty_percent > timing::MAX_LATE_RENEWAL_PENALTY_PERCENT {
            return Err(format!(
                "Late penalty {}% exceeds maximum {}%",
                self.late_renewal_penalty_percent,
                timing::MAX_LATE_RENEWAL_PENALTY_PERCENT
            ));
        }
        Ok(())
    }
}

impl Default for LifecycleParams {
    fn default() -> Self {
        Self {
            renewal_window_blocks: timing::RENEWAL_WINDOW_BLOCKS,
            expiry_grace_blocks: timing::EXPIRATION_GRACE_BLOCKS,
            revocation_grace_blocks: timing::REVOCATION_GRACE_BLOCKS,
            late_renewal_penalty_percent: timing::DEFAULT_LATE_RENEWAL_PENALTY_PERCENT,
        }
    }
}

/// Per-class lifecycle parameter overrides
///
/// Different domain classifications may have different lifecycle rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassLifecycleParams {
    /// Parameters for commercial domains
    pub commercial: LifecycleParams,
    /// Parameters for welfare child domains (*.food.sov, etc.)
    pub welfare_child: LifecycleParams,
    /// Parameters for welfare/reserved roots
    pub welfare_root: LifecycleParams,
}

impl Default for ClassLifecycleParams {
    fn default() -> Self {
        Self {
            commercial: LifecycleParams::default(),
            welfare_child: LifecycleParams::default(),
            welfare_root: LifecycleParams::default(),
        }
    }
}

// ============================================================================
// Governance Types
// ============================================================================

/// Governance resolution record for dao.X domains
///
/// `dao.X` resolves to a multi-resolution record containing
/// governance contract, DID endpoint, and application endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRecord {
    /// Authoritative on-chain governance contract address
    pub governance_contract: Address,
    /// Off-chain DID service endpoint (optional)
    pub did_service_endpoint: Option<String>,
    /// UI application endpoint (optional)
    pub application_endpoint: Option<String>,
}

// ============================================================================
// Phase 2: dao. Prefix Enforcement Types (Issue #657)
// ============================================================================

/// Governance pointer configuration for dao.X resolution
///
/// Stored on the parent domain `X`, not on `dao.X` (which is virtual).
/// When resolving `dao.X`, this pointer determines where governance lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernancePointer {
    /// On-chain governance contract address
    pub contract: Option<Address>,
    /// Off-chain governance DID service endpoint
    pub did: Option<String>,
}

impl GovernancePointer {
    /// Create an empty governance pointer
    pub fn empty() -> Self {
        Self {
            contract: None,
            did: None,
        }
    }

    /// Check if the pointer has any governance endpoint configured
    pub fn is_configured(&self) -> bool {
        self.contract.is_some() || self.did.is_some()
    }
}

impl Default for GovernancePointer {
    fn default() -> Self {
        Self::empty()
    }
}

/// Target for governance delegation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegateTarget {
    /// Delegate to an on-chain contract
    Contract(Address),
    /// Delegate to an off-chain DID
    Did(String),
}

/// Governance delegation for dao.X control
///
/// Allows the owner of `X` to delegate governance authority
/// for `dao.X` to another contract or DID.
///
/// # Invariants
/// - Delegation is explicit and must be set by the owner of X
/// - Delegation persists across domain transfers
/// - Delegation can be revoked by the new owner after transfer
/// - Expired delegations are treated as revoked
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDelegation {
    /// Delegated controller (contract or DID)
    pub delegate: DelegateTarget,
    /// Optional expiration timestamp (None = permanent until revoked)
    pub expires_at: Option<Timestamp>,
}

impl GovernanceDelegation {
    /// Check if the delegation is active at the given time
    pub fn is_active(&self, current_time: Timestamp) -> bool {
        match self.expires_at {
            Some(expires) => current_time < expires,
            None => true,
        }
    }

    /// Get the active delegate address if the delegation is valid
    pub fn active_delegate(&self, current_time: Timestamp) -> Option<&DelegateTarget> {
        if self.is_active(current_time) {
            Some(&self.delegate)
        } else {
            None
        }
    }
}

/// Status of governance for a dao.X resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceStatus {
    /// Governance is active and operational
    Active,
    /// Governance is suspended (parent domain suspended)
    Suspended,
    /// Governance is revoked (parent domain revoked)
    Revoked,
    /// Parent domain has expired
    ParentExpired,
}

/// Resolution result for dao.X queries
///
/// This is returned when resolving `dao.X` - a virtual governance view
/// derived from the parent domain `X`'s configuration.
///
/// # Invariants
/// - dao.X is NEVER stored as a NameRecord
/// - dao.X resolution is ALWAYS derived from X.governance_pointer
/// - If X doesn't exist, resolution returns NotFound (not this struct)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceResolution {
    /// The parent domain this governance is derived from
    pub parent_domain: String,
    /// Parent domain name hash
    pub parent_hash: NameHash,
    /// On-chain governance contract address
    pub governance_contract: Option<Address>,
    /// Off-chain governance DID service endpoint
    pub governance_did: Option<String>,
    /// Delegate address (if governance was explicitly delegated)
    pub delegate: Option<DelegateTarget>,
    /// Current governance status
    pub status: GovernanceStatus,
}

/// Result of a name resolution query
///
/// Distinguishes between standard domain resolution and
/// governance resolution for dao.* queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionResult {
    /// Standard domain resolution (content, endpoints)
    Domain(NameRecord),
    /// Governance resolution (dao.* queries)
    Governance(GovernanceResolution),
    /// Name not found
    NotFound,
    /// Invalid name (e.g., dao.dao.sov)
    Invalid { reason: String },
}

/// Reference to a verifiable credential
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VCReference {
    /// Issuer DID of the credential
    pub issuer_did: String,
    /// Credential ID or hash
    pub credential_id: [u8; 32],
    /// When the credential was issued
    pub issued_at: Timestamp,
    /// When the credential expires (if applicable)
    pub expires_at: Option<Timestamp>,
    /// Type of credential (e.g., "EntityVerification", "PersonVerification")
    pub credential_type: String,
}

// ============================================================================
// Transfer and Renewal History
// ============================================================================

/// Record of a domain transfer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecord {
    /// Previous owner
    pub from: PublicKey,
    /// New owner
    pub to: PublicKey,
    /// Block height when transfer occurred
    pub transferred_at: BlockHeight,
    /// Transaction hash of the transfer
    pub tx_hash: [u8; 32],
}

/// Record of a domain renewal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalRecord {
    /// Who renewed the domain
    pub renewed_by: PublicKey,
    /// Block height when renewal occurred
    pub renewed_at: BlockHeight,
    /// Previous expiration timestamp
    pub previous_expiry: Timestamp,
    /// New expiration timestamp
    pub new_expiry: Timestamp,
    /// Fee paid for renewal
    pub fee_paid: u64,
}

// ============================================================================
// Zone Controller (for delegation)
// ============================================================================

/// Zone controller for delegated issuance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneController {
    /// Contract address that can issue under this zone
    pub controller: PublicKey,
    /// The zone root this controller manages (hash of zone root)
    pub scope: NameHash,
    /// Optional expiration (None = permanent until revoked)
    pub expires_at: Option<u64>,
}

// ============================================================================
// Name Record (Core State)
// ============================================================================

/// Complete record for a registered domain name
///
/// This is the primary state structure for the `.sov` naming system.
/// Each registered name has a corresponding NameRecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    // === Identity ===
    /// Fully qualified name (e.g., "shoes.sov", "kitchen.food.sov")
    pub name: String,
    /// BLAKE3 hash of the name for indexing
    pub name_hash: NameHash,

    // === Ownership & Control ===
    /// Current owner's public key
    pub owner: PublicKey,
    /// Operational controller (if delegated, otherwise None)
    pub controller: Option<PublicKey>,
    /// Contract that can mint children (for zone delegation)
    pub zone_controller: Option<Address>,

    // === Hierarchy ===
    /// Parent name_hash (None for root-level like "shoes.sov")
    pub parent: Option<NameHash>,
    /// Depth in hierarchy (0 for root level)
    pub depth: u8,
    /// Classification determining registration rules
    pub classification: NameClassification,

    // === Verification ===
    /// Current verification level of the owner
    pub verification_level: VerificationLevel,
    /// Reference to anchored verifiable credential
    pub verification_proof: Option<VCReference>,
    /// Who issued/registered this name
    pub issuer: PublicKey,

    // === Governance (Phase 2: Issue #657) ===
    /// Governance pointer for dao.X resolution (legacy field)
    pub governance_pointer: Option<GovernanceRecord>,
    /// Phase 2: New governance pointer configuration
    pub governance_config: Option<GovernancePointer>,
    /// Phase 2: Optional delegation of dao.X control
    /// Allows owner to delegate governance authority to another contract/DID
    pub governance_delegate: Option<GovernanceDelegation>,

    // === Lifecycle (Phase 6: Block Height Authority) ===
    /// Current explicit status in the lifecycle
    /// Note: Use `effective_status(height)` for derived status
    pub status: NameStatus,
    /// Block height when registered
    pub registered_at: BlockHeight,

    // --- Authoritative Block Heights (Phase 6) ---
    /// When the registration expires (block height) - AUTHORITATIVE
    pub expires_at_height: BlockHeight,
    /// When renewal window opens (block height)
    /// Calculated as: expires_at_height - renewal_window_blocks
    pub renewal_window_start_height: BlockHeight,
    /// When expiry grace period ends (block height)
    /// Calculated as: expires_at_height + expiry_grace_blocks
    pub renew_grace_until_height: BlockHeight,
    /// When revocation grace period ends (block height)
    /// Only set for governance-initiated revocations (Invariant L5)
    pub revoke_grace_until_height: Option<BlockHeight>,

    // --- Legacy/Display Fields ---
    /// When the registration expires (unix timestamp) - DISPLAY ONLY
    /// Derived in clients/indexers, not authoritative on-chain
    #[deprecated(note = "Use expires_at_height for on-chain logic")]
    pub expires_at: Timestamp,
    /// Grace period end (when in grace state) - DISPLAY ONLY
    #[deprecated(note = "Use renew_grace_until_height for on-chain logic")]
    pub grace_ends_at: Option<Timestamp>,

    // --- Suspension ---
    /// When suspended (block height)
    pub suspended_at: Option<BlockHeight>,
    /// Who suspended (if applicable)
    pub suspended_by: Option<SuspensionAuthority>,

    // --- Custodian (Phase 6: Post-Grace Governance) ---
    /// Custodian for domains returned to governance
    /// Set when domain transitions to ReturnedToGovernance state
    pub custodian: Option<CustodianId>,

    // === Transfer Lock ===
    /// When the transfer lock expires (block height)
    pub transfer_lock_until: Option<BlockHeight>,

    // === Audit Trail ===
    /// History of ownership transfers
    pub transfer_history: Vec<TransferRecord>,
    /// History of renewals
    pub renewal_history: Vec<RenewalRecord>,
}

impl NameRecord {
    // ========================================================================
    // Phase 6: Lifecycle Queries (Unique to NameRecord)
    // ========================================================================
    //
    // Note: Core lifecycle methods (effective_status, is_in_grace_period, etc.)
    // are provided by the LifecycleFields trait implementation below.

    /// Check if this domain has an active transfer lock (block height)
    pub fn has_transfer_lock(&self, current_height: BlockHeight) -> bool {
        self.transfer_lock_until
            .map(|lock_until| current_height < lock_until)
            .unwrap_or(false)
    }

    /// Check if this domain is in renewal window
    pub fn is_in_renewal_window(&self, current_height: BlockHeight) -> bool {
        current_height >= self.renewal_window_start_height
            && current_height <= self.renew_grace_until_height
    }

    /// Check if this domain is in revocation grace period
    pub fn is_in_revocation_grace(&self, current_height: BlockHeight) -> bool {
        if let Some(grace_until) = self.revoke_grace_until_height {
            matches!(self.status, NameStatus::RevocationPending { .. })
                && current_height <= grace_until
        } else {
            false
        }
    }

    /// Check if domain can be transferred at current height
    pub fn can_transfer_at(&self, current_height: BlockHeight) -> bool {
        let effective = self.effective_status(current_height);
        effective.can_transfer() && !self.has_transfer_lock(current_height)
    }

    // ========================================================================
    // Renewal Execution (Phase 6)
    // ========================================================================

    /// Extend registration by duration, recalculating lifecycle heights
    pub fn extend_registration(
        &mut self,
        duration_blocks: BlockHeight,
        params: &LifecycleParams,
        current_height: BlockHeight,
    ) {
        // Extend from current expiry (not current time)
        let new_expiry = self.expires_at_height.saturating_add(duration_blocks);

        self.expires_at_height = new_expiry;
        self.renewal_window_start_height = new_expiry.saturating_sub(params.renewal_window_blocks);
        self.renew_grace_until_height = new_expiry.saturating_add(params.expiry_grace_blocks);

        // Reset transfer lock
        self.transfer_lock_until = Some(current_height.saturating_add(timing::TRANSFER_LOCK_BLOCKS));

        // Clear expired state if was in grace
        if matches!(self.status, NameStatus::Expired { .. }) {
            self.status = NameStatus::Active;
        }
    }

    // ========================================================================
    // Legacy/Compatibility Methods
    // ========================================================================

    /// Check if this domain is in its grace period (legacy: unix timestamp)
    /// DEPRECATED: Use is_in_grace_period(block_height) instead
    #[deprecated(note = "Use is_in_grace_period(block_height) for on-chain logic")]
    pub fn is_in_grace_period_legacy(&self, current_time: Timestamp) -> bool {
        match &self.status {
            NameStatus::Expired { grace_ends } => current_time < *grace_ends,
            NameStatus::RevocationPending { grace_ends, .. } => current_time < *grace_ends,
            _ => false,
        }
    }

    /// Check if this domain has expired (legacy: unix timestamp)
    /// DEPRECATED: Use has_fully_expired(block_height) instead
    #[deprecated(note = "Use has_fully_expired(block_height) for on-chain logic")]
    pub fn has_fully_expired_legacy(&self, current_time: Timestamp) -> bool {
        match &self.status {
            NameStatus::Expired { grace_ends } => current_time >= *grace_ends,
            _ => false,
        }
    }

    /// Get the depth of this name in the hierarchy (0 for root-level)
    pub fn get_depth(&self) -> usize {
        self.name.matches('.').count().saturating_sub(1) // -1 for .sov TLD
    }
}

// ============================================================================
// Legacy/Storage Types (for migration compatibility)
// ============================================================================

/// Legacy domain record for migration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyDomainRecord {
    pub domain: String,
    pub owner: String,
    pub expires_at: u64,
}

/// Versioned storage record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredRecord {
    V1(LegacyDomainRecord),
    V2(NameRecord),
}

// ============================================================================
// Welfare Sector Types
// ============================================================================

/// Immutable original welfare sectors that cannot be removed
pub const WELFARE_SECTORS: &[&str] = &["food", "health", "edu", "housing", "energy"];

/// Welfare sector identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WelfareSector {
    Food,
    Health,
    Education,
    Housing,
    Energy,
    /// Extended sector (governance-added)
    Extended { sector_id: u32 },
}

impl WelfareSector {
    /// Get the subdomain name for this sector
    pub fn subdomain(&self) -> &str {
        match self {
            WelfareSector::Food => "food",
            WelfareSector::Health => "health",
            WelfareSector::Education => "edu",
            WelfareSector::Housing => "housing",
            WelfareSector::Energy => "energy",
            WelfareSector::Extended { .. } => "extended", // Would need registry lookup
        }
    }

    /// Get the full reserved welfare domain
    pub fn dao_domain(&self) -> String {
        format!("{}.dao.sov", self.subdomain())
    }

    /// Check if this is an immutable original sector
    pub fn is_original(&self) -> bool {
        !matches!(self, WelfareSector::Extended { .. })
    }

    /// Try to parse a sector from a subdomain string
    pub fn from_subdomain(subdomain: &str) -> Option<Self> {
        match subdomain.to_lowercase().as_str() {
            "food" => Some(WelfareSector::Food),
            "health" => Some(WelfareSector::Health),
            "edu" => Some(WelfareSector::Education),
            "housing" => Some(WelfareSector::Housing),
            "energy" => Some(WelfareSector::Energy),
            _ => None,
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Normalize a domain name (lowercase, trim)
pub fn normalize_name(name: &str) -> String {
    name.trim().to_lowercase()
}

/// Hash a name using BLAKE3
pub fn hash_name(name: &str) -> NameHash {
    use blake3::Hasher;
    let normalized = normalize_name(name);
    let mut hasher = Hasher::new();
    hasher.update(normalized.as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Check if a name hash is all zeros
pub fn is_zero_name_hash(name_hash: &NameHash) -> bool {
    name_hash.iter().all(|b| *b == 0)
}

// ============================================================================
// Timing Constants
// ============================================================================

/// Timing parameters for domain lifecycle management
///
/// # Phase 6: Block Height Authority
/// All lifecycle timestamps use block height (never wall-clock on-chain).
/// Wall-clock seconds are kept for display/client compatibility only.
///
/// # Invariant L1
/// Contract determinism requires block height. Wall-clock seconds create
/// nondeterministic forks when nodes disagree on time.
pub mod timing {
    /// Blocks per day (ideal, assuming 10-second block time)
    /// 86,400 seconds / 10 = 8,640 blocks
    ///
    /// We intentionally use 8,600 blocks/day instead of 8,640 to get an
    /// integer number of 100-block epochs per day:
    /// - 100 blocks/epoch
    /// - 8,600 blocks/day = 86 epochs/day
    ///
    /// This introduces a ~0.46% drift from the ideal 10-second-based day,
    /// which is acceptable because block height is the authoritative time
    /// source and wall-clock seconds are advisory only.
    pub const BLOCKS_PER_DAY: u64 = 8_600;

    /// Renewal window: 90 days before expiry (in blocks)
    pub const RENEWAL_WINDOW_BLOCKS: u64 = 90 * BLOCKS_PER_DAY;

    /// Expiration grace period: 30 days after expiry (in blocks)
    /// Invariant L2: Expired-in-grace domains resolve but with content disabled
    pub const EXPIRATION_GRACE_BLOCKS: u64 = 30 * BLOCKS_PER_DAY;

    /// Revocation grace period (dispute): 7 days minimum (in blocks)
    /// Invariant L5: Only applies to governance-initiated revocations
    pub const REVOCATION_GRACE_BLOCKS: u64 = 7 * BLOCKS_PER_DAY;

    /// Transfer lock duration: 24 hours after registration/renewal (in blocks)
    pub const TRANSFER_LOCK_BLOCKS: u64 = BLOCKS_PER_DAY;

    /// Governance timelock minimum: 7 days (in blocks)
    pub const GOVERNANCE_TIMELOCK_BLOCKS: u64 = 7 * BLOCKS_PER_DAY;

    /// Sector addition timelock: 30 days (in blocks)
    pub const SECTOR_ADDITION_TIMELOCK_BLOCKS: u64 = 30 * BLOCKS_PER_DAY;

    // === Legacy constants (for display/migration only) ===

    /// Renewal window: 90 days before expiry (in seconds) - DEPRECATED
    #[deprecated(note = "Use RENEWAL_WINDOW_BLOCKS for on-chain logic")]
    pub const RENEWAL_WINDOW_SECS: u64 = 90 * 24 * 60 * 60;

    /// Expiration grace period: 30 days after expiry (in seconds) - DEPRECATED
    #[deprecated(note = "Use EXPIRATION_GRACE_BLOCKS for on-chain logic")]
    pub const EXPIRATION_GRACE_SECS: u64 = 30 * 24 * 60 * 60;

    /// Revocation grace period: 7 days (in seconds) - DEPRECATED
    #[deprecated(note = "Use REVOCATION_GRACE_BLOCKS for on-chain logic")]
    pub const REVOCATION_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

    /// Transfer lock duration: 24 hours (in seconds) - DEPRECATED
    #[deprecated(note = "Use TRANSFER_LOCK_BLOCKS for on-chain logic")]
    pub const TRANSFER_LOCK_SECS: u64 = 24 * 60 * 60;

    /// Governance timelock: 7 days (in seconds) - DEPRECATED
    #[deprecated(note = "Use GOVERNANCE_TIMELOCK_BLOCKS for on-chain logic")]
    pub const GOVERNANCE_TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

    /// Sector addition timelock: 30 days (in seconds) - DEPRECATED
    #[deprecated(note = "Use SECTOR_ADDITION_TIMELOCK_BLOCKS for on-chain logic")]
    pub const SECTOR_ADDITION_TIMELOCK_SECS: u64 = 30 * 24 * 60 * 60;

    // === Constitutional Floors (minimum values, governance cannot reduce) ===

    /// Minimum expiration grace period: 7 days (in blocks)
    pub const MIN_EXPIRATION_GRACE_BLOCKS: u64 = 7 * BLOCKS_PER_DAY;

    /// Minimum revocation grace period: 3 days (in blocks)
    pub const MIN_REVOCATION_GRACE_BLOCKS: u64 = 3 * BLOCKS_PER_DAY;

    /// Maximum late renewal penalty: 50%
    pub const MAX_LATE_RENEWAL_PENALTY_PERCENT: u8 = 50;

    /// Default late renewal penalty: 20%
    pub const DEFAULT_LATE_RENEWAL_PENALTY_PERCENT: u8 = 20;
}

/// Depth and length limits
pub mod limits {
    /// Maximum delegation depth from .sov (default 8)
    pub const MAX_DEPTH: usize = 8;

    /// Maximum label length (standard DNS: 63 chars)
    pub const MAX_LABEL_LENGTH: usize = 63;

    /// Maximum total name length (standard DNS: 253 chars)
    pub const MAX_NAME_LENGTH: usize = 253;

    /// Minimum label length
    pub const MIN_LABEL_LENGTH: usize = 1;

    /// Premium pricing threshold (3x multiplier for <=6 chars)
    pub const PREMIUM_LENGTH_THRESHOLD: usize = 6;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_level_ordering() {
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L0Unverified));
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L1BasicDID));
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L2VerifiedEntity));
        assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L3ConstitutionalActor));

        assert!(!VerificationLevel::L1BasicDID.meets_minimum(VerificationLevel::L2VerifiedEntity));
        assert!(!VerificationLevel::L0Unverified.meets_minimum(VerificationLevel::L1BasicDID));
    }

    #[test]
    fn test_classification_verification_requirements() {
        assert_eq!(
            NameClassification::Commercial.minimum_verification_level(),
            VerificationLevel::L2VerifiedEntity
        );
        assert_eq!(
            NameClassification::WelfareDelegated.minimum_verification_level(),
            VerificationLevel::L1BasicDID
        );
        assert_eq!(
            NameClassification::ReservedWelfare.minimum_verification_level(),
            VerificationLevel::L3ConstitutionalActor
        );
    }

    #[test]
    fn test_name_status_transitions() {
        let active = NameStatus::Active;
        assert!(active.is_active());
        assert!(active.can_renew());
        assert!(active.can_transfer());
        assert!(!active.is_suspended());

        let expired = NameStatus::Expired { grace_ends: 1000 };
        assert!(!expired.is_active());
        assert!(expired.can_renew());
        assert!(!expired.can_transfer());

        let suspended = NameStatus::Suspended {
            reason: SuspensionReason::Emergency { reason: "test".into() },
        };
        assert!(!suspended.can_renew());
        assert!(!suspended.can_transfer());
        assert!(suspended.is_suspended());
    }

    #[test]
    fn test_welfare_sectors() {
        assert_eq!(WelfareSector::Food.subdomain(), "food");
        assert_eq!(WelfareSector::Health.dao_domain(), "health.dao.sov");
        assert!(WelfareSector::Food.is_original());
        assert!(!WelfareSector::Extended { sector_id: 1 }.is_original());

        assert_eq!(
            WelfareSector::from_subdomain("food"),
            Some(WelfareSector::Food)
        );
        assert_eq!(
            WelfareSector::from_subdomain("unknown"),
            None
        );
    }

    #[test]
    fn test_transfer_lock() {
        #[allow(deprecated)]
        let record = NameRecord {
            name: "test.sov".to_string(),
            name_hash: [0u8; 32],
            owner: [1u8; 32],
            controller: None,
            zone_controller: None,
            parent: None,
            depth: 0,
            classification: NameClassification::Commercial,
            verification_level: VerificationLevel::L2VerifiedEntity,
            verification_proof: None,
            issuer: [1u8; 32],
            governance_pointer: None,
            governance_config: None,
            governance_delegate: None,
            status: NameStatus::Active,
            registered_at: 100,
            // Phase 6: Block height fields
            expires_at_height: 1000000,
            renewal_window_start_height: 1000000 - timing::RENEWAL_WINDOW_BLOCKS,
            renew_grace_until_height: 1000000 + timing::EXPIRATION_GRACE_BLOCKS,
            revoke_grace_until_height: None,
            // Legacy fields (deprecated)
            expires_at: 0,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            custodian: None,
            transfer_lock_until: Some(200),
            transfer_history: vec![],
            renewal_history: vec![],
        };

        assert!(record.has_transfer_lock(150));
        assert!(!record.has_transfer_lock(250));
    }

    #[test]
    fn test_effective_status_active() {
        #[allow(deprecated)]
        let record = NameRecord {
            name: "test.sov".to_string(),
            name_hash: [0u8; 32],
            owner: [1u8; 32],
            controller: None,
            zone_controller: None,
            parent: None,
            depth: 0,
            classification: NameClassification::Commercial,
            verification_level: VerificationLevel::L2VerifiedEntity,
            verification_proof: None,
            issuer: [1u8; 32],
            governance_pointer: None,
            governance_config: None,
            governance_delegate: None,
            status: NameStatus::Active,
            registered_at: 100,
            expires_at_height: 1000000,
            renewal_window_start_height: 1000000 - timing::RENEWAL_WINDOW_BLOCKS,
            renew_grace_until_height: 1000000 + timing::EXPIRATION_GRACE_BLOCKS,
            revoke_grace_until_height: None,
            expires_at: 0,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            custodian: None,
            transfer_lock_until: None,
            transfer_history: vec![],
            renewal_history: vec![],
        };

        // Before expiry: Active
        assert_eq!(record.effective_status(500000), EffectiveStatus::Active);
        assert!(record.effective_status(500000).is_content_enabled());

        // After expiry but in grace: ExpiredInGrace
        let in_grace = record.expires_at_height + 1000;
        assert_eq!(record.effective_status(in_grace), EffectiveStatus::ExpiredInGrace);
        assert!(!record.effective_status(in_grace).is_content_enabled());
        assert!(record.effective_status(in_grace).can_renew());

        // Past grace: Released (commercial)
        let past_grace = record.renew_grace_until_height + 1;
        assert_eq!(record.effective_status(past_grace), EffectiveStatus::Released);
    }

    #[test]
    fn test_effective_status_welfare() {
        #[allow(deprecated)]
        let record = NameRecord {
            name: "farm.food.dao.sov".to_string(),
            name_hash: [0u8; 32],
            owner: [1u8; 32],
            controller: None,
            zone_controller: None,
            parent: Some([2u8; 32]),
            depth: 1,
            classification: NameClassification::WelfareDelegated,
            verification_level: VerificationLevel::L1BasicDID,
            verification_proof: None,
            issuer: [1u8; 32],
            governance_pointer: None,
            governance_config: None,
            governance_delegate: None,
            status: NameStatus::Active,
            registered_at: 100,
            expires_at_height: 1000000,
            renewal_window_start_height: 1000000 - timing::RENEWAL_WINDOW_BLOCKS,
            renew_grace_until_height: 1000000 + timing::EXPIRATION_GRACE_BLOCKS,
            revoke_grace_until_height: None,
            expires_at: 0,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            custodian: None,
            transfer_lock_until: None,
            transfer_history: vec![],
            renewal_history: vec![],
        };

        // Past grace: ReturnedToGovernance (welfare)
        let past_grace = record.renew_grace_until_height + 1;
        assert_eq!(record.effective_status(past_grace), EffectiveStatus::ReturnedToGovernance);
    }

    #[test]
    fn test_renewal_fee_calculation() {
        #[allow(deprecated)]
        let record = NameRecord {
            name: "test.sov".to_string(),
            name_hash: [0u8; 32],
            owner: [1u8; 32],
            controller: None,
            zone_controller: None,
            parent: None,
            depth: 0,
            classification: NameClassification::Commercial,
            verification_level: VerificationLevel::L2VerifiedEntity,
            verification_proof: None,
            issuer: [1u8; 32],
            governance_pointer: None,
            governance_config: None,
            governance_delegate: None,
            status: NameStatus::Active,
            registered_at: 100,
            expires_at_height: 1000000,
            renewal_window_start_height: 1000000 - timing::RENEWAL_WINDOW_BLOCKS,
            renew_grace_until_height: 1000000 + timing::EXPIRATION_GRACE_BLOCKS,
            revoke_grace_until_height: None,
            expires_at: 0,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            custodian: None,
            transfer_lock_until: None,
            transfer_history: vec![],
            renewal_history: vec![],
        };

        let base_fee = 1000;
        let penalty = 20; // 20%

        // Before expiry: base fee only
        assert_eq!(record.calculate_renewal_fee(500000, base_fee, penalty), 1000);

        // In grace period: base + penalty (1000 + 200 = 1200)
        let in_grace = record.expires_at_height + 1000;
        assert_eq!(record.calculate_renewal_fee(in_grace, base_fee, penalty), 1200);

        // Past grace: cannot renew (returns 0)
        let past_grace = record.renew_grace_until_height + 1;
        assert_eq!(record.calculate_renewal_fee(past_grace, base_fee, penalty), 0);
    }

    #[test]
    fn test_lifecycle_params_validation() {
        // Valid params
        let params = LifecycleParams::default();
        assert!(params.validate().is_ok());

        // Below floor - should be clamped in constructor
        let clamped = LifecycleParams::new(
            timing::RENEWAL_WINDOW_BLOCKS,
            1000, // Below MIN_EXPIRATION_GRACE_BLOCKS
            1000, // Below MIN_REVOCATION_GRACE_BLOCKS
            100,  // Above MAX_LATE_RENEWAL_PENALTY_PERCENT
        );
        assert_eq!(clamped.expiry_grace_blocks, timing::MIN_EXPIRATION_GRACE_BLOCKS);
        assert_eq!(clamped.revocation_grace_blocks, timing::MIN_REVOCATION_GRACE_BLOCKS);
        assert_eq!(clamped.late_renewal_penalty_percent, timing::MAX_LATE_RENEWAL_PENALTY_PERCENT);
    }

    #[test]
    fn test_hash_name() {
        let hash1 = hash_name("test.sov");
        let hash2 = hash_name("TEST.SOV");
        assert_eq!(hash1, hash2, "Hash should be case-insensitive");

        let hash3 = hash_name("other.sov");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("  Test.SOV  "), "test.sov");
        assert_eq!(normalize_name("HELLO"), "hello");
    }
}
