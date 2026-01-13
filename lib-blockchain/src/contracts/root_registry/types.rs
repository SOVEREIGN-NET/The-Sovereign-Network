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

/// Block height timestamp
pub type BlockHeight = u64;

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

    // === Governance ===
    /// Governance pointer for dao.X resolution
    pub governance_pointer: Option<GovernanceRecord>,

    // === Lifecycle ===
    /// Current status in the lifecycle
    pub status: NameStatus,
    /// Block height when registered
    pub registered_at: BlockHeight,
    /// When the registration expires (unix timestamp)
    pub expires_at: Timestamp,
    /// Grace period end (when in grace state)
    pub grace_ends_at: Option<Timestamp>,
    /// When suspended (if applicable)
    pub suspended_at: Option<Timestamp>,
    /// Who suspended (if applicable)
    pub suspended_by: Option<SuspensionAuthority>,

    // === Transfer Lock ===
    /// When the transfer lock expires (24h after registration/renewal)
    pub transfer_lock_until: Option<Timestamp>,

    // === Audit Trail ===
    /// History of ownership transfers
    pub transfer_history: Vec<TransferRecord>,
    /// History of renewals
    pub renewal_history: Vec<RenewalRecord>,
}

impl NameRecord {
    /// Check if this domain has an active transfer lock
    pub fn has_transfer_lock(&self, current_time: Timestamp) -> bool {
        self.transfer_lock_until
            .map(|lock_until| current_time < lock_until)
            .unwrap_or(false)
    }

    /// Check if this domain is in its grace period
    pub fn is_in_grace_period(&self, current_time: Timestamp) -> bool {
        match &self.status {
            NameStatus::Expired { grace_ends } => current_time < *grace_ends,
            NameStatus::RevocationPending { grace_ends, .. } => current_time < *grace_ends,
            _ => false,
        }
    }

    /// Check if this domain has expired (past grace period)
    pub fn has_fully_expired(&self, current_time: Timestamp) -> bool {
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
pub mod timing {
    /// Renewal window: 90 days before expiry (in seconds)
    pub const RENEWAL_WINDOW_SECS: u64 = 90 * 24 * 60 * 60;

    /// Expiration grace period: 30 days after expiry (in seconds)
    pub const EXPIRATION_GRACE_SECS: u64 = 30 * 24 * 60 * 60;

    /// Revocation grace period (dispute): 7 days minimum (in seconds)
    pub const REVOCATION_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

    /// Transfer lock duration: 24 hours after registration/renewal (in seconds)
    pub const TRANSFER_LOCK_SECS: u64 = 24 * 60 * 60;

    /// Governance timelock minimum: 7 days (in seconds)
    pub const GOVERNANCE_TIMELOCK_SECS: u64 = 7 * 24 * 60 * 60;

    /// Sector addition timelock: 30 days (in seconds)
    pub const SECTOR_ADDITION_TIMELOCK_SECS: u64 = 30 * 24 * 60 * 60;
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
            status: NameStatus::Active,
            registered_at: 100,
            expires_at: 1000000,
            grace_ends_at: None,
            suspended_at: None,
            suspended_by: None,
            transfer_lock_until: Some(200),
            transfer_history: vec![],
            renewal_history: vec![],
        };

        assert!(record.has_transfer_lock(150));
        assert!(!record.has_transfer_lock(250));
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
