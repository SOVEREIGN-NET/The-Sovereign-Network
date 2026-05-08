//! Canonical observer admission types for the Sovereign Network.
//!
//! Pure data types for identity-backed observer admission, sponsorship,
//! proof-level policy, trusted sync-source selection, and revocation.
//!
//! Rule: keep behavior here minimal and type-local. Domain crates own
//! lifecycle logic, validation, policy enforcement/overrides, and state
//! transitions. This module primarily defines the shapes, plus lightweight,
//! pure helper methods that are intrinsic to those shapes.

use serde::{Deserialize, Serialize};

// =============================================================================
// STATUS
// =============================================================================

/// Lifecycle status of an observer admission record.
///
/// `Active` is required for an observer to sync or serve data, but
/// record-level authorization may impose additional checks (e.g. expiry).
/// All other states deny bootstrap, gap-fill, and long-range block import.
///
/// # Serialization contract
///
/// - **JSON** (`serde_json`): variant name string — `"Pending"`, `"Active"`,
///   `"Suspended"`, `"Revoked"`. This is the stable external wire format.
///   Golden representations are pinned in the test suite.
/// - **Binary** (`bincode` v1.x): variant *ordinal index* as a
///   little-endian `u32` (4 bytes). The `#[repr(u8)]` annotation controls
///   Rust memory layout only and has no effect on serde output. Stability
///   depends on variant **ordering** — appending new variants is safe;
///   inserting or removing variants is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)] // layout only — not the serialized discriminant; see doc comment above
pub enum ObserverAdmissionStatus {
    /// Enrollment submitted, awaiting approval.
    Pending = 0,
    /// Admitted and authorized to sync.
    Active = 1,
    /// Temporarily denied — may be reinstated.
    Suspended = 2,
    /// Permanently denied — requires new enrollment.
    Revoked = 3,
}

impl ObserverAdmissionStatus {
    /// Whether this status permits sync and data access.
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Active)
    }
}

// =============================================================================
// PROOF LEVEL
// =============================================================================

/// Sponsoring user proof level that gates observer capacity.
///
/// Higher proof levels allow sponsoring more observers and receive
/// higher rate-limit tiers. Exact quota mappings are governance-
/// configurable; this type encodes the tier identity only.
///
/// # Serialization contract
///
/// - **JSON** (`serde_json`): variant name string — `"None"`, `"Basic"`,
///   `"Enhanced"`, `"Organizational"`.
/// - **Binary** (`bincode` v1.x): variant *ordinal index* as a
///   little-endian `u32` (4 bytes). `#[repr(u8)]` is Rust-layout only;
///   it does not affect serde output. Do not reorder variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)] // layout only — not the serialized discriminant; see doc comment above
pub enum ObserverProofLevel {
    /// Cannot sponsor any observers.
    None = 0,
    /// May sponsor 1 observer (basic verified user).
    Basic = 1,
    /// May sponsor up to 3 observers (enhanced verification).
    Enhanced = 2,
    /// May sponsor organizational / higher-count observers.
    Organizational = 3,
}

impl ObserverProofLevel {
    /// Default maximum observer quota for this proof level.
    ///
    /// Governance may override these values; this provides the
    /// protocol-default baseline.
    pub fn default_max_observers(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Basic => 1,
            Self::Enhanced => 3,
            Self::Organizational => 10,
        }
    }
}

// =============================================================================
// RATE-LIMIT TIER
// =============================================================================

/// Rate-limit tier assigned to an observer on admission.
///
/// Determines per-observer connection, sync, API, and bandwidth caps.
/// Exact limits are enforcement-layer concerns; this type identifies
/// which tier applies.
///
/// # Serialization contract
///
/// - **JSON** (`serde_json`): variant name string — `"Standard"`,
///   `"Elevated"`, `"Organizational"`.
/// - **Binary** (`bincode` v1.x): variant *ordinal index* as a
///   little-endian `u32` (4 bytes). `#[repr(u8)]` is Rust-layout only;
///   it does not affect serde output. Do not reorder variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)] // layout only — not the serialized discriminant; see doc comment above
pub enum ObserverRateLimitTier {
    /// Default tier for proof-level 1 sponsors.
    Standard = 0,
    /// Elevated tier for proof-level 2 sponsors.
    Elevated = 1,
    /// Organizational tier for proof-level 3 sponsors.
    Organizational = 2,
}

impl ObserverRateLimitTier {
    /// Per-observer ingress quota in requests per minute (observer-admission-8).
    ///
    /// These are protocol-level defaults consumed by the `lib-blockchain`
    /// token-bucket helper. They intentionally live on the canonical
    /// type so every enforcement point (API, sync, RPC) sees the same
    /// number, and they are deterministic / replay-safe.
    pub const fn quota_per_minute(self) -> u32 {
        match self {
            Self::Standard => 60,
            Self::Elevated => 300,
            Self::Organizational => 1_200,
        }
    }

    /// Refill rate (tokens per second) for a token bucket sized at
    /// [`Self::quota_per_minute`].
    pub fn refill_per_second(self) -> f64 {
        f64::from(self.quota_per_minute()) / 60.0
    }
}

// =============================================================================
// NODE INFO
// =============================================================================

/// Observer node identity and endpoint metadata.
///
/// Captures the machine-side identity that connects to the network.
/// The DID here is the *node* DID, not the sponsoring *user* DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverNodeInfo {
    /// Node DID (`did:zhtp:...`) — machine identity for QUIC auth.
    pub observer_node_did: String,
    /// Node public key (Dilithium5) as raw bytes.
    /// When serialized with derived Serde JSON, this is encoded as an array
    /// of byte values, not as a base64 string.
    pub observer_public_key: Vec<u8>,
    /// Optional advertised endpoints in `host:port` form.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

// =============================================================================
// SPONSOR BINDING
// =============================================================================

/// Binding between a sponsoring user DID and an observer node DID.
///
/// The sponsor is the accountable party: they authorized the observer,
/// and revoking the sponsor may cascade to all child observers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverSponsorBinding {
    /// User DID that authorized this observer.
    pub sponsoring_user_did: String,
    /// Sponsor signature over the enrollment statement.
    ///
    /// Statement binds: sponsor DID, observer node DID, requested role,
    /// network identifier, issuance time, and nonce.
    pub sponsor_signature: Vec<u8>,
    /// Sponsor proof level at enrollment time.
    pub proof_level: ObserverProofLevel,
}

// =============================================================================
// NETWORK / ENVIRONMENT BINDING
// =============================================================================

/// Network and environment scope for an admission record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverNetworkBinding {
    /// Network identifier this admission applies to (e.g. `"mainnet"`, `"testnet"`).
    pub allowed_network: String,
    /// Sync scope: which chain segments the observer may request.
    #[serde(default)]
    pub trusted_sync_scope: Option<String>,
}

// =============================================================================
// TRUSTED SYNC-SOURCE REFERENCE
// =============================================================================

/// Reference to a trusted sync source returned after admission.
///
/// Protocol-neutral counterpart to the config-layer `TrustedSyncSource`.
/// This is the canonical shape stored in admission records and returned
/// by enrollment APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedSyncSourceRef {
    /// Endpoint in `host:port` form.
    pub address: String,
    /// Expected peer DID after authenticated QUIC handshake.
    #[serde(default)]
    pub peer_did: Option<String>,
}

// =============================================================================
// CHALLENGE REFERENCE
// =============================================================================

/// Anti-replay challenge issued during the enrollment handshake.
///
/// The observer must sign this challenge to prove liveness and
/// ownership of `observer_node_did`. Challenges are single-use
/// and time-bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverAdmissionChallengeRef {
    /// Unique challenge identifier (UUID or hash).
    pub challenge_id: String,
    /// Random nonce the observer must sign.
    pub challenge_nonce: Vec<u8>,
    /// Unix timestamp (seconds) when this challenge expires.
    pub expires_at: u64,
}

// =============================================================================
// SUSPENSION / REVOCATION METADATA
// =============================================================================

/// Metadata attached when an observer is suspended or revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverAdmissionActionMeta {
    /// DID of the actor who initiated the action (sponsor, admin, system).
    pub actor_did: String,
    /// Human-readable reason.
    pub reason: String,
    /// Unix timestamp (seconds) when the action was taken.
    pub timestamp: u64,
    /// Cumulative count of policy violations recorded against this
    /// observer (observer-admission-8 anti-abuse). Persists across
    /// status transitions so escalation thresholds are sticky.
    /// Additive field: defaults to 0 for legacy records.
    #[serde(default)]
    pub abuse_counter: u32,
    /// Last violation timestamp (unix seconds), if any.
    /// Additive field: defaults to `None` for legacy records.
    #[serde(default)]
    pub last_violation_at: Option<u64>,
}

// =============================================================================
// ADMISSION RECORD
// =============================================================================

/// Canonical observer admission record.
///
/// This is the primary persisted state for an admitted observer.
/// It binds a node identity to a sponsor identity, captures the
/// admission status, and carries rate-limit and scope metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverAdmissionRecord {
    /// Observer node identity and public key.
    pub node_info: ObserverNodeInfo,
    /// Sponsor binding (user DID, signature, proof level).
    pub sponsor: ObserverSponsorBinding,
    /// Current lifecycle status.
    pub status: ObserverAdmissionStatus,
    /// Rate-limit tier assigned at admission.
    pub rate_limit_tier: ObserverRateLimitTier,
    /// Network and sync-scope binding.
    pub network: ObserverNetworkBinding,
    /// Unix timestamp (seconds) when the record was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last status change.
    pub updated_at: u64,
    /// Optional expiration (unix seconds). `None` = no expiry.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Metadata from the most recent suspension or revocation, if any.
    #[serde(default)]
    pub action_meta: Option<ObserverAdmissionActionMeta>,
}

impl ObserverAdmissionRecord {
    /// Whether this record currently permits sync access.
    ///
    /// `now_secs` is the current unix timestamp in seconds. Records with
    /// an `expires_at` in the past are denied even if status is `Active`.
    pub fn is_authorized_at(&self, now_secs: u64) -> bool {
        if !self.status.is_authorized() {
            return false;
        }
        if let Some(expires) = self.expires_at {
            if now_secs >= expires {
                return false;
            }
        }
        true
    }
}

// =============================================================================
// ADMISSION POLICY
// =============================================================================

/// Protocol-level observer admission policy.
///
/// Governance-configurable parameters that control who may sponsor
/// observers and under what constraints. Domain crates read these
/// values to enforce enrollment and rate-limit decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverAdmissionPolicy {
    /// Minimum sponsor proof level required to enroll an observer.
    pub minimum_proof_level: ObserverProofLevel,
    /// Whether admission is mandatory for sync access.
    pub admission_required: bool,
    /// Whether qualifying sponsors are auto-approved (`Active`)
    /// or must wait for admin review (`Pending`).
    pub auto_approve: bool,
    /// Per-proof-level observer quota overrides.
    /// If empty, `ObserverProofLevel::default_max_observers()` applies.
    #[serde(default)]
    pub quota_overrides: Vec<ProofLevelQuota>,
    /// Reserved for v2 economic anti-sybil: required bond (in base units)
    /// to enroll an observer. `None` in v1 (observer-admission-8).
    /// Additive field with explicit `None` default.
    #[serde(default)]
    pub bond_amount: Option<u64>,
    /// Cumulative violation count at which an `Active` observer is
    /// automatically suspended (observer-admission-8 anti-abuse).
    /// Default 3 when not specified by governance.
    #[serde(default = "default_abuse_suspend_threshold")]
    pub abuse_suspend_threshold: u32,
    /// Cumulative violation count at which an observer is automatically
    /// revoked (observer-admission-8 anti-abuse). Default 5.
    #[serde(default = "default_abuse_revoke_threshold")]
    pub abuse_revoke_threshold: u32,
}

fn default_abuse_suspend_threshold() -> u32 {
    3
}

fn default_abuse_revoke_threshold() -> u32 {
    5
}

/// Per-proof-level quota override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLevelQuota {
    pub proof_level: ObserverProofLevel,
    pub max_observers: u32,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a representative admission record for round-trip tests.
    fn sample_record() -> ObserverAdmissionRecord {
        ObserverAdmissionRecord {
            node_info: ObserverNodeInfo {
                observer_node_did: "did:zhtp:abc123".into(),
                observer_public_key: vec![1, 2, 3, 4],
                endpoints: vec!["203.0.113.10:9334".into()],
            },
            sponsor: ObserverSponsorBinding {
                sponsoring_user_did: "did:zhtp:sponsor456".into(),
                sponsor_signature: vec![10, 20, 30],
                proof_level: ObserverProofLevel::Enhanced,
            },
            status: ObserverAdmissionStatus::Active,
            rate_limit_tier: ObserverRateLimitTier::Elevated,
            network: ObserverNetworkBinding {
                allowed_network: "testnet".into(),
                trusted_sync_scope: Some("full".into()),
            },
            created_at: 1700000000,
            updated_at: 1700000000,
            expires_at: None,
            action_meta: None,
        }
    }

    // ----- JSON round-trip -----

    #[test]
    fn json_round_trip_admission_record() {
        let record = sample_record();
        let json = serde_json::to_string(&record).expect("serialize");
        let back: ObserverAdmissionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn json_round_trip_status_variants() {
        for status in [
            ObserverAdmissionStatus::Pending,
            ObserverAdmissionStatus::Active,
            ObserverAdmissionStatus::Suspended,
            ObserverAdmissionStatus::Revoked,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            let back: ObserverAdmissionStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, back);
        }
    }

    #[test]
    fn json_round_trip_proof_levels() {
        for level in [
            ObserverProofLevel::None,
            ObserverProofLevel::Basic,
            ObserverProofLevel::Enhanced,
            ObserverProofLevel::Organizational,
        ] {
            let json = serde_json::to_string(&level).expect("serialize");
            let back: ObserverProofLevel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(level, back);
        }
    }

    #[test]
    fn json_round_trip_rate_limit_tiers() {
        for tier in [
            ObserverRateLimitTier::Standard,
            ObserverRateLimitTier::Elevated,
            ObserverRateLimitTier::Organizational,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let back: ObserverRateLimitTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn json_round_trip_challenge_ref() {
        let challenge = ObserverAdmissionChallengeRef {
            challenge_id: "chall-001".into(),
            challenge_nonce: vec![0xAA, 0xBB, 0xCC],
            expires_at: 1700001000,
        };
        let json = serde_json::to_string(&challenge).expect("serialize");
        let back: ObserverAdmissionChallengeRef =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(challenge, back);
    }

    #[test]
    fn json_round_trip_policy() {
        let policy = ObserverAdmissionPolicy {
            minimum_proof_level: ObserverProofLevel::Basic,
            admission_required: true,
            auto_approve: false,
            quota_overrides: vec![ProofLevelQuota {
                proof_level: ObserverProofLevel::Organizational,
                max_observers: 25,
            }],
            bond_amount: None,
            abuse_suspend_threshold: 3,
            abuse_revoke_threshold: 5,
        };
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: ObserverAdmissionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back);
    }

    #[test]
    fn json_round_trip_trusted_sync_source_ref() {
        let src = TrustedSyncSourceRef {
            address: "77.42.37.161:9334".into(),
            peer_did: Some("did:zhtp:peer789".into()),
        };
        let json = serde_json::to_string(&src).expect("serialize");
        let back: TrustedSyncSourceRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(src, back);
    }

    // ----- bincode round-trip (deterministic binary serialization) -----

    #[test]
    fn bincode_round_trip_admission_record() {
        let record = sample_record();
        let bytes = bincode::serialize(&record).expect("serialize");
        let back: ObserverAdmissionRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn bincode_round_trip_status_variants() {
        for status in [
            ObserverAdmissionStatus::Pending,
            ObserverAdmissionStatus::Active,
            ObserverAdmissionStatus::Suspended,
            ObserverAdmissionStatus::Revoked,
        ] {
            let bytes = bincode::serialize(&status).expect("serialize");
            let back: ObserverAdmissionStatus =
                bincode::deserialize(&bytes).expect("deserialize");
            assert_eq!(status, back);
        }
    }

    // ----- authorization logic -----

    #[test]
    fn only_active_status_is_authorized() {
        assert!(ObserverAdmissionStatus::Active.is_authorized());
        assert!(!ObserverAdmissionStatus::Pending.is_authorized());
        assert!(!ObserverAdmissionStatus::Suspended.is_authorized());
        assert!(!ObserverAdmissionStatus::Revoked.is_authorized());
    }

    #[test]
    fn active_record_is_authorized() {
        let record = sample_record();
        assert!(record.is_authorized_at(1700000000));
    }

    #[test]
    fn suspended_record_is_not_authorized() {
        let mut record = sample_record();
        record.status = ObserverAdmissionStatus::Suspended;
        assert!(!record.is_authorized_at(1700000000));
    }

    #[test]
    fn expired_record_is_not_authorized() {
        let mut record = sample_record();
        record.expires_at = Some(1700000000);
        // At expiry time: denied
        assert!(!record.is_authorized_at(1700000000));
        // After expiry: denied
        assert!(!record.is_authorized_at(1700000001));
        // Before expiry: allowed
        assert!(record.is_authorized_at(1699999999));
    }

    // ----- proof-level quotas -----

    #[test]
    fn proof_level_default_quotas() {
        assert_eq!(ObserverProofLevel::None.default_max_observers(), 0);
        assert_eq!(ObserverProofLevel::Basic.default_max_observers(), 1);
        assert_eq!(ObserverProofLevel::Enhanced.default_max_observers(), 3);
        assert_eq!(ObserverProofLevel::Organizational.default_max_observers(), 10);
    }

    #[test]
    fn proof_level_ordering() {
        assert!(ObserverProofLevel::None < ObserverProofLevel::Basic);
        assert!(ObserverProofLevel::Basic < ObserverProofLevel::Enhanced);
        assert!(ObserverProofLevel::Enhanced < ObserverProofLevel::Organizational);
    }

    // ----- action metadata -----

    #[test]
    fn json_round_trip_record_with_action_meta() {
        let mut record = sample_record();
        record.status = ObserverAdmissionStatus::Revoked;
        record.action_meta = Some(ObserverAdmissionActionMeta {
            actor_did: "did:zhtp:admin001".into(),
            reason: "abuse detected".into(),
            timestamp: 1700002000,
            abuse_counter: 0,
            last_violation_at: None,
        });
        let json = serde_json::to_string(&record).expect("serialize");
        let back: ObserverAdmissionRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    // ----- JSON stability: known representations must not change -----

    #[test]
    fn status_json_repr_is_stable() {
        assert_eq!(
            serde_json::to_string(&ObserverAdmissionStatus::Pending).unwrap(),
            "\"Pending\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverAdmissionStatus::Active).unwrap(),
            "\"Active\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverAdmissionStatus::Suspended).unwrap(),
            "\"Suspended\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverAdmissionStatus::Revoked).unwrap(),
            "\"Revoked\""
        );
    }

    #[test]
    fn proof_level_json_repr_is_stable() {
        assert_eq!(
            serde_json::to_string(&ObserverProofLevel::None).unwrap(),
            "\"None\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverProofLevel::Basic).unwrap(),
            "\"Basic\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverProofLevel::Enhanced).unwrap(),
            "\"Enhanced\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverProofLevel::Organizational).unwrap(),
            "\"Organizational\""
        );
    }

    #[test]
    fn rate_limit_tier_json_repr_is_stable() {
        assert_eq!(
            serde_json::to_string(&ObserverRateLimitTier::Standard).unwrap(),
            "\"Standard\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverRateLimitTier::Elevated).unwrap(),
            "\"Elevated\""
        );
        assert_eq!(
            serde_json::to_string(&ObserverRateLimitTier::Organizational).unwrap(),
            "\"Organizational\""
        );
    }

    // ----- bincode golden-byte contract tests -----
    //
    // Bincode 1.x encodes unit-enum variants as their ordinal index
    // (little-endian u32, 4 bytes).  This is independent of the `repr(u8)`
    // numeric discriminant — `repr(u8)` is Rust memory-layout only.
    //
    // These tests document and pin the binary encoding so that:
    //   a) it is clear the contract is ordinal-index-based, not repr-value-based;
    //   b) any accidental variant reordering is caught immediately.
    //
    // Safe evolution: appending new variants at the end does not break these
    // golden bytes.  Inserting variants in the middle is a breaking change.

    #[test]
    fn bincode_golden_bytes_admission_status() {
        // index 0 = Pending, 1 = Active, 2 = Suspended, 3 = Revoked
        assert_eq!(
            bincode::serialize(&ObserverAdmissionStatus::Pending).unwrap().as_slice(),
            &[0, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverAdmissionStatus::Active).unwrap().as_slice(),
            &[1, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverAdmissionStatus::Suspended).unwrap().as_slice(),
            &[2, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverAdmissionStatus::Revoked).unwrap().as_slice(),
            &[3, 0, 0, 0]
        );
    }

    #[test]
    fn bincode_golden_bytes_proof_level() {
        // index 0 = None, 1 = Basic, 2 = Enhanced, 3 = Organizational
        assert_eq!(
            bincode::serialize(&ObserverProofLevel::None).unwrap().as_slice(),
            &[0, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverProofLevel::Basic).unwrap().as_slice(),
            &[1, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverProofLevel::Enhanced).unwrap().as_slice(),
            &[2, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverProofLevel::Organizational).unwrap().as_slice(),
            &[3, 0, 0, 0]
        );
    }

    #[test]
    fn bincode_golden_bytes_rate_limit_tier() {
        // index 0 = Standard, 1 = Elevated, 2 = Organizational
        assert_eq!(
            bincode::serialize(&ObserverRateLimitTier::Standard).unwrap().as_slice(),
            &[0, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverRateLimitTier::Elevated).unwrap().as_slice(),
            &[1, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&ObserverRateLimitTier::Organizational).unwrap().as_slice(),
            &[2, 0, 0, 0]
        );
    }
}
