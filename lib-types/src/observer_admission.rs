//! Canonical observer admission types for the Sovereign Network.
//!
//! Pure data types for identity-backed observer admission, sponsorship,
//! proof-level policy, trusted sync-source selection, and revocation.
//!
//! Rule: No behavior here. Domain crates own lifecycle logic, validation,
//! and state transitions. This module defines only the shapes.

use serde::{Deserialize, Serialize};

// =============================================================================
// STATUS
// =============================================================================

/// Lifecycle status of an observer admission record.
///
/// Only `Active` observers may sync or serve data. All other states
/// deny bootstrap, gap-fill, and long-range block import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ObserverRateLimitTier {
    /// Default tier for proof-level 1 sponsors.
    Standard = 0,
    /// Elevated tier for proof-level 2 sponsors.
    Elevated = 1,
    /// Organizational tier for proof-level 3 sponsors.
    Organizational = 2,
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
    /// Node public key (Dilithium5), base64-encoded.
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
    pub fn is_authorized(&self) -> bool {
        if !self.status.is_authorized() {
            return false;
        }
        // Expired records are not authorized even if status is Active.
        if let Some(expires) = self.expires_at {
            // Caller must supply current time; this is a structural check
            // against a sentinel. Domain crates do the real time comparison.
            if expires == 0 {
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
        assert!(record.is_authorized());
    }

    #[test]
    fn suspended_record_is_not_authorized() {
        let mut record = sample_record();
        record.status = ObserverAdmissionStatus::Suspended;
        assert!(!record.is_authorized());
    }

    #[test]
    fn expired_record_with_zero_sentinel_is_not_authorized() {
        let mut record = sample_record();
        record.expires_at = Some(0);
        assert!(!record.is_authorized());
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
}
