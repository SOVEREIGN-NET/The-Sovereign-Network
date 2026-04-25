//! Canonical observer admission policy (observer-admission-4).
//!
//! Pure, deterministic functions that evaluate whether an observer is
//! authorized given:
//!   - the persisted [`ObserverAdmissionRecord`]
//!   - the current [`ObserverAdmissionPolicy`]
//!   - the network identifier the local node operates on
//!   - a wall-clock-equivalent `now` value (block height/timestamp) for
//!     expiry checks
//!
//! No I/O, no clocks, no logging — replay-safe by construction.
//!
//! # Decision model
//!
//! [`evaluate_admission`] returns:
//!   - [`AdmissionDecision::Authorized`] iff the record is `Active`, not
//!     expired, network matches, and sponsor proof level meets the policy
//!     minimum.
//!   - [`AdmissionDecision::Denied`] otherwise, with a typed reason.
//!
//! Quota enforcement is a separate function ([`check_sponsor_quota`])
//! because it requires enumerating other records and is invoked at
//! registration time, not on every authorization check.
//!
//! # Anonymous-sponsor rule
//!
//! Per ticket: anonymous users cannot sponsor observers. We model "anonymous"
//! as either an empty sponsor DID or `ObserverProofLevel::None`. Both are
//! rejected by [`check_proof_level`].

use lib_types::{
    ObserverAdmissionPolicy, ObserverAdmissionRecord, ObserverAdmissionStatus, ObserverProofLevel,
    ProofLevelQuota,
};

// =============================================================================
// DECISION TYPES
// =============================================================================

/// Outcome of [`evaluate_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// The observer is authorized to bootstrap, sync, and serve.
    Authorized,
    /// The observer is not authorized; carries a typed reason.
    Denied(PolicyDenial),
}

impl AdmissionDecision {
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Authorized)
    }
}

/// Typed denial reasons produced by policy evaluation.
///
/// Callers may map these to executor-boundary validation errors or stable
/// reason codes, but that mapping is defined outside this module. As of v1
/// the executor formats `PolicyDenial` into a generic `TxApplyError::InvalidType`
/// string; future work may introduce stable per-variant error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDenial {
    /// Record exists but its lifecycle status forbids access.
    NotAuthorizedStatus(ObserverAdmissionStatus),
    /// Record has an expiry and `now >= expires_at`.
    Expired { expires_at: u64, now: u64 },
    /// Sponsor proof level is below the policy minimum.
    SponsorProofLevelTooLow {
        sponsor_level: ObserverProofLevel,
        required: ObserverProofLevel,
    },
    /// Sponsor exhausted their per-proof-level quota.
    SponsorQuotaExhausted {
        proof_level: ObserverProofLevel,
        max: u32,
        current: u32,
    },
    /// Observer is admitted for a different network than the local node.
    NetworkMismatch {
        record_network: String,
        expected_network: String,
    },
    /// Sponsor DID is empty / sponsor is effectively anonymous.
    AnonymousSponsorRejected,
}

// =============================================================================
// PURE POLICY FUNCTIONS
// =============================================================================

/// Whether `sponsor_level` meets the policy's minimum proof level.
///
/// Anonymous sponsors (`ObserverProofLevel::None`) are always rejected here
/// regardless of the policy minimum; downstream callers must additionally
/// reject empty sponsor DID strings.
pub fn check_proof_level(
    sponsor_level: ObserverProofLevel,
    policy: &ObserverAdmissionPolicy,
) -> Result<(), PolicyDenial> {
    if sponsor_level == ObserverProofLevel::None {
        return Err(PolicyDenial::AnonymousSponsorRejected);
    }
    if sponsor_level < policy.minimum_proof_level {
        return Err(PolicyDenial::SponsorProofLevelTooLow {
            sponsor_level,
            required: policy.minimum_proof_level,
        });
    }
    Ok(())
}

/// Whether the sponsor still has quota for one more observer.
///
/// `current` is the count of records this sponsor already owns. The cap is
/// the policy override for the sponsor's proof level if present, else the
/// proof level's protocol default.
pub fn check_sponsor_quota(
    sponsor_level: ObserverProofLevel,
    current: u32,
    policy: &ObserverAdmissionPolicy,
) -> Result<(), PolicyDenial> {
    let max = quota_for(sponsor_level, policy);
    if current >= max {
        return Err(PolicyDenial::SponsorQuotaExhausted {
            proof_level: sponsor_level,
            max,
            current,
        });
    }
    Ok(())
}

/// Resolve the effective per-sponsor quota for `level` under `policy`.
pub fn quota_for(level: ObserverProofLevel, policy: &ObserverAdmissionPolicy) -> u32 {
    policy
        .quota_overrides
        .iter()
        .find(|q: &&ProofLevelQuota| q.proof_level == level)
        .map(|q| q.max_observers)
        .unwrap_or_else(|| level.default_max_observers())
}

/// Whether the record's allowed_network matches the local node's network.
pub fn check_network_match(
    record_network: &str,
    expected_network: &str,
) -> Result<(), PolicyDenial> {
    if record_network != expected_network {
        return Err(PolicyDenial::NetworkMismatch {
            record_network: record_network.to_string(),
            expected_network: expected_network.to_string(),
        });
    }
    Ok(())
}

/// Final canonical authorization decision for a single observer record.
///
/// Order of checks (deterministic):
/// 1. status must be `Active`.
/// 2. record must not be expired at `now`.
/// 3. network binding must match `expected_network`.
/// 4. sponsor proof level must satisfy `policy.minimum_proof_level`.
///
/// Quota is intentionally not checked here — quota is a registration-time
/// constraint, not an ongoing access check (revocations free quota,
/// admissions consume it).
pub fn evaluate_admission(
    record: &ObserverAdmissionRecord,
    policy: &ObserverAdmissionPolicy,
    expected_network: &str,
    now: u64,
) -> AdmissionDecision {
    if !record.status.is_authorized() {
        return AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(record.status));
    }
    if let Some(expires) = record.expires_at {
        if now >= expires {
            return AdmissionDecision::Denied(PolicyDenial::Expired {
                expires_at: expires,
                now,
            });
        }
    }
    if let Err(d) = check_network_match(&record.network.allowed_network, expected_network) {
        return AdmissionDecision::Denied(d);
    }
    if let Err(d) = check_proof_level(record.sponsor.proof_level, policy) {
        return AdmissionDecision::Denied(d);
    }
    AdmissionDecision::Authorized
}

/// Default protocol policy seeded at genesis.
///
/// - `minimum_proof_level: Basic` — anonymous nodes cannot sponsor.
/// - `admission_required: true` — observers need a canonical record to sync.
/// - `auto_approve: false` — sponsors land in `Pending` and need explicit
///   activation. (Operators can override via on-chain governance later.)
pub fn default_policy() -> ObserverAdmissionPolicy {
    ObserverAdmissionPolicy {
        minimum_proof_level: ObserverProofLevel::Basic,
        admission_required: true,
        auto_approve: false,
        quota_overrides: Vec::new(),
        // observer-admission-8: reserved economic anti-sybil hook (unused in v1).
        bond_amount: None,
        // observer-admission-8: anti-abuse escalation thresholds.
        abuse_suspend_threshold: 3,
        abuse_revoke_threshold: 5,
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_types::{
        ObserverAdmissionActionMeta, ObserverAdmissionRecord, ObserverNetworkBinding,
        ObserverNodeInfo, ObserverRateLimitTier, ObserverSponsorBinding,
    };

    fn make_record(
        status: ObserverAdmissionStatus,
        sponsor_level: ObserverProofLevel,
        network: &str,
        expires_at: Option<u64>,
    ) -> ObserverAdmissionRecord {
        ObserverAdmissionRecord {
            node_info: ObserverNodeInfo {
                observer_node_did: "did:zhtp:n".to_string(),
                observer_public_key: vec![1, 2, 3],
                endpoints: vec![],
            },
            sponsor: ObserverSponsorBinding {
                sponsoring_user_did: "did:zhtp:s".to_string(),
                sponsor_signature: vec![],
                proof_level: sponsor_level,
            },
            status,
            rate_limit_tier: ObserverRateLimitTier::Standard,
            network: ObserverNetworkBinding {
                allowed_network: network.to_string(),
                trusted_sync_scope: None,
            },
            created_at: 0,
            updated_at: 0,
            expires_at,
            action_meta: None::<ObserverAdmissionActionMeta>,
        }
    }

    #[test]
    fn active_record_with_meeting_proof_level_is_authorized() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Active,
            ObserverProofLevel::Basic,
            "testnet",
            None,
        );
        assert_eq!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Authorized
        );
    }

    #[test]
    fn pending_status_denied() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Pending,
            ObserverProofLevel::Basic,
            "testnet",
            None,
        );
        match evaluate_admission(&r, &p, "testnet", 100) {
            AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
                ObserverAdmissionStatus::Pending,
            )) => {}
            other => panic!("expected pending denial, got {other:?}"),
        }
    }

    #[test]
    fn suspended_status_denied() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Suspended,
            ObserverProofLevel::Basic,
            "testnet",
            None,
        );
        assert!(matches!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
                ObserverAdmissionStatus::Suspended
            ))
        ));
    }

    #[test]
    fn revoked_status_denied() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Revoked,
            ObserverProofLevel::Basic,
            "testnet",
            None,
        );
        assert!(matches!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
                ObserverAdmissionStatus::Revoked
            ))
        ));
    }

    #[test]
    fn expired_record_denied() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Active,
            ObserverProofLevel::Basic,
            "testnet",
            Some(100),
        );
        assert!(matches!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Denied(PolicyDenial::Expired { .. })
        ));
        // Same record one tick before expiry → authorized.
        assert_eq!(
            evaluate_admission(&r, &p, "testnet", 99),
            AdmissionDecision::Authorized
        );
    }

    #[test]
    fn network_mismatch_denied() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Active,
            ObserverProofLevel::Basic,
            "mainnet",
            None,
        );
        assert!(matches!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Denied(PolicyDenial::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn proof_level_below_minimum_denied() {
        let mut p = default_policy();
        p.minimum_proof_level = ObserverProofLevel::Enhanced;
        let r = make_record(
            ObserverAdmissionStatus::Active,
            ObserverProofLevel::Basic,
            "testnet",
            None,
        );
        assert!(matches!(
            evaluate_admission(&r, &p, "testnet", 100),
            AdmissionDecision::Denied(PolicyDenial::SponsorProofLevelTooLow { .. })
        ));
    }

    #[test]
    fn anonymous_sponsor_always_rejected() {
        let p = default_policy();
        // Even if minimum_proof_level were None, ProofLevel::None must be rejected.
        let mut p2 = p.clone();
        p2.minimum_proof_level = ObserverProofLevel::None;
        assert!(matches!(
            check_proof_level(ObserverProofLevel::None, &p2),
            Err(PolicyDenial::AnonymousSponsorRejected)
        ));
    }

    #[test]
    fn quota_default_uses_proof_level_default() {
        let p = default_policy();
        // Basic = 1 by protocol default. current=0 ok, current=1 exhausted.
        assert!(check_sponsor_quota(ObserverProofLevel::Basic, 0, &p).is_ok());
        assert!(matches!(
            check_sponsor_quota(ObserverProofLevel::Basic, 1, &p),
            Err(PolicyDenial::SponsorQuotaExhausted { max: 1, current: 1, .. })
        ));
    }

    #[test]
    fn quota_override_takes_precedence() {
        let mut p = default_policy();
        p.quota_overrides.push(ProofLevelQuota {
            proof_level: ObserverProofLevel::Basic,
            max_observers: 5,
        });
        assert!(check_sponsor_quota(ObserverProofLevel::Basic, 4, &p).is_ok());
        assert!(check_sponsor_quota(ObserverProofLevel::Basic, 5, &p).is_err());
        assert_eq!(quota_for(ObserverProofLevel::Basic, &p), 5);
    }

    #[test]
    fn evaluate_admission_is_pure_and_deterministic() {
        let p = default_policy();
        let r = make_record(
            ObserverAdmissionStatus::Active,
            ObserverProofLevel::Basic,
            "testnet",
            Some(50),
        );
        // Same inputs → same output, no matter how many calls.
        for _ in 0..16 {
            assert_eq!(
                evaluate_admission(&r, &p, "testnet", 49),
                AdmissionDecision::Authorized
            );
            assert!(matches!(
                evaluate_admission(&r, &p, "testnet", 50),
                AdmissionDecision::Denied(PolicyDenial::Expired { .. })
            ));
        }
    }
}
