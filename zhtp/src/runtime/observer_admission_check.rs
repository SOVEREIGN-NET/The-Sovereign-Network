//! Observer admission gate for sync-source selection (observer-admission-5).
//!
//! Replaces the legacy "peer reachable ⇒ eligible" assumption in the
//! bootstrap/sync path with a canonical, blockchain-state-driven check:
//!
//!   discover → fetch peer DID → consult `observer_registry` →
//!   require `is_authorized_at(now)` for the local network.
//!
//! This module composes the pure policy in
//! [`lib_blockchain::observer::policy`] with a [`BlockchainStore`] lookup.
//! It does **not** mutate state, dial peers, or do I/O beyond a single
//! synchronous read of the observer record and policy.
//!
//! # Decision precedence
//!
//! The operator-configured `trusted_sync_sources` allowlist remains
//! authoritative for nodes that operators manually pin (e.g. a known
//! genesis bootstrap node before any observers are admitted). Beyond
//! that allowlist, a peer is only eligible as a sync source if it
//! presents a DID and that DID resolves to an `Active`, non-expired,
//! network-matching admission record.
//!
//! Empty allowlist no longer means "any peer is trusted": when the
//! allowlist is empty, the only eligible peers are admitted observers.

use lib_blockchain::observer::policy::{
    default_policy, evaluate_admission, AdmissionDecision, PolicyDenial,
};
use lib_blockchain::storage::{did_to_hash, BlockchainStore};

/// Outcome of [`is_eligible_sync_source`].
///
/// Carries the reason for diagnostics and tests; callers that just
/// need a boolean can use [`SyncSourceEligibility::is_eligible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncSourceEligibility {
    /// Peer is eligible to act as a sync source.
    Eligible(EligibilityReason),
    /// Peer is not eligible; carries a typed reason.
    Rejected(RejectionReason),
}

impl SyncSourceEligibility {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityReason {
    /// Peer is in the operator-configured `trusted_sync_sources` allowlist.
    OperatorTrusted,
    /// Peer presented a DID with an `Active` admission record matching
    /// the local network.
    AdmittedObserver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    /// Peer presented no DID and is not in the operator allowlist.
    AnonymousAndNotAllowlisted,
    /// Peer DID has no admission record in the registry.
    NotAdmitted,
    /// Admission record exists but the canonical policy denied it.
    AdmissionDenied(PolicyDenial),
    /// Reading the observer registry failed.
    StoreError(String),
}

/// Whether `(peer_address, peer_did)` matches the operator allowlist.
///
/// Mirrors the existing `is_trusted_sync_source` semantics for an empty
/// allowlist returning `false` is the **only** behavior change here:
/// admission-5 disallows the legacy "empty ⇒ universal trust" rule.
fn matches_operator_allowlist(
    peer_address: &str,
    peer_did: Option<&str>,
    trusted_sync_sources: &[crate::config::TrustedSyncSource],
) -> bool {
    trusted_sync_sources.iter().any(|trusted| {
        trusted.address == peer_address
            && trusted
                .peer_did
                .as_deref()
                .map(|expected_did| Some(expected_did) == peer_did)
                .unwrap_or(true)
    })
}

/// Look up the peer's admission record and evaluate the canonical policy.
///
/// `now` is unix seconds. `expected_network` is the local node's network id.
///
/// Returns:
///   - `Eligible(AdmittedObserver)` when the policy says `Authorized`.
///   - `Rejected(AnonymousAndNotAllowlisted)` when `peer_did` is missing/empty.
///   - `Rejected(NotAdmitted)` when no record exists.
///   - `Rejected(AdmissionDenied(_))` when the policy denied the record.
///   - `Rejected(StoreError(_))` on I/O failure.
pub fn evaluate_observer_admission_for_sync(
    store: &dyn BlockchainStore,
    peer_did: Option<&str>,
    expected_network: &str,
    now: u64,
) -> SyncSourceEligibility {
    let did = match peer_did {
        Some(d) if !d.is_empty() => d,
        _ => return SyncSourceEligibility::Rejected(RejectionReason::AnonymousAndNotAllowlisted),
    };

    let did_hash = did_to_hash(did);
    let record = match store.get_observer_record(&did_hash) {
        Ok(Some(r)) => r,
        Ok(None) => return SyncSourceEligibility::Rejected(RejectionReason::NotAdmitted),
        Err(e) => return SyncSourceEligibility::Rejected(RejectionReason::StoreError(e.to_string())),
    };

    let policy = match store.get_observer_policy() {
        Ok(Some(p)) => p,
        Ok(None) => default_policy(),
        Err(e) => return SyncSourceEligibility::Rejected(RejectionReason::StoreError(e.to_string())),
    };

    match evaluate_admission(&record, &policy, expected_network, now) {
        AdmissionDecision::Authorized => {
            SyncSourceEligibility::Eligible(EligibilityReason::AdmittedObserver)
        }
        AdmissionDecision::Denied(denial) => {
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(denial))
        }
    }
}

/// Composite eligibility gate used by the bootstrap/sync code path.
///
/// Order:
///   1. Operator allowlist — if `(peer_address, peer_did)` matches, eligible.
///   2. Otherwise consult the observer registry via
///      [`evaluate_observer_admission_for_sync`].
///
/// An empty `trusted_sync_sources` allowlist is **not** a permit — under
/// admission-5, eligibility falls through to the observer registry and a
/// peer with no admission record is rejected.
pub fn is_eligible_sync_source(
    peer_address: &str,
    peer_did: Option<&str>,
    trusted_sync_sources: &[crate::config::TrustedSyncSource],
    store: &dyn BlockchainStore,
    expected_network: &str,
    now: u64,
) -> SyncSourceEligibility {
    if matches_operator_allowlist(peer_address, peer_did, trusted_sync_sources) {
        return SyncSourceEligibility::Eligible(EligibilityReason::OperatorTrusted);
    }

    // On a fresh genesis (no blocks beyond genesis), no observer records exist.
    // Skip admission check — all authenticated peers are eligible.
    // Once blocks start being produced, the admission system takes over.
    if let Ok(None) = store.get_block_by_height(1) {
        if peer_did.is_some_and(|did| !did.trim().is_empty()) {
            tracing::debug!(
                "No block at height 1 (fresh genesis) — skipping observer admission for authenticated peer {}",
                peer_address
            );
            return SyncSourceEligibility::Eligible(EligibilityReason::OperatorTrusted);
        }
    }

    evaluate_observer_admission_for_sync(store, peer_did, expected_network, now)
}

/// Trusted sync-source selector (observer-admission-7).
///
/// Filters a candidate set of `(peer_address, peer_did)` tuples down to
/// only those eligible to act as sync sources, consulting both the
/// operator-configured allowlist and the on-chain observer admission
/// registry via [`is_eligible_sync_source`].
///
/// This is the canonical function the discovery / bootstrap layers
/// should use when populating their sync-source pool. It centralizes
/// the admission gate so the network layer never has to reason about
/// admission policy directly (lib-network has no `lib-blockchain`
/// dependency, so this orchestration lives in the runtime crate).
///
/// Returns the input tuples (in input order) that the gate accepted.
pub fn select_trusted_sync_sources<I>(
    peers: I,
    trusted_sync_sources: &[crate::config::TrustedSyncSource],
    store: &dyn BlockchainStore,
    expected_network: &str,
    now: u64,
) -> Vec<(String, Option<String>)>
where
    I: IntoIterator<Item = (String, Option<String>)>,
{
    peers
        .into_iter()
        .filter(|(addr, did)| {
            is_eligible_sync_source(
                addr,
                did.as_deref(),
                trusted_sync_sources,
                store,
                expected_network,
                now,
            )
            .is_eligible()
        })
        .collect()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::storage::{BlockchainStore, StorageResult};
    use lib_types::{
        ObserverAdmissionPolicy, ObserverAdmissionRecord, ObserverAdmissionStatus,
        ObserverNetworkBinding, ObserverNodeInfo, ObserverProofLevel, ObserverRateLimitTier,
        ObserverSponsorBinding,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory test double for `BlockchainStore`. Only the observer
    /// admission methods are implemented; the rest fall through to the
    /// trait's default no-op impls.
    #[derive(Default)]
    struct MockObserverStore {
        records: Mutex<HashMap<[u8; 32], ObserverAdmissionRecord>>,
        policy: Mutex<Option<ObserverAdmissionPolicy>>,
    }

    impl MockObserverStore {
        fn insert(&self, record: ObserverAdmissionRecord) {
            let h = did_to_hash(&record.node_info.observer_node_did);
            self.records.lock().unwrap().insert(h, record);
        }

        fn set_policy(&self, p: ObserverAdmissionPolicy) {
            *self.policy.lock().unwrap() = Some(p);
        }
    }

    impl BlockchainStore for MockObserverStore {
        fn get_observer_record(
            &self,
            did_hash: &[u8; 32],
        ) -> StorageResult<Option<ObserverAdmissionRecord>> {
            Ok(self.records.lock().unwrap().get(did_hash).cloned())
        }

        fn get_observer_policy(&self) -> StorageResult<Option<ObserverAdmissionPolicy>> {
            Ok(self.policy.lock().unwrap().clone())
        }
    }

    fn record(
        node_did: &str,
        sponsor_did: &str,
        status: ObserverAdmissionStatus,
        network: &str,
    ) -> ObserverAdmissionRecord {
        ObserverAdmissionRecord {
            node_info: ObserverNodeInfo {
                observer_node_did: node_did.to_string(),
                observer_public_key: vec![1, 2, 3],
                endpoints: vec![],
            },
            sponsor: ObserverSponsorBinding {
                sponsoring_user_did: sponsor_did.to_string(),
                sponsor_signature: vec![9, 9, 9],
                proof_level: ObserverProofLevel::Basic,
            },
            status,
            rate_limit_tier: ObserverRateLimitTier::Standard,
            network: ObserverNetworkBinding {
                allowed_network: network.to_string(),
                trusted_sync_scope: None,
            },
            created_at: 1,
            updated_at: 1,
            expires_at: None,
            action_meta: None,
        }
    }

    #[test]
    fn anonymous_peer_rejected_when_not_in_allowlist() {
        let store = MockObserverStore::default();
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            None,
            &[],
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::AnonymousAndNotAllowlisted)
        );
    }

    #[test]
    fn unknown_peer_did_rejected_as_not_admitted() {
        let store = MockObserverStore::default();
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:stranger"),
            &[],
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::NotAdmitted)
        );
    }

    #[test]
    fn admitted_active_peer_eligible() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "testnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Eligible(EligibilityReason::AdmittedObserver)
        );
    }

    #[test]
    fn pending_peer_rejected_with_admission_denied() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Pending,
            "testnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        match result {
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::NotAuthorizedStatus(ObserverAdmissionStatus::Pending),
            )) => {}
            other => panic!("expected pending denial, got {other:?}"),
        }
    }

    #[test]
    fn revoked_peer_rejected() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Revoked,
            "testnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        assert!(matches!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::NotAuthorizedStatus(ObserverAdmissionStatus::Revoked)
            ))
        ));
    }

    #[test]
    fn suspended_peer_rejected() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Suspended,
            "testnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        assert!(matches!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::NotAuthorizedStatus(ObserverAdmissionStatus::Suspended)
            ))
        ));
    }

    #[test]
    fn network_mismatch_peer_rejected() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "mainnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        match result {
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::NetworkMismatch { .. },
            )) => {}
            other => panic!("expected network mismatch, got {other:?}"),
        }
    }

    #[test]
    fn expired_peer_rejected() {
        let store = MockObserverStore::default();
        let mut rec = record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "testnet",
        );
        rec.expires_at = Some(50);
        store.insert(rec);
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        match result {
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::Expired { expires_at: 50, now: 100 },
            )) => {}
            other => panic!("expected expired denial, got {other:?}"),
        }
    }

    #[test]
    fn operator_allowlist_overrides_admission_lookup() {
        // Even though the store has no record for this DID, the operator
        // allowlist match short-circuits to Eligible(OperatorTrusted).
        let store = MockObserverStore::default();
        let trusted = vec![crate::config::TrustedSyncSource {
            address: "10.0.0.1:9334".to_string(),
            peer_did: Some("did:zhtp:pinned".to_string()),
        }];
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:pinned"),
            &trusted,
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Eligible(EligibilityReason::OperatorTrusted)
        );
    }

    #[test]
    fn empty_allowlist_no_longer_grants_universal_trust() {
        // Pre-admission-5: empty allowlist meant any peer was trusted.
        // Post-admission-5: empty allowlist means we must consult the registry.
        let store = MockObserverStore::default();
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:random"),
            &[],
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::NotAdmitted)
        );
    }

    #[test]
    fn allowlist_match_requires_peer_did_when_pinned() {
        let store = MockObserverStore::default();
        let trusted = vec![crate::config::TrustedSyncSource {
            address: "10.0.0.1:9334".to_string(),
            peer_did: Some("did:zhtp:pinned".to_string()),
        }];
        // Address matches but peer presented a different DID — falls
        // through to admission lookup, which will reject (no record).
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:other"),
            &trusted,
            &store,
            "testnet",
            100,
        );
        assert_eq!(
            result,
            SyncSourceEligibility::Rejected(RejectionReason::NotAdmitted)
        );
    }

    #[test]
    fn custom_policy_with_higher_minimum_proof_level_denies_basic_sponsor() {
        let store = MockObserverStore::default();
        store.set_policy(ObserverAdmissionPolicy {
            minimum_proof_level: ObserverProofLevel::Enhanced,
            admission_required: true,
            auto_approve: false,
            quota_overrides: vec![],
            bond_amount: None,
            abuse_suspend_threshold: 3,
            abuse_revoke_threshold: 5,
        });
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "testnet",
        ));
        let result = is_eligible_sync_source(
            "10.0.0.1:9334",
            Some("did:zhtp:obs"),
            &[],
            &store,
            "testnet",
            100,
        );
        match result {
            SyncSourceEligibility::Rejected(RejectionReason::AdmissionDenied(
                PolicyDenial::SponsorProofLevelTooLow { .. },
            )) => {}
            other => panic!("expected proof-level-too-low denial, got {other:?}"),
        }
    }

    // ---- select_trusted_sync_sources (observer-admission-7) ----

    #[test]
    fn selector_returns_empty_for_no_candidates() {
        let store = MockObserverStore::default();
        let out = select_trusted_sync_sources(
            std::iter::empty::<(String, Option<String>)>(),
            &[],
            &store,
            "testnet",
            100,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn selector_keeps_only_admitted_peers_in_input_order() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:good",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "testnet",
        ));
        let candidates = vec![
            ("10.0.0.1:9334".to_string(), Some("did:zhtp:stranger".to_string())),
            ("10.0.0.2:9334".to_string(), Some("did:zhtp:good".to_string())),
            ("10.0.0.3:9334".to_string(), None),
        ];
        let out = select_trusted_sync_sources(candidates, &[], &store, "testnet", 100);
        assert_eq!(
            out,
            vec![("10.0.0.2:9334".to_string(), Some("did:zhtp:good".to_string()))]
        );
    }

    #[test]
    fn selector_rejects_all_when_none_admitted_or_allowlisted() {
        let store = MockObserverStore::default();
        let candidates = vec![
            ("10.0.0.1:9334".to_string(), Some("did:zhtp:a".to_string())),
            ("10.0.0.2:9334".to_string(), Some("did:zhtp:b".to_string())),
        ];
        let out = select_trusted_sync_sources(candidates, &[], &store, "testnet", 100);
        assert!(out.is_empty());
    }

    #[test]
    fn selector_preserves_unknown_state_by_not_inventing_eligibility() {
        // No records, no allowlist — selector must not fabricate eligibility.
        // Even if the discovery layer's RemoteChainState is Unknown, this
        // selector returns no candidates rather than guessing.
        let store = MockObserverStore::default();
        let candidates = vec![("10.0.0.1:9334".to_string(), None)];
        let out = select_trusted_sync_sources(candidates, &[], &store, "testnet", 100);
        assert!(out.is_empty());
    }

    #[test]
    fn selector_honors_operator_allowlist_for_unadmitted_peer() {
        let store = MockObserverStore::default();
        let trusted = vec![crate::config::TrustedSyncSource {
            address: "10.0.0.1:9334".to_string(),
            peer_did: None,
        }];
        let candidates = vec![
            ("10.0.0.1:9334".to_string(), None),
            ("10.0.0.2:9334".to_string(), Some("did:zhtp:rando".to_string())),
        ];
        let out = select_trusted_sync_sources(candidates, &trusted, &store, "testnet", 100);
        assert_eq!(out, vec![("10.0.0.1:9334".to_string(), None)]);
    }

    #[test]
    fn selector_excludes_network_mismatched_admitted_peer() {
        let store = MockObserverStore::default();
        store.insert(record(
            "did:zhtp:obs",
            "did:zhtp:sponsor",
            ObserverAdmissionStatus::Active,
            "mainnet",
        ));
        let candidates = vec![("10.0.0.1:9334".to_string(), Some("did:zhtp:obs".to_string()))];
        let out = select_trusted_sync_sources(candidates, &[], &store, "testnet", 100);
        assert!(out.is_empty());
    }
}
