//! Observer admission integration tests (observer-admission-9).
//!
//! End-to-end coverage exercising the executor + storage + policy stack
//! through the public lib-blockchain API. These tests are the canonical
//! release gate for the observer-admission epic and are wired into
//! `scripts/validate-observer-admission.sh` and the DAO-ready gate.
//!
//! What we cover here:
//!
//!   * replay determinism — applying the same sequence of admission
//!     transactions twice yields identical observer registry state.
//!   * duplicate registration is rejected (executor returns an error).
//!   * invalid sponsor binding is rejected at apply time.
//!   * the canonical authorization gate (`evaluate_admission`) denies
//!     unadmitted / suspended / revoked / network-mismatched / expired
//!     records — i.e. unauthorized bootstrap is impossible.
//!   * trusted sync-source enforcement: admitted+matching → Authorized.
//!   * status transitions A→S, S→A (reauthorize), A→R, S→R, P→R.
//!   * suspension/revocation effects on bootstrap (deny).
//!   * sponsor quota enforcement (Basic = 1) and sponsor proof-level
//!     gating (anonymous sponsor rejected).
//!
//! All transactions are constructed via `lib_blockchain::transaction::*`
//! public constructors; blocks via `lib_blockchain::create_genesis_block`
//! and a local `make_block_with_txs` helper.

use std::sync::Arc;

use lib_blockchain::execution::BlockExecutor;
use lib_blockchain::observer::{
    default_policy, evaluate_admission, AdmissionDecision, PolicyDenial,
};
use lib_blockchain::storage::{did_to_hash, BlockchainStore, SledStore};
use lib_blockchain::transaction::{
    RegisterObserverData, ReauthorizeObserverData, RevokeObserverData, SuspendObserverData,
    Transaction,
};
use lib_blockchain::{create_genesis_block, Block, BlockHeader};
use lib_blockchain::types::Hash;
use lib_crypto::{PublicKey, Signature, SignatureAlgorithm};
use lib_types::{
    ObserverAdmissionRecord, ObserverAdmissionStatus, ObserverProofLevel, ObserverRateLimitTier,
};

const NET: &str = "testnet";
const NOW: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Test harness helpers (self-contained — no internal-only test utilities).
// ---------------------------------------------------------------------------

fn dummy_signature() -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: PublicKey::new([0u8; 2592]),
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp: 0,
    }
}

fn store() -> Arc<dyn BlockchainStore> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.keep();
    Arc::new(SledStore::open(&path).expect("open sled store at tempdir"))
}

/// Build a store and seed an `auto_approve = true` policy so subsequent
/// `RegisterObserver` transactions land observers directly in `Active`.
/// Used by lifecycle tests that need to exercise A→S, S→A, A→R, S→R
/// transitions through real blocks (no out-of-band record mutation).
fn store_auto_approve() -> Arc<dyn BlockchainStore> {
    let s = store();
    let mut policy = lib_blockchain::observer::default_policy();
    policy.auto_approve = true;
    s.save_observer_policy(&policy)
        .expect("seed auto_approve policy");
    s
}

fn make_block_with_txs(height: u64, prev: Hash, txs: Vec<Transaction>) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    hash_bytes[8] = txs.len() as u8;
    let block_hash = Hash::new(hash_bytes);
    let header = BlockHeader {
        version: 1,
        previous_hash: prev.into(),
        data_helix_root: Hash::default().into(),
        timestamp: 1000 + height,
        height,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash,
    };
    Block::new(header, txs)
}

fn apply_genesis(executor: &BlockExecutor) -> Hash {
    let g = create_genesis_block();
    executor.apply_block(&g).expect("apply genesis");
    g.header.block_hash
}

fn register_tx(observer: &str, sponsor: &str, level: ObserverProofLevel, nonce: u64) -> Transaction {
    let data = RegisterObserverData {
        observer_node_did: observer.to_string(),
        observer_public_key: vec![1u8; 32],
        endpoints: vec!["127.0.0.1:9000".to_string()],
        sponsor_user_did: sponsor.to_string(),
        sponsor_proof_level: level,
        sponsor_signature: vec![1u8; 32],
        allowed_network: NET.to_string(),
        trusted_sync_scope: None,
        rate_limit_tier: ObserverRateLimitTier::Standard,
        expires_at: None,
        nonce,
    };
    Transaction::new_register_observer(0x03, data, dummy_signature())
}

fn suspend_tx(observer: &str, actor: &str, nonce: u64) -> Transaction {
    let data = SuspendObserverData {
        observer_node_did: observer.to_string(),
        actor_did: actor.to_string(),
        reason: "test suspension".to_string(),
        nonce,
    };
    Transaction::new_suspend_observer(0x03, data, dummy_signature())
}

fn revoke_tx(observer: &str, actor: &str, nonce: u64) -> Transaction {
    let data = RevokeObserverData {
        observer_node_did: observer.to_string(),
        actor_did: actor.to_string(),
        reason: "test revocation".to_string(),
        nonce,
    };
    Transaction::new_revoke_observer(0x03, data, dummy_signature())
}

fn reauth_tx(observer: &str, sponsor: &str, nonce: u64) -> Transaction {
    let data = ReauthorizeObserverData {
        observer_node_did: observer.to_string(),
        sponsor_user_did: sponsor.to_string(),
        nonce,
    };
    Transaction::new_reauthorize_observer(0x03, data, dummy_signature())
}

fn record_for(store: &Arc<dyn BlockchainStore>, did: &str) -> Option<ObserverAdmissionRecord> {
    let h = did_to_hash(&did.to_string());
    store.get_observer_record(&h).expect("store read")
}

fn fingerprint_registry(store: &Arc<dyn BlockchainStore>) -> Vec<(String, ObserverAdmissionStatus, u64)> {
    let mut all: Vec<(String, ObserverAdmissionStatus, u64)> = store
        .iter_observer_records()
        .expect("iter")
        .into_iter()
        .map(|r| {
            (
                r.node_info.observer_node_did.clone(),
                r.status,
                r.updated_at,
            )
        })
        .collect();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    all
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Replaying the same admission tx sequence on two independent stores
/// must yield bit-for-bit identical observer registry state.
#[test]
fn replay_determinism_for_admission_tx_sequence() {
    let run = || {
        let s = store();
        let exec = BlockExecutor::with_store(s.clone());
        let g = apply_genesis(&exec);
        let b1 = make_block_with_txs(
            1,
            g,
            vec![register_tx("did:zhtp:obsA", "did:zhtp:spA", ObserverProofLevel::Basic, 1)],
        );
        exec.apply_block(&b1).expect("b1");
        let b2 = make_block_with_txs(
            2,
            b1.header.block_hash,
            vec![register_tx("did:zhtp:obsB", "did:zhtp:spB", ObserverProofLevel::Enhanced, 2)],
        );
        exec.apply_block(&b2).expect("b2");
        fingerprint_registry(&s)
    };
    let first = run();
    let second = run();
    assert_eq!(first, second, "admission registry must be replay-deterministic");
}

/// Re-applying RegisterObserver for the same DID in a later block must
/// be rejected by the executor.
#[test]
fn duplicate_registration_rejected() {
    let s = store();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:dupA", "did:zhtp:spX", ObserverProofLevel::Basic, 1)],
    );
    exec.apply_block(&b1).expect("first registration must succeed");

    let b2 = make_block_with_txs(
        2,
        b1.header.block_hash,
        vec![register_tx("did:zhtp:dupA", "did:zhtp:spX", ObserverProofLevel::Basic, 2)],
    );
    let err = exec
        .apply_block(&b2)
        .expect_err("duplicate registration must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("already") || msg.contains("exists") || msg.to_lowercase().contains("duplicate"),
        "unexpected duplicate-rejection error: {msg}"
    );
}

/// Invalid sponsor binding (empty sponsor DID) must be rejected at apply time.
#[test]
fn invalid_sponsor_binding_rejected() {
    let s = store();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:noSp", "", ObserverProofLevel::Basic, 1)],
    );
    let err = exec
        .apply_block(&b1)
        .expect_err("empty sponsor DID must be rejected");
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("sponsor"),
        "unexpected sponsor-rejection error: {msg}"
    );
}

/// An anonymous sponsor (proof_level = None) must be denied registration
/// per the canonical policy proof-level check.
#[test]
fn anonymous_sponsor_rejected_by_policy() {
    let s = store();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:anonObs", "did:zhtp:anonSp", ObserverProofLevel::None, 1)],
    );
    let err = exec
        .apply_block(&b1)
        .expect_err("anonymous sponsor must be rejected");
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("anonymous") || msg.contains("proof") || msg.contains("level"),
        "unexpected anonymous-sponsor error: {msg}"
    );
}

/// Basic-tier sponsors are limited to one observer (default quota).
/// Registering a second observer under the same Basic sponsor must be denied.
#[test]
fn sponsor_quota_enforced_for_basic_tier() {
    let s = store();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:quotaA", "did:zhtp:spQ", ObserverProofLevel::Basic, 1)],
    );
    exec.apply_block(&b1).expect("first observer under Basic sponsor");

    let b2 = make_block_with_txs(
        2,
        b1.header.block_hash,
        vec![register_tx("did:zhtp:quotaB", "did:zhtp:spQ", ObserverProofLevel::Basic, 2)],
    );
    let err = exec
        .apply_block(&b2)
        .expect_err("Basic sponsor quota=1 must be enforced");
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("quota") || msg.contains("max") || msg.contains("limit"),
        "unexpected quota-rejection error: {msg}"
    );
}

/// Pending observers cannot bootstrap: the canonical admission gate
/// returns `Denied(NotAuthorizedStatus(Pending))`. This is exactly the
/// rule consumed by `zhtp::runtime::observer_admission_check`.
#[test]
fn pending_observer_cannot_bootstrap() {
    let s = store();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:pendObs", "did:zhtp:spP", ObserverProofLevel::Basic, 1)],
    );
    exec.apply_block(&b1).expect("register");
    let record = record_for(&s, "did:zhtp:pendObs").expect("record exists");
    assert_eq!(record.status, ObserverAdmissionStatus::Pending);

    let policy = default_policy();
    let decision = evaluate_admission(&record, &policy, NET, NOW);
    assert!(
        matches!(
            decision,
            AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
                ObserverAdmissionStatus::Pending
            ))
        ),
        "unexpected decision: {decision:?}"
    );
}

/// Status transitions: A → S → A (reauthorize) and bootstrap effects.
#[test]
fn status_transitions_active_suspend_reauthorize() {
    let s = store_auto_approve();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);

    // Register — with auto_approve=true the observer lands in Active.
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:lifeObs", "did:zhtp:lifeSp", ObserverProofLevel::Basic, 1)],
    );
    exec.apply_block(&b1).expect("register");
    assert_eq!(
        record_for(&s, "did:zhtp:lifeObs").unwrap().status,
        ObserverAdmissionStatus::Active,
        "auto_approve policy must yield Active"
    );

    // A → S
    let b2 = make_block_with_txs(
        2,
        b1.header.block_hash,
        vec![suspend_tx("did:zhtp:lifeObs", "did:zhtp:lifeSp", 2)],
    );
    exec.apply_block(&b2).expect("suspend active");
    assert_eq!(
        record_for(&s, "did:zhtp:lifeObs").unwrap().status,
        ObserverAdmissionStatus::Suspended
    );

    // Suspended observer cannot bootstrap.
    let policy = default_policy();
    let suspended = record_for(&s, "did:zhtp:lifeObs").unwrap();
    assert!(matches!(
        evaluate_admission(&suspended, &policy, NET, NOW),
        AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
            ObserverAdmissionStatus::Suspended
        ))
    ));

    // S → A via reauthorize
    let b3 = make_block_with_txs(
        3,
        b2.header.block_hash,
        vec![reauth_tx("did:zhtp:lifeObs", "did:zhtp:lifeSp", 3)],
    );
    exec.apply_block(&b3).expect("reauthorize suspended");
    let reactivated = record_for(&s, "did:zhtp:lifeObs").unwrap();
    assert_eq!(reactivated.status, ObserverAdmissionStatus::Active);
    assert!(matches!(
        evaluate_admission(&reactivated, &policy, NET, NOW),
        AdmissionDecision::Authorized
    ));
}

/// Status transitions: A → R, S → R, P → R. All terminal — bootstrap denied.
#[test]
fn status_transitions_revoke_paths_all_deny_bootstrap() {
    let policy = default_policy();

    // A → R
    {
        let s = store_auto_approve();
        let exec = BlockExecutor::with_store(s.clone());
        let g = apply_genesis(&exec);
        let b1 = make_block_with_txs(
            1,
            g,
            vec![register_tx("did:zhtp:rA", "did:zhtp:spR", ObserverProofLevel::Basic, 1)],
        );
        exec.apply_block(&b1).expect("register");
        let h = did_to_hash(&"did:zhtp:rA".to_string());
        assert_eq!(
            s.get_observer_record(&h).unwrap().unwrap().status,
            ObserverAdmissionStatus::Active
        );

        let b2 = make_block_with_txs(
            2,
            b1.header.block_hash,
            vec![revoke_tx("did:zhtp:rA", "did:zhtp:spR", 2)],
        );
        exec.apply_block(&b2).expect("A->R");
        let rec = s.get_observer_record(&h).unwrap().unwrap();
        assert_eq!(rec.status, ObserverAdmissionStatus::Revoked);
        assert!(matches!(
            evaluate_admission(&rec, &policy, NET, NOW),
            AdmissionDecision::Denied(PolicyDenial::NotAuthorizedStatus(
                ObserverAdmissionStatus::Revoked
            ))
        ));
    }

    // S → R (auto_approve → Active, suspend, then revoke)
    {
        let s = store_auto_approve();
        let exec = BlockExecutor::with_store(s.clone());
        let g = apply_genesis(&exec);
        let b1 = make_block_with_txs(
            1,
            g,
            vec![register_tx("did:zhtp:rS", "did:zhtp:spS", ObserverProofLevel::Basic, 1)],
        );
        exec.apply_block(&b1).expect("register");
        let b2 = make_block_with_txs(
            2,
            b1.header.block_hash,
            vec![suspend_tx("did:zhtp:rS", "did:zhtp:spS", 2)],
        );
        exec.apply_block(&b2).expect("A->S");
        let h = did_to_hash(&"did:zhtp:rS".to_string());
        assert_eq!(
            s.get_observer_record(&h).unwrap().unwrap().status,
            ObserverAdmissionStatus::Suspended
        );

        let b3 = make_block_with_txs(
            3,
            b2.header.block_hash,
            vec![revoke_tx("did:zhtp:rS", "did:zhtp:spS", 3)],
        );
        exec.apply_block(&b3).expect("S->R");
        let rec = s.get_observer_record(&h).unwrap().unwrap();
        assert_eq!(rec.status, ObserverAdmissionStatus::Revoked);
    }

    // P → R (revoke a Pending observer)
    {
        let s = store();
        let exec = BlockExecutor::with_store(s.clone());
        let g = apply_genesis(&exec);
        let b1 = make_block_with_txs(
            1,
            g,
            vec![register_tx("did:zhtp:rP", "did:zhtp:spP2", ObserverProofLevel::Basic, 1)],
        );
        exec.apply_block(&b1).expect("register");
        let h = did_to_hash(&"did:zhtp:rP".to_string());
        let rec = s.get_observer_record(&h).unwrap().unwrap();
        assert_eq!(rec.status, ObserverAdmissionStatus::Pending);

        let b2 = make_block_with_txs(
            2,
            b1.header.block_hash,
            vec![revoke_tx("did:zhtp:rP", "did:zhtp:spP2", 2)],
        );
        exec.apply_block(&b2).expect("P->R revoke");
        let rec = s.get_observer_record(&h).unwrap().unwrap();
        assert_eq!(rec.status, ObserverAdmissionStatus::Revoked);
    }
}

/// Trusted sync-source enforcement: an admitted, Active, network-matched
/// observer is Authorized; a network-mismatched record is denied.
#[test]
fn trusted_sync_source_enforcement_via_evaluate_admission() {
    let s = store_auto_approve();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    let b1 = make_block_with_txs(
        1,
        g,
        vec![register_tx("did:zhtp:tsObs", "did:zhtp:tsSp", ObserverProofLevel::Basic, 1)],
    );
    exec.apply_block(&b1).expect("register");
    let h = did_to_hash(&"did:zhtp:tsObs".to_string());
    let rec = s.get_observer_record(&h).unwrap().unwrap();
    assert_eq!(rec.status, ObserverAdmissionStatus::Active);

    let policy = default_policy();

    // Matching network → Authorized.
    assert!(matches!(
        evaluate_admission(&rec, &policy, NET, NOW),
        AdmissionDecision::Authorized
    ));

    // Wrong network → Denied(NetworkMismatch).
    let decision = evaluate_admission(&rec, &policy, "mainnet", NOW);
    assert!(
        matches!(
            decision,
            AdmissionDecision::Denied(PolicyDenial::NetworkMismatch { .. })
        ),
        "unexpected decision: {decision:?}"
    );
}

/// Expired records cannot bootstrap even when status=Active.
#[test]
fn expired_record_denied_bootstrap() {
    let s = store_auto_approve();
    let exec = BlockExecutor::with_store(s.clone());
    let g = apply_genesis(&exec);
    // Register with an explicit expires_at in the past.
    let mut tx = register_tx("did:zhtp:expObs", "did:zhtp:expSp", ObserverProofLevel::Basic, 1);
    if let lib_blockchain::transaction::TransactionPayload::RegisterObserver(ref mut data) = tx.payload {
        data.expires_at = Some(NOW - 1);
    } else {
        panic!("expected RegisterObserver payload");
    }
    let b1 = make_block_with_txs(1, g, vec![tx]);
    exec.apply_block(&b1).expect("register expired");
    let h = did_to_hash(&"did:zhtp:expObs".to_string());
    let rec = s.get_observer_record(&h).unwrap().unwrap();
    assert_eq!(rec.status, ObserverAdmissionStatus::Active);
    assert_eq!(rec.expires_at, Some(NOW - 1));

    let policy = default_policy();
    let decision = evaluate_admission(&rec, &policy, NET, NOW);
    assert!(
        matches!(
            decision,
            AdmissionDecision::Denied(PolicyDenial::Expired { .. })
        ),
        "unexpected decision: {decision:?}"
    );
}
