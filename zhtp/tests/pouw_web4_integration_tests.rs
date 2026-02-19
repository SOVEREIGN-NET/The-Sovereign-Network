//! PoUW Web4 Integration Tests (PoUW-BETA #1354)
//!
//! Covers the full Web4 route → receipt → validation flow, including:
//! - Test 1: Web4 manifest route receipt accepted and reward produced
//! - Test 2: Web4 content served receipt accepted and reward produced
//! - Test 3: Anti-abuse — fabricated manifest CID rejected
//! - Test 4: Anti-abuse — replay detected and rejected
//! - Test 5: Anti-abuse — new identity rejected (too young)
//! - Test 6: Anti-abuse — signature forgery rejected

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use zhtp::pouw::{
    ChallengeGenerator,
    new_shared_session_log,
    validation::ReceiptValidator,
};
use zhtp::pouw::types::{
    ProofType, Receipt, ReceiptBatch, SignedReceipt, POUW_VERSION,
};

use lib_identity::{IdentityManager, IdentityType};
use lib_crypto::{
    classical::ed25519::{ed25519_keypair_from_seed, ed25519_sign},
    PublicKey,
    Hash,
};

// =============================================================================
// Test helpers
// =============================================================================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a deterministic Ed25519 keypair from a fixed seed byte.
fn make_ed25519_keys(seed_byte: u8) -> ([u8; 32], Vec<u8>) {
    let seed = [seed_byte; 32];
    let (pk_vec, sk_vec) = ed25519_keypair_from_seed(&seed);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_vec);
    (pk, sk_vec)
}

/// Build a 32-byte identity ID and matching DID from a seed byte.
fn make_did(id_byte: u8) -> (Hash, String) {
    let id_bytes = [id_byte; 32];
    let id = Hash::from_bytes(&id_bytes);
    let did = format!("did:zhtp:{}", hex::encode(&id_bytes));
    (id, did)
}

/// Register an identity in the manager.
///
/// `ed25519_pk` is stored as `key_id` in the PublicKey so that the
/// validator can resolve it for signature verification.
fn register_identity(
    manager: &mut IdentityManager,
    id_byte: u8,
    ed25519_pk: [u8; 32],
    created_at: u64,
) -> String {
    let (identity_id, did) = make_did(id_byte);
    let public_key = PublicKey {
        dilithium_pk: vec![],
        kyber_pk: vec![],
        key_id: ed25519_pk,
    };
    manager
        .register_external_identity(
            identity_id,
            did.clone(),
            public_key,
            IdentityType::Human,
            "test_device".to_string(),
            Some("Test User".to_string()),
            created_at,
        )
        .expect("register_external_identity failed");
    did
}

/// Issue a challenge that allows the given proof types.
async fn issue_challenge(
    generator: &Arc<ChallengeGenerator>,
    proof_types: &str,
) -> (Vec<u8>, Vec<u8>) {
    let response = generator
        .generate_challenge(Some(proof_types), None, None, None)
        .await
        .expect("generate_challenge failed");

    let token_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.token)
        .expect("base64 decode challenge token");
    let token: zhtp::pouw::types::ChallengeToken =
        serde_json::from_slice(&token_bytes).expect("parse challenge token");

    (token.challenge_nonce, token.task_id)
}

/// Build an aux JSON string for a Web4ManifestRoute receipt.
fn web4_manifest_aux(
    manifest_cid: &str,
    domain: &str,
    route_hops: u8,
    quic_session_id: [u8; 8],
) -> String {
    serde_json::json!({
        "manifest_cid": manifest_cid,
        "domain": domain,
        "route_hops": route_hops,
        "quic_session_id": hex::encode(quic_session_id),
    })
    .to_string()
}

/// Build an aux JSON string for a Web4ContentServed receipt.
fn web4_content_aux(
    manifest_cid: &str,
    domain: &str,
    served_from_cache: bool,
    quic_session_id: [u8; 8],
) -> String {
    serde_json::json!({
        "manifest_cid": manifest_cid,
        "domain": domain,
        "served_from_cache": served_from_cache,
        "quic_session_id": hex::encode(quic_session_id),
    })
    .to_string()
}

/// Build and sign a receipt batch.
fn build_signed_batch(
    client_did: &str,
    ed25519_sk: &[u8],
    challenge_nonce: Vec<u8>,
    task_id: Vec<u8>,
    proof_type: ProofType,
    bytes_verified: u64,
    aux: Option<String>,
    receipt_nonce_seed: u8,
) -> ReceiptBatch {
    let now = now_secs();
    let receipt = Receipt {
        version: POUW_VERSION,
        task_id: task_id.clone(),
        client_did: client_did.to_string(),
        client_node_id: vec![0u8; 32],
        provider_id: vec![],
        content_id: vec![1u8; 32],
        proof_type,
        bytes_verified,
        result_ok: true,
        started_at: now - 1,
        finished_at: now,
        receipt_nonce: vec![receipt_nonce_seed; 32],
        challenge_nonce,
        aux,
    };

    let receipt_bytes = bincode::serialize(&receipt).expect("serialize receipt");
    let signature = ed25519_sign(&receipt_bytes, ed25519_sk).expect("sign receipt");

    ReceiptBatch {
        version: POUW_VERSION,
        client_did: client_did.to_string(),
        receipts: vec![SignedReceipt {
            receipt,
            sig_scheme: "ed25519".to_string(),
            signature,
        }],
    }
}

// Bring base64 engine into scope
use base64::Engine;

// =============================================================================
// Test 1: Web4 manifest route → receipt accepted
// =============================================================================

#[tokio::test]
async fn test_web4_manifest_route_receipt_accepted() {
    // Setup keys & identity (aged past 24h)
    let (node_pk, node_sk) = make_ed25519_keys(0xAA);
    let (client_pk, client_sk) = make_ed25519_keys(0x01);
    let created_at = now_secs() - 90_000; // 25 hours old

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x01, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    let session_log = new_shared_session_log();
    let quic_session_id = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    session_log
        .write()
        .await
        .record(quic_session_id, client_did.clone(), "/api/v1/pouw".to_string());

    let validator = ReceiptValidator::new(generator.clone(), identity_mgr)
        .with_session_log(session_log)
        .with_min_identity_age(86_400);

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "web4manifestroute,web4contentserved,hash").await;

    let aux = web4_manifest_aux(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "central.sov",
        3,
        quic_session_id,
    );

    let batch = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce,
        task_id,
        ProofType::Web4ManifestRoute,
        4096,
        Some(aux),
        0x10,
    );

    let response = validator.validate_batch(&batch).await.unwrap();
    assert_eq!(response.accepted.len(), 1, "Expected receipt to be accepted: {:?}", response.rejected);
    assert_eq!(response.rejected.len(), 0);

    // Verify receipt is stored
    let receipts = validator.get_validated_receipts().await;
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r.proof_type, ProofType::Web4ManifestRoute);
    assert_eq!(r.bytes_verified, 4096);
    assert_eq!(r.client_did, client_did);
    assert!(r.manifest_cid.is_some(), "manifest_cid should be set");
    assert_eq!(r.manifest_cid.as_deref().unwrap(), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
    assert_eq!(r.domain.as_deref().unwrap(), "central.sov");
    assert_eq!(r.route_hops, Some(3));
}

// =============================================================================
// Test 2: Web4 content served → receipt accepted
// =============================================================================

#[tokio::test]
async fn test_web4_content_served_receipt_accepted() {
    let (node_pk, node_sk) = make_ed25519_keys(0xBB);
    let (client_pk, client_sk) = make_ed25519_keys(0x02);
    let created_at = now_secs() - 90_000;

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x02, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    let session_log = new_shared_session_log();
    let quic_session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    session_log
        .write()
        .await
        .record(quic_session_id, client_did.clone(), "/api/v1/pouw".to_string());

    let validator = ReceiptValidator::new(generator.clone(), identity_mgr)
        .with_session_log(session_log)
        .with_min_identity_age(86_400);

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "web4manifestroute,web4contentserved,hash").await;

    let aux = web4_content_aux(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "app.sov",
        true,
        quic_session_id,
    );

    let batch = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce,
        task_id,
        ProofType::Web4ContentServed,
        65536,
        Some(aux),
        0x20,
    );

    let response = validator.validate_batch(&batch).await.unwrap();
    assert_eq!(response.accepted.len(), 1, "Expected receipt to be accepted: {:?}", response.rejected);
    assert_eq!(response.rejected.len(), 0);

    let receipts = validator.get_validated_receipts().await;
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert_eq!(r.proof_type, ProofType::Web4ContentServed);
    assert_eq!(r.bytes_verified, 65536);
    assert_eq!(r.served_from_cache, Some(true));
    assert_eq!(r.domain.as_deref().unwrap(), "app.sov");
}

// =============================================================================
// Test 3: Anti-abuse — fabricated receipt (missing manifest_cid) rejected
// =============================================================================

#[tokio::test]
async fn test_fabricated_receipt_missing_manifest_cid_rejected() {
    let (node_pk, node_sk) = make_ed25519_keys(0xCC);
    let (client_pk, client_sk) = make_ed25519_keys(0x03);
    let created_at = now_secs() - 90_000;

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x03, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    let validator = ReceiptValidator::new(generator.clone(), identity_mgr);

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "web4manifestroute,web4contentserved,hash").await;

    // Fabricated: aux JSON missing manifest_cid
    let bad_aux = serde_json::json!({
        "domain": "evil.sov",
        "route_hops": 1,
        "quic_session_id": "deadbeefcafebabe",
        // manifest_cid intentionally absent
    })
    .to_string();

    let batch = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce,
        task_id,
        ProofType::Web4ManifestRoute,
        1024,
        Some(bad_aux),
        0x30,
    );

    let response = validator.validate_batch(&batch).await.unwrap();
    assert_eq!(response.accepted.len(), 0, "Fabricated receipt should be rejected");
    assert_eq!(response.rejected.len(), 1);
    assert_eq!(response.rejected[0].reason, "BAD_PROOF");
}

// =============================================================================
// Test 4: Anti-abuse — replay detected and rejected
// =============================================================================

#[tokio::test]
async fn test_replay_receipt_rejected() {
    let (node_pk, node_sk) = make_ed25519_keys(0xDD);
    let (client_pk, client_sk) = make_ed25519_keys(0x04);
    let created_at = now_secs() - 90_000;

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x04, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    let session_log = new_shared_session_log();
    let quic_session_id = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    session_log
        .write()
        .await
        .record(quic_session_id, client_did.clone(), "/api/v1/pouw".to_string());

    let validator = Arc::new(
        ReceiptValidator::new(generator.clone(), identity_mgr)
            .with_session_log(session_log),
    );

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "web4manifestroute,web4contentserved,hash").await;

    let aux = web4_manifest_aux(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "replay.sov",
        2,
        quic_session_id,
    );

    // First submission — same nonce (0x40)
    let batch1 = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce.clone(),
        task_id.clone(),
        ProofType::Web4ManifestRoute,
        1024,
        Some(aux.clone()),
        0x40,
    );

    let resp1 = validator.validate_batch(&batch1).await.unwrap();
    assert_eq!(resp1.accepted.len(), 1, "First submission should be accepted");

    // Second submission — same receipt nonce → REPLAY
    let batch2 = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce,
        task_id,
        ProofType::Web4ManifestRoute,
        1024,
        Some(aux),
        0x40, // Same nonce_seed → same receipt_nonce bytes
    );

    let resp2 = validator.validate_batch(&batch2).await.unwrap();
    assert_eq!(resp2.accepted.len(), 0, "Replay should be rejected");
    assert_eq!(resp2.rejected.len(), 1);
    assert_eq!(resp2.rejected[0].reason, "REPLAY");
}

// =============================================================================
// Test 5: Anti-abuse — new identity rejected (too young)
// =============================================================================

#[tokio::test]
async fn test_new_identity_receipt_rejected() {
    let (node_pk, node_sk) = make_ed25519_keys(0xEE);
    let (client_pk, client_sk) = make_ed25519_keys(0x05);

    // Identity created NOW (0 seconds old — well below 86400s minimum)
    let created_at = now_secs();

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x05, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    // Validator configured with 24-hour minimum identity age
    let validator = ReceiptValidator::new(generator.clone(), identity_mgr)
        .with_min_identity_age(86_400);

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "hash").await;

    let batch = build_signed_batch(
        &client_did,
        &client_sk,
        challenge_nonce,
        task_id,
        ProofType::Hash,
        1024,
        None,
        0x50,
    );

    let response = validator.validate_batch(&batch).await.unwrap();
    assert_eq!(response.accepted.len(), 0, "New identity should be rejected");
    assert_eq!(response.rejected.len(), 1);
    assert_eq!(
        response.rejected[0].reason, "CLIENT_INVALID",
        "Expected CLIENT_INVALID for new identity, got {:?}",
        response.rejected[0].reason
    );
}

// =============================================================================
// Test 6: Anti-abuse — DID signature forgery rejected
// =============================================================================

#[tokio::test]
async fn test_signature_forgery_rejected() {
    let (node_pk, node_sk) = make_ed25519_keys(0xFF);
    let (client_pk, _client_sk) = make_ed25519_keys(0x06);
    let created_at = now_secs() - 90_000;

    let mut identity_manager = IdentityManager::new();
    let client_did = register_identity(&mut identity_manager, 0x06, client_pk, created_at);

    let generator = Arc::new(ChallengeGenerator::new(node_sk.try_into().unwrap(), node_pk));
    let identity_mgr = Arc::new(RwLock::new(identity_manager));

    let validator = ReceiptValidator::new(generator.clone(), identity_mgr);

    let (challenge_nonce, task_id) =
        issue_challenge(&generator, "hash").await;

    let now = now_secs();
    let receipt = Receipt {
        version: POUW_VERSION,
        task_id: task_id.clone(),
        client_did: client_did.clone(),
        client_node_id: vec![0u8; 32],
        provider_id: vec![],
        content_id: vec![1u8; 32],
        proof_type: ProofType::Hash,
        bytes_verified: 1024,
        result_ok: true,
        started_at: now - 1,
        finished_at: now,
        receipt_nonce: vec![0x60; 32],
        challenge_nonce,
        aux: None,
    };

    // Sign with a DIFFERENT key (attacker's key, not client's)
    let (_attacker_pk, attacker_sk) = make_ed25519_keys(0x99);
    let receipt_bytes = bincode::serialize(&receipt).expect("serialize receipt");
    let forged_signature = ed25519_sign(&receipt_bytes, &attacker_sk).expect("sign with wrong key");

    let batch = ReceiptBatch {
        version: POUW_VERSION,
        client_did: client_did.clone(),
        receipts: vec![SignedReceipt {
            receipt,
            sig_scheme: "ed25519".to_string(),
            signature: forged_signature,
        }],
    };

    let response = validator.validate_batch(&batch).await.unwrap();
    assert_eq!(response.accepted.len(), 0, "Forged signature should be rejected");
    assert_eq!(response.rejected.len(), 1);
    assert_eq!(
        response.rejected[0].reason, "BAD_SIG",
        "Expected BAD_SIG for forged signature, got {:?}",
        response.rejected[0].reason
    );
}
