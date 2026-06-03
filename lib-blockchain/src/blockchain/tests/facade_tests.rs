//! Phase 1 (#2635) facade tests: sled-first reads on `Blockchain`.
//!
//! These lock in the contract that `token_balance` and
//! `identity_consensus_by_did` read the authoritative sled store when one is
//! attached, and degrade gracefully (in-mem / `None`) in store-less mode.

use super::*;
use crate::storage::{Address, IdentityConsensus, IdentityMetadata, SledStore, TokenId};
use std::sync::Arc;

/// #2637: iter_token_contract_metadata() is sled-first and surfaces the
/// contract set (name/symbol/decimals/supply). It is METADATA ONLY — per its
/// doc, per-address balances on the returned contracts are unreliable (the
/// executor writes balances to a separate token_balances tree, so a contract it
/// wrote has an empty balances map). Balances must be read via token_balance().
#[test]
fn iter_token_contract_metadata_lists_sled_contracts() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_meta_store")).unwrap());

    let creator = crate::integration::crypto_integration::PublicKey::new([1u8; 2592]);
    let custom = crate::contracts::TokenContract::new(
        [0xCC; 32],
        "Meta".to_string(),
        "MTA".to_string(),
        8,
        1_000_000,
        false,
        0,
        creator,
    );
    store.begin_block(0).unwrap();
    store.put_token_contract(&custom).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);

    let listed = bc.iter_token_contract_metadata();
    let mta = listed
        .iter()
        .find(|c| c.symbol == "MTA")
        .expect("MTA contract must be listed from sled");
    assert_eq!(mta.name, "Meta");
    assert_eq!(mta.max_supply, 1_000_000);
}

/// CR #2658 #2: `token_balance` is now write-through inside an open block.
/// A `set_token_balance` staged in `tx_batch` between `begin_block` and
/// `commit_block` is observed by subsequent reads via the facade. Without
/// this, mid-`apply_block` reads from `process_*_transactions` would see
/// pre-block state and silently authorise a double-spend.
#[test]
fn token_balance_mid_block_reads_staged_write() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("midblock_store")).unwrap());
    let token = TokenId::new([3u8; 32]);
    let addr = Address::new([0x55; 32]);

    // Commit an initial balance of 100.
    store.begin_block(0).unwrap();
    store.set_token_balance(&token, &addr, 100).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store.clone());
    assert_eq!(bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(), 100);

    // Open a new block, stage 999, do NOT commit.
    store.begin_block(1).unwrap();
    store.set_token_balance(&token, &addr, 999).unwrap();
    assert_eq!(
        bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(),
        999,
        "mid-block: facade must observe the staged write (write-through)"
    );

    // After commit, the value persists.
    store.commit_block().unwrap();
    assert_eq!(bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(), 999);

    // Multiple staged writes in the same block: last write wins.
    store.begin_block(2).unwrap();
    store.set_token_balance(&token, &addr, 1).unwrap();
    store.set_token_balance(&token, &addr, 7).unwrap();
    assert_eq!(bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(), 7);
    store.commit_block().unwrap();
    assert_eq!(bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(), 7);

    // Staged remove (zero balance) is observed as 0 even if sled still has the
    // pre-block value.
    store.begin_block(3).unwrap();
    store.set_token_balance(&token, &addr, 0).unwrap();
    assert_eq!(
        bc.token_balance(&[3u8; 32], &[0x55; 32]).unwrap(),
        0,
        "mid-block: staged remove visible as 0"
    );
    store.commit_block().unwrap();
}

#[test]
fn token_balance_reads_sled_when_store_attached() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_bal_store")).unwrap());

    let token = TokenId::new([7u8; 32]);
    let addr = Address::new([0xAB; 32]);
    store.begin_block(0).unwrap();
    store.set_token_balance(&token, &addr, 4_242).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);

    assert_eq!(
        bc.token_balance(&[7u8; 32], &[0xAB; 32]).unwrap(),
        4_242,
        "facade must return the sled balance"
    );
    // Unknown address under an attached store reads sled's authoritative zero.
    assert_eq!(bc.token_balance(&[7u8; 32], &[0x01; 32]).unwrap(), 0);
}

#[test]
fn identity_consensus_by_did_none_without_store() {
    let bc = Blockchain::new().expect("blockchain construct");
    assert!(bc.get_store().is_none(), "test assumes no store attached");
    assert!(
        bc.identity_consensus_by_did("did:zhtp:nobody").is_none(),
        "store-less facade returns None"
    );
}

#[test]
fn identity_consensus_by_did_reads_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_id_store")).unwrap());

    let did = "did:zhtp:facade-test";
    let did_hash = crate::storage::did_to_hash(did);
    let consensus = IdentityConsensus {
        did_hash,
        owner: Address::new([0x11; 32]),
        public_key_hash: [0x22; 32],
        did_document_hash: [0x33; 32],
        registration_fee: 100,
        ..Default::default()
    };

    store.begin_block(0).unwrap();
    store.put_identity(&did_hash, &consensus).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);

    let got = bc
        .identity_consensus_by_did(did)
        .expect("facade must read the identity from sled");
    assert_eq!(got.did_hash, did_hash);
    assert_eq!(got.registration_fee, 100);
    // An unknown DID is None even with a store attached.
    assert!(bc.identity_consensus_by_did("did:zhtp:unknown").is_none());
}

// ---- #2639 identity field facade tests ----

/// Construct a minimal in-memory IdentityTransactionData (no Default derive).
fn mk_inmem_identity(did: &str) -> crate::transaction::core::IdentityTransactionData {
    crate::transaction::core::IdentityTransactionData {
        did: did.to_string(),
        display_name: "InMem".to_string(),
        public_key: vec![],
        ownership_proof: vec![],
        identity_type: "user".to_string(),
        did_document_hash: crate::types::hash::Hash::default(),
        created_at: 0,
        registration_fee: 0,
        dao_fee: 0,
        controlled_nodes: vec![],
        owned_wallets: vec![],
        kyber_public_key: vec![],
    }
}

fn put_sled_identity(store: &SledStore, height: u64, did: &str, consensus: IdentityConsensus) {
    let did_hash = crate::storage::did_to_hash(did);
    store.begin_block(height).unwrap();
    store.put_identity(&did_hash, &consensus).unwrap();
    store.commit_block().unwrap();
}

/// identity_exists() is a union: in-mem (pending/same-block) OR durable sled.
/// The sled-only case is what a store-backed node sees after restart (the
/// in-memory registry is empty — no sled->in-mem rebuild).
#[test]
fn identity_exists_union_inmem_or_sled() {
    // store-less: answers from the in-memory shadow.
    let mut bc = Blockchain::new().unwrap();
    bc.identity_registry
        .insert("did:zhtp:inmem".to_string(), mk_inmem_identity("did:zhtp:inmem"));
    assert!(bc.identity_exists("did:zhtp:inmem"), "in-mem present -> true");
    assert!(!bc.identity_exists("did:zhtp:ghost"), "absent everywhere -> false");

    // sled-backed with an EMPTY in-mem registry (post-restart simulation):
    // the sled-only identity must still be found.
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_exists")).unwrap());
    let did = "did:zhtp:sledonly";
    let did_hash = crate::storage::did_to_hash(did);
    put_sled_identity(
        &store,
        0,
        did,
        IdentityConsensus { did_hash, ..Default::default() },
    );
    let mut bc2 = Blockchain::new().unwrap();
    bc2.set_store(store);
    assert!(
        !bc2.identity_registry.contains_key(did),
        "test premise: this DID is sled-only (absent from the in-mem shadow)"
    );
    assert!(bc2.identity_exists(did), "sled-only identity found via union");
    assert!(!bc2.identity_exists("did:zhtp:ghost"));
}

/// identity_count() reports the authoritative sled count, not the (possibly
/// empty) in-memory shadow.
#[test]
fn identity_count_reads_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_count")).unwrap());
    store.begin_block(0).unwrap();
    for i in 0..3u8 {
        let did = format!("did:zhtp:count{}", i);
        let did_hash = crate::storage::did_to_hash(&did);
        store
            .put_identity(&did_hash, &IdentityConsensus { did_hash, ..Default::default() })
            .unwrap();
    }
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store);
    assert_eq!(bc.identity_count(), 3, "count comes from sled, not the in-mem shadow");
    assert_eq!(
        bc.iter_identities_consensus().len(),
        3,
        "iter_identities_consensus surfaces the full sled set"
    );
}

/// identity_public_key() returns the metadata key ONLY when it is pinned to
/// consensus (blake3(pk) == consensus.public_key_hash); a drifted key is
/// refused (None).
#[test]
fn identity_public_key_pins_to_consensus() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_pk")).unwrap());

    // Pinned: metadata key hashes to consensus.public_key_hash.
    let did = "did:zhtp:pk-ok";
    let did_hash = crate::storage::did_to_hash(did);
    let pk = vec![0x7u8; 2592];
    let pk_hash = crate::types::hash::blake3_hash(&pk).as_array();
    store.begin_block(0).unwrap();
    store
        .put_identity(
            &did_hash,
            &IdentityConsensus { did_hash, public_key_hash: pk_hash, ..Default::default() },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &IdentityMetadata {
                did: did.to_string(),
                display_name: "Pinned".to_string(),
                public_key: pk.clone(),
                ownership_proof: vec![],
                controlled_nodes: vec![],
                owned_wallets: vec![],
                attributes: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    // Drifted: metadata key whose hash does NOT match consensus.public_key_hash.
    let bad = "did:zhtp:pk-drift";
    let bad_hash = crate::storage::did_to_hash(bad);
    store.begin_block(1).unwrap();
    store
        .put_identity(
            &bad_hash,
            &IdentityConsensus { did_hash: bad_hash, public_key_hash: [0xAB; 32], ..Default::default() },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &bad_hash,
            &IdentityMetadata {
                did: bad.to_string(),
                display_name: "Drift".to_string(),
                public_key: vec![0x9u8; 2592],
                ownership_proof: vec![],
                controlled_nodes: vec![],
                owned_wallets: vec![],
                attributes: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store);
    assert_eq!(
        bc.identity_public_key(did),
        Some(pk),
        "pinned key returned when blake3(pk) == consensus.public_key_hash"
    );
    assert_eq!(
        bc.identity_public_key(bad),
        None,
        "drifted key (hash mismatch) refused"
    );
    assert_eq!(
        bc.identity_display_name(did),
        Some("Pinned".to_string()),
        "display_name read from sled metadata"
    );
}

/// identity_controlled_nodes() reads controlled_nodes from sled metadata even
/// when the in-memory shadow is empty (the restart case) — the read that lets a
/// restarted validator recognize itself as the selected proposer (#2639/#59).
#[test]
fn identity_controlled_nodes_reads_sled_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_cn")).unwrap());

    let did = "did:zhtp:validator-x";
    let did_hash = crate::storage::did_to_hash(did);
    let nodes = vec!["aa".repeat(32), "bb".repeat(32)];
    store.begin_block(0).unwrap();
    store
        .put_identity(&did_hash, &IdentityConsensus { did_hash, ..Default::default() })
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &IdentityMetadata {
                did: did.to_string(),
                display_name: "V".to_string(),
                public_key: vec![],
                ownership_proof: vec![],
                controlled_nodes: nodes.clone(),
                owned_wallets: vec![],
                attributes: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store);
    assert!(
        !bc.identity_registry.contains_key(did),
        "test premise: DID is sled-only (in-mem shadow empty, like after restart)"
    );
    assert_eq!(
        bc.identity_controlled_nodes(did),
        Some(nodes),
        "controlled_nodes resolved from sled metadata despite empty in-mem shadow"
    );
    assert_eq!(
        bc.identity_controlled_nodes("did:zhtp:unknown"),
        None,
        "unknown DID -> None"
    );
}
