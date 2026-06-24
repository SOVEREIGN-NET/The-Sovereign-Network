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
fn token_nonce_reads_sled_when_store_attached() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_nonce_store")).unwrap());
    let token = TokenId::new([5u8; 32]);
    let addr = Address::new([0xCC; 32]);
    store.begin_block(0).unwrap();
    store.set_token_nonce(&token, &addr, 42).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    bc.token_nonces.insert(([5u8; 32], [0xCC; 32]), 7);

    assert_eq!(
        bc.token_nonce(&[5u8; 32], &[0xCC; 32]).unwrap(),
        42,
        "facade must return sled nonce, not stale in-memory value"
    );
}

#[test]
fn is_nonce_current_reads_sled_nonce_not_stale_in_memory() {
    use crate::transaction::{TokenTransferData, Transaction, TransactionPayload};
    use crate::types::TransactionType;

    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("nonce_gate_store")).unwrap());
    let token_id = [0xDDu8; 32];
    let sender = [0xEEu8; 32];
    let token = TokenId::new(token_id);
    let addr = Address::new(sender);
    store.begin_block(0).unwrap();
    store.set_token_nonce(&token, &addr, 5).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    bc.token_nonces.insert((token_id, sender), 0);

    let current_tx = Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: crate::integration::crypto_integration::Signature::default(),
        memo: vec![],
        payload: TransactionPayload::TokenTransfer(TokenTransferData {
            token_id,
            from: sender,
            to: [0x11; 32],
            amount: 1,
            nonce: 5,
        }),
    };
    let stale_tx = Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: crate::integration::crypto_integration::Signature::default(),
        memo: vec![],
        payload: TransactionPayload::TokenTransfer(TokenTransferData {
            token_id,
            from: sender,
            to: [0x11; 32],
            amount: 1,
            nonce: 0,
        }),
    };

    assert!(
        bc.is_nonce_current(&current_tx),
        "nonce matching sled value must be accepted"
    );
    assert!(
        !bc.is_nonce_current(&stale_tx),
        "stale in-memory nonce-0 must be rejected when sled expects 5"
    );
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
fn count_token_holders_reads_sled_when_store_attached() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_holders_store")).unwrap());
    let token = TokenId::new([9u8; 32]);
    store.begin_block(0).unwrap();
    store
        .set_token_balance(&token, &Address::new([1u8; 32]), 100)
        .unwrap();
    store
        .set_token_balance(&token, &Address::new([2u8; 32]), 0)
        .unwrap();
    store
        .set_token_balance(&token, &Address::new([3u8; 32]), 50)
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    assert_eq!(bc.count_token_holders(&[9u8; 32]), 2);
}

#[test]
fn count_token_holders_uses_in_memory_in_storeless_mode() {
    use crate::contracts::TokenContract;
    use crate::integration::crypto_integration::PublicKey;

    let mut bc = Blockchain::new().expect("blockchain construct");
    assert!(bc.get_store().is_none());

    let token_id = [0xAAu8; 32];
    let mut token = TokenContract::new_sov_native();
    let holder = PublicKey {
        dilithium_pk: [0u8; 2592],
        kyber_pk: [0u8; 1568],
        key_id: [0x11; 32],
    };
    token.mint(&holder, 1_000).unwrap();
    bc.token_contracts.insert(token_id, token);

    assert_eq!(bc.count_token_holders(&token_id), 1);
}

#[test]
fn count_token_holders_ignores_mid_block_staged_writes() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_holders_midblock")).unwrap());
    let token = TokenId::new([0xBB; 32]);
    store.begin_block(0).unwrap();
    store
        .set_token_balance(&token, &Address::new([1u8; 32]), 10)
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store.clone());
    assert_eq!(bc.count_token_holders(&[0xBB; 32]), 1);

    store.begin_block(1).unwrap();
    store
        .set_token_balance(&token, &Address::new([2u8; 32]), 20)
        .unwrap();
    assert_eq!(
        bc.count_token_holders(&[0xBB; 32]),
        1,
        "mid-block staged holder must not be counted until commit"
    );
    store.commit_block().unwrap();
    assert_eq!(bc.count_token_holders(&[0xBB; 32]), 2);
}

#[test]
fn calculate_user_voting_power_reads_sled_not_in_memory() {
    use crate::transaction::WalletTransactionData;
    use crate::types::hash::Hash;

    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("facade_voting_power")).unwrap());
    let sov_id = crate::contracts::utils::generate_lib_token_id();
    let wallet_id = [0x44u8; 32];
    let identity_bytes = [0x55u8; 32];
    let identity_id = lib_identity::IdentityId::from_bytes(&identity_bytes);
    let amount = lib_types::sov::atoms(100);

    store.begin_block(0).unwrap();
    store
        .set_token_balance(
            &TokenId::new(sov_id),
            &Address::new(wallet_id),
            amount,
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    bc.voting_power_mode = crate::dao::VotingPowerMode::Linear;
    bc.token_contracts
        .insert(sov_id, crate::contracts::TokenContract::new_sov_native());

    let wallet_id_hash = Hash::new(wallet_id);
    bc.wallet_registry.insert(
        hex::encode(wallet_id),
        WalletTransactionData {
            wallet_id: wallet_id_hash,
            wallet_type: "Primary".to_string(),
            wallet_name: "Test".to_string(),
            alias: None,
            public_key: vec![0u8; 2592],
            owner_identity_id: Some(Hash::new(identity_id.0)),
            seed_commitment: Hash::default(),
            created_at: 0,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        },
    );

    assert_eq!(
        bc.calculate_user_voting_power(&identity_id),
        100,
        "voting power must use sled token_balance, not empty in-memory map"
    );
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
                ..Default::default()
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
                ..Default::default()
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

#[test]
fn identity_transaction_data_reads_sled_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_tx_data")).unwrap());
    let did = "did:zhtp:tx-data";
    let did_hash = crate::storage::did_to_hash(did);
    store.begin_block(0).unwrap();
    store
        .put_identity(
            &did_hash,
            &IdentityConsensus {
                did_hash,
                created_at: 42,
                registration_fee: 7,
                ..Default::default()
            },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &crate::storage::IdentityMetadata {
                did: did.to_string(),
                display_name: "Sled User".to_string(),
                public_key: vec![0xAB; 2592],
                ..Default::default()
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    let got = bc
        .identity_transaction_data(did)
        .expect("sled-backed identity");
    assert_eq!(got.display_name, "Sled User");
    assert_eq!(got.created_at, 42);
    assert_eq!(got.registration_fee, 7);
}

#[test]
fn identity_registry_snapshot_includes_sled_without_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_snapshot")).unwrap());
    let did = "did:zhtp:snapshot-only";
    let did_hash = crate::storage::did_to_hash(did);
    store.begin_block(0).unwrap();
    store
        .put_identity(&did_hash, &IdentityConsensus { did_hash, ..Default::default() })
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &crate::storage::IdentityMetadata {
                did: did.to_string(),
                display_name: "Only Sled".to_string(),
                public_key: vec![0xCD; 2592],
                ..Default::default()
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    let snap = bc.identity_registry_snapshot();
    assert_eq!(snap.get(did).map(|d| d.display_name.as_str()), Some("Only Sled"));
}

#[test]
fn identity_display_name_taken_reads_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("id_name_taken")).unwrap());
    let did = "did:zhtp:name-taken";
    let did_hash = crate::storage::did_to_hash(did);
    store.begin_block(0).unwrap();
    store
        .put_identity(&did_hash, &IdentityConsensus { did_hash, ..Default::default() })
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &crate::storage::IdentityMetadata {
                did: did.to_string(),
                display_name: "UniqueName".to_string(),
                public_key: vec![0xEF; 2592],
                ..Default::default()
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    assert!(bc.identity_display_name_taken("uniquename"));
    assert!(!bc.identity_display_name_taken("available"));
}

fn test_wallet_data(wallet_id: [u8; 32], name: &str) -> crate::transaction::WalletTransactionData {
    crate::transaction::WalletTransactionData {
        wallet_id: crate::types::hash::Hash::new(wallet_id),
        wallet_type: "Primary".to_string(),
        wallet_name: name.to_string(),
        alias: None,
        public_key: vec![],
        owner_identity_id: None,
        seed_commitment: crate::types::hash::Hash::zero(),
        created_at: 0,
        registration_fee: 0,
        capabilities: 0,
        initial_balance: 0,
    }
}

#[test]
fn wallet_exists_union_inmem_or_sled() {
    let mut bc = Blockchain::new().expect("blockchain construct");
    let wallet_id = [0x77u8; 32];
    let wallet_id_hex = hex::encode(wallet_id);
    bc.wallet_registry.insert(
        wallet_id_hex.clone(),
        test_wallet_data(wallet_id, "In-Mem"),
    );
    assert!(bc.wallet_exists(&wallet_id_hex), "in-mem present -> true");
    assert!(!bc.wallet_exists("00000000000000000000000000000000000000000000000000000000000000ab"));

    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("wallet_exists")).unwrap());
    store.begin_block(0).unwrap();
    store
        .put_wallet_projection(
            &wallet_id,
            &crate::storage::WalletProjectionRecord {
                wallet_data: test_wallet_data(wallet_id, "Sled Only"),
                committed_at_height: 0,
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc2 = Blockchain::new().expect("blockchain construct");
    bc2.set_store(store);
    assert!(bc2.wallet_exists(&wallet_id_hex), "sled-only wallet found via union");
}

#[test]
fn wallet_transaction_data_reads_sled_projection() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("wallet_tx_data")).unwrap());
    let wallet_id = [0x88u8; 32];
    let wallet_id_hex = hex::encode(wallet_id);
    store.begin_block(0).unwrap();
    store
        .put_wallet_projection(
            &wallet_id,
            &crate::storage::WalletProjectionRecord {
                wallet_data: test_wallet_data(wallet_id, "Projection Wallet"),
                committed_at_height: 3,
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    let got = bc
        .wallet_transaction_data(&wallet_id_hex)
        .expect("sled-backed wallet");
    assert_eq!(got.wallet_name, "Projection Wallet");
    assert_eq!(got.wallet_type, "Primary");
}

#[test]
fn wallet_registry_snapshot_includes_sled_without_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("wallet_snapshot")).unwrap());
    let wallet_id = [0x99u8; 32];
    let did_hex = hex::encode(wallet_id);
    store.begin_block(0).unwrap();
    store
        .put_wallet_projection(
            &wallet_id,
            &crate::storage::WalletProjectionRecord {
                wallet_data: test_wallet_data(wallet_id, "Only Sled"),
                committed_at_height: 0,
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    let snap = bc.wallet_registry_snapshot();
    assert_eq!(snap.get(&did_hex).map(|w| w.wallet_name.as_str()), Some("Only Sled"));
}

#[test]
fn wallet_count_reads_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("wallet_count")).unwrap());
    store.begin_block(0).unwrap();
    for i in 0..3u8 {
        let wallet_id = [i; 32];
        store
            .put_wallet_projection(
                &wallet_id,
                &crate::storage::WalletProjectionRecord {
                    wallet_data: test_wallet_data(wallet_id, &format!("Wallet{}", i)),
                    committed_at_height: 0,
                },
            )
            .unwrap();
    }
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store);
    assert_eq!(bc.wallet_count(), 3, "count comes from sled, not the in-mem shadow");
}

/// did_by_public_key() resolves a DID from a public key by scanning sled
/// metadata even when the in-memory shadow is empty (restart case) — the read
/// that lets council-membership / dedup checks work on a store-backed node
/// (#2639/#61).
#[test]
fn did_by_public_key_reads_sled_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("did_by_pk")).unwrap());

    let did = "did:zhtp:signer";
    let did_hash = crate::storage::did_to_hash(did);
    let pk = vec![0x9u8; 2592];
    // Consensus pin: did_by_public_key requires blake3(metadata.pk) ==
    // consensus.public_key_hash (CR PR #2678), so build the consensus record
    // with the matching hash.
    let pk_hash = crate::types::hash::blake3_hash(&pk).as_array();
    store.begin_block(0).unwrap();
    store
        .put_identity(
            &did_hash,
            &IdentityConsensus {
                did_hash,
                public_key_hash: pk_hash,
                ..Default::default()
            },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &IdentityMetadata {
                did: did.to_string(),
                display_name: "S".to_string(),
                public_key: pk.clone(),
                ownership_proof: vec![],
                controlled_nodes: vec![],
                owned_wallets: vec![],
                attributes: vec![],
                kyber_public_key: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store.clone());
    assert!(
        !bc.identity_registry.values().any(|i| i.public_key == pk),
        "test premise: this pubkey is sled-only (in-mem shadow empty, like after restart)"
    );
    assert_eq!(
        bc.did_by_public_key(&pk),
        Some(did.to_string()),
        "DID resolved from sled metadata despite empty in-mem shadow"
    );
    assert_eq!(
        bc.did_by_public_key(&vec![0x1u8; 2592]),
        None,
        "unknown pubkey -> None"
    );
    // is_public_key_registered routes through did_by_public_key.
    assert!(bc.is_public_key_registered(&pk));
    assert!(!bc.is_public_key_registered(&vec![0x1u8; 2592]));

    // CR pin: a metadata-only key whose consensus hash DOES NOT match
    // must be refused (drift signal), even though metadata says it's a
    // valid identity.
    let did_drift = "did:zhtp:drift";
    let drift_did_hash = crate::storage::did_to_hash(did_drift);
    let drift_pk = vec![0xAAu8; 2592];
    store.begin_block(1).unwrap();
    store
        .put_identity(
            &drift_did_hash,
            &IdentityConsensus {
                did_hash: drift_did_hash,
                // Intentionally NOT blake3(drift_pk) — simulates metadata/consensus drift.
                public_key_hash: [0u8; 32],
                ..Default::default()
            },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &drift_did_hash,
            &IdentityMetadata {
                did: did_drift.to_string(),
                display_name: "D".to_string(),
                public_key: drift_pk.clone(),
                ownership_proof: vec![],
                controlled_nodes: vec![],
                owned_wallets: vec![],
                attributes: vec![],
                kyber_public_key: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();
    assert_eq!(
        bc.did_by_public_key(&drift_pk),
        None,
        "drifted metadata key (metadata pk hash != consensus public_key_hash) must be refused"
    );
}

/// identity_controlled_nodes() reads controlled_nodes from sled metadata even
/// when the in-memory shadow is empty (the restart case) — the read that lets a
/// restarted validator recognize itself as the selected proposer (#2639/#59).
/// (Test from #2676; preserved across the merge with #2678.)
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
                kyber_public_key: vec![],
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

/// did_by_device_key_id() resolves a canonical DID from a device key-id
/// fingerprint — `blake3(dilithium)` or `blake3(dilithium || kyber)` — by
/// scanning sled metadata even when the in-memory shadow is empty (the restart
/// case). This is the read the messaging / device-key reverse lookups depend on
/// (#58); the combined-hash arm exercises the schema-v2 `kyber_public_key` the
/// migration persists (#2679). It is a fingerprint resolver (NOT consensus
/// signature verification), so it is not consensus-pinned.
#[test]
fn did_by_device_key_id_reads_sled_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("did_by_devkey")).unwrap());

    let did = "did:zhtp:device-owner";
    let did_hash = crate::storage::did_to_hash(did);
    let pk = vec![0x9u8; 2592];
    let kyber = vec![0x7u8; 1568];

    store.begin_block(0).unwrap();
    store
        .put_identity(
            &did_hash,
            &IdentityConsensus { did_hash, ..Default::default() },
        )
        .unwrap();
    store
        .put_identity_metadata(
            &did_hash,
            &IdentityMetadata {
                did: did.to_string(),
                display_name: "D".to_string(),
                public_key: pk.clone(),
                kyber_public_key: kyber.clone(),
                ownership_proof: vec![],
                controlled_nodes: vec![],
                owned_wallets: vec![],
                attributes: vec![],
            },
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().unwrap();
    bc.set_store(store.clone());
    assert!(
        !bc.identity_registry.contains_key(did)
            && !bc.identity_registry.values().any(|i| i.public_key == pk),
        "test premise: this identity is sled-only (absent from the in-mem shadow, like after restart)"
    );

    // (a) Dilithium-only key id. Computed with lib_crypto::hash_blake3 exactly
    //     as the facade does, so the hashes are byte-identical.
    let dil_key_id = hex::encode(lib_crypto::hash_blake3(&pk));
    assert_eq!(
        bc.did_by_device_key_id(&dil_key_id),
        Some(did.to_string()),
        "resolves DID from blake3(dilithium) over sled metadata"
    );

    // (b) Combined Dilithium+Kyber device key id (the schema-v2 kyber path).
    let combined = [&pk[..], &kyber[..]].concat();
    let combined_key_id = hex::encode(lib_crypto::hash_blake3(&combined));
    assert_eq!(
        bc.did_by_device_key_id(&combined_key_id),
        Some(did.to_string()),
        "resolves DID from blake3(dilithium || kyber) over sled metadata"
    );

    // (c) Unknown fingerprint -> None (no match, and the constructed
    //     did:zhtp:{key_id} is not a registered DID either).
    assert_eq!(
        bc.did_by_device_key_id(&"de".repeat(32)),
        None,
        "unknown device key id -> None"
    );

    // (d) Direct match: the key id is itself a registered DID suffix, resolved
    //     via the sled-first existence check (not the hash scan).
    let direct_did = "did:zhtp:abcd1234";
    let direct_hash = crate::storage::did_to_hash(direct_did);
    put_sled_identity(
        &store,
        1,
        direct_did,
        IdentityConsensus { did_hash: direct_hash, ..Default::default() },
    );
    assert_eq!(
        bc.did_by_device_key_id("abcd1234"),
        Some(direct_did.to_string()),
        "direct DID-suffix match resolves via identity_exists"
    );
}

// ---- #56 durable validator record sled persistence ----

/// Durable validator records persist + read back through the sled trait surface:
/// direct write (migration path), point get, iterator, count, and schema version.
/// A brand-new store reports schema version 0 (no durable validators yet), and
/// the iterator validates each record's identity_id hashes to its tree key (#56).
#[test]
fn validator_records_persist_through_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = SledStore::open(&temp.path().join("validators")).unwrap();

    // Brand-new store: no durable validators, schema version 0.
    assert_eq!(store.validator_record_schema_version().unwrap(), 0);
    assert_eq!(store.count_validator_records().unwrap(), 0);

    let did = "did:zhtp:val-A";
    let did_hash = crate::storage::did_to_hash(did);
    let record = crate::storage::StoredValidatorRecord {
        consensus: crate::storage::ValidatorConsensusRecord {
            identity_id: did.to_string(),
            consensus_key: [3u8; 2592],
            stake: 5_000,
            storage_provided: 1 << 40,
            status: "active".to_string(),
            oracle_key_id: None,
        },
        metadata: crate::storage::ValidatorMetadata {
            networking_key: vec![9, 9],
            rewards_key: vec![8, 8],
            network_address: "10.0.0.1:7000".to_string(),
            commission_rate: 3,
            registered_at: 12,
            last_activity: 34,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "onchain_governance".to_string(),
            governance_proposal_id: None,
        },
    };

    // Direct write (migration path) + point read round-trips byte-for-byte.
    store
        .put_validator_record_direct(&did_hash, &record)
        .unwrap();
    let got = store
        .get_validator_record(&did_hash)
        .unwrap()
        .expect("record present");
    assert_eq!(got, record);
    assert_eq!(store.count_validator_records().unwrap(), 1);

    // Iterator surfaces it (and would error if id didn't hash to the key).
    let all: Vec<_> = store.iter_validator_records().unwrap().collect();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].consensus.identity_id, did);

    // Schema version round-trips.
    store.set_validator_record_schema_version(1).unwrap();
    assert_eq!(store.validator_record_schema_version().unwrap(), 1);

    // Unknown key -> None.
    assert!(store.get_validator_record(&[0u8; 32]).unwrap().is_none());

    // Clear empties the tree.
    store.clear_validator_records().unwrap();
    assert_eq!(store.count_validator_records().unwrap(), 0);
}

/// #56: validator_exists is a union — in-memory overlay OR durable sled.
#[test]
fn validator_exists_union_inmem_or_sled() {
    let mut bc = Blockchain::new_runtime_state();
    let info = ValidatorInfo {
        identity_id: "did:zhtp:val-inmem".to_string(),
        stake: 100_000,
        storage_provided: 1 << 40,
        consensus_key: [1u8; 2592],
        networking_key: vec![2],
        rewards_key: vec![3],
        network_address: "1.2.3.4:1".to_string(),
        commission_rate: 0,
        status: "active".to_string(),
        registered_at: 1,
        last_activity: 1,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: "test".to_string(),
        governance_proposal_id: None,
        oracle_key_id: None,
    };
    bc.validator_registry.insert(info.identity_id.clone(), info);
    assert!(bc.validator_exists("did:zhtp:val-inmem"));
    assert!(!bc.validator_exists("did:zhtp:ghost"));

    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val-exists")).unwrap());
    let did = "did:zhtp:val-sled";
    let did_hash = crate::storage::did_to_hash(did);
    let record = crate::storage::StoredValidatorRecord {
        consensus: crate::storage::ValidatorConsensusRecord {
            identity_id: did.to_string(),
            consensus_key: [4u8; 2592],
            stake: 200_000,
            storage_provided: 1 << 40,
            status: "active".to_string(),
            oracle_key_id: None,
        },
        metadata: crate::storage::ValidatorMetadata {
            networking_key: vec![],
            rewards_key: vec![],
            network_address: "host:1".to_string(),
            commission_rate: 0,
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "test".to_string(),
            governance_proposal_id: None,
        },
    };
    store.put_validator_record_direct(&did_hash, &record).unwrap();
    let mut bc2 = Blockchain::new_runtime_state();
    bc2.store = Some(store);
    assert!(bc2.validator_exists(did), "sled-only validator found via union");
    let got = bc2.validator_info_by_did(did).expect("sled read");
    assert_eq!(got.stake, 200_000);
}

/// Custom tokens (BUBL class): executor writes balances to the sled
/// `token_balances` tree only — in-mem `TokenContract.balances` stays empty.
/// sled-first `token_balance()` must return the sled value, not 0 from in-mem.
#[test]
fn custom_token_balance_reads_sled_not_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("bubl_bal_store")).unwrap());
    let token_id = [0xBB; 32];
    let holder = [0x42; 32];
    let creator = crate::integration::crypto_integration::PublicKey::new([1u8; 2592]);
    let contract = crate::contracts::TokenContract::new(
        token_id,
        "Bubble".to_string(),
        "BUBL".to_string(),
        8,
        1_000_000,
        false,
        0,
        creator,
    );
    store.begin_block(0).unwrap();
    store.put_token_contract(&contract).unwrap();
    store
        .set_token_balance(
            &TokenId::new(token_id),
            &Address::new(holder),
            5_000,
        )
        .unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    // Simulate post-restart: no in-mem contract overlay.
    assert!(
        !bc.token_contracts.contains_key(&token_id),
        "test premise: custom token exists only in sled"
    );
    assert_eq!(
        bc.token_balance(&token_id, &holder).unwrap(),
        5_000,
        "facade must read sled balance for custom token (BUBL class)"
    );
    // In-mem-only read would wrongly return 0 — regression guard.
    assert_eq!(
        bc.token_contracts
            .get(&token_id)
            .map(|c| c.balance_of(&crate::integration::crypto_integration::PublicKey::new(
                [0u8; 2592]
            )))
            .unwrap_or(0),
        0,
        "in-mem path absent/empty — the bug #2637 fixed"
    );
}

/// Legacy fee path debits in-mem; sled must be updated so token_balance() agrees.
#[test]
fn legacy_fee_deduction_syncs_sled_balance() {
    use crate::block::{Block, BlockHeader};
    use crate::contracts::utils::generate_lib_token_id;
    use crate::transaction::{
        Transaction, TransactionInput, TransactionOutput, TransactionPayload,
    };
    use crate::types::TransactionType;
    use lib_crypto::types::keys::PublicKey;
    use lib_crypto::types::signatures::{Signature, SignatureAlgorithm};

    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("fee_sled_sync")).unwrap());
    let sov_id = generate_lib_token_id();
    let sender_id = [0x11u8; 32];
    let sender = PublicKey {
        dilithium_pk: [0u8; 2592],
        kyber_pk: [0u8; 1568],
        key_id: sender_id,
    };
    let initial: u128 = 10_000;
    let fee: u64 = 250;

    store
        .force_set_token_balances(&[(
            TokenId::new(sov_id),
            Address::new(sender_id),
            initial,
        )])
        .unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store.clone());
    let sov = crate::contracts::TokenContract::new_sov_native();
    bc.token_contracts.insert(sov_id, sov);
    bc.token_contracts
        .get_mut(&sov_id)
        .unwrap()
        .set_balance(&sender, initial);

    let tx = Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::Transfer,
        inputs: vec![TransactionInput {
            previous_output: crate::types::hash::Hash::new([1u8; 32]),
            output_index: 0,
            nullifier: crate::types::hash::Hash::new([2u8; 32]),
            zk_proof: crate::integration::zk_integration::ZkTransactionProof::default(),
        }],
        outputs: vec![TransactionOutput {
            commitment: crate::types::hash::Hash::new([3u8; 32]),
            note: crate::types::hash::Hash::new([4u8; 32]),
            recipient: PublicKey::new([5u8; 2592]),
            merkle_leaf: crate::types::hash::Hash::default(),
        }],
        fee,
        signature: Signature {
            signature: vec![0u8; 64],
            public_key: sender.clone(),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo: vec![],
        payload: TransactionPayload::None,
    };
    let block = Block::new(
        BlockHeader {
            version: 1,
            previous_hash: crate::types::hash::Hash::zero().into(),
            data_helix_root: crate::types::hash::Hash::zero().into(),
            timestamp: 0,
            height: 1,
            verification_helix_root: [0u8; 32],
            state_root: crate::types::hash::Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash: crate::types::hash::Hash::zero(),
        },
        vec![tx],
    );

    let collected = bc.deduct_transaction_fees(&block).unwrap();
    assert_eq!(collected, fee);

    let expected = initial - fee as u128;
    assert_eq!(
        bc.token_balance(&sov_id, &sender_id).unwrap(),
        expected,
        "sled-first read must see legacy fee debit"
    );
    assert_eq!(
        store
            .get_token_balance(&TokenId::new(sov_id), &Address::new(sender_id))
            .unwrap(),
        expected
    );
}

#[test]
fn validator_registry_snapshot_includes_sled_without_in_memory() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val_snapshot")).unwrap());
    let did = "did:zhtp:val-snapshot";
    let did_hash = crate::storage::did_to_hash(did);
    store
        .put_validator_record_direct(
            &did_hash,
            &crate::storage::StoredValidatorRecord {
                consensus: crate::storage::ValidatorConsensusRecord {
                    identity_id: did.to_string(),
                    consensus_key: [5u8; 2592],
                    stake: 300_000,
                    storage_provided: 1 << 40,
                    status: "active".to_string(),
                    oracle_key_id: None,
                },
                metadata: crate::storage::ValidatorMetadata {
                    networking_key: vec![],
                    rewards_key: vec![],
                    network_address: "snap:1".to_string(),
                    commission_rate: 0,
                    registered_at: 0,
                    last_activity: 0,
                    blocks_validated: 0,
                    slash_count: 0,
                    admission_source: "test".to_string(),
                    governance_proposal_id: None,
                },
            },
        )
        .unwrap();
    let mut bc = Blockchain::new_runtime_state();
    bc.store = Some(store);
    let snap = bc.validator_registry_snapshot();
    assert_eq!(snap.get(did).map(|v| v.stake), Some(300_000));
}

#[test]
fn validator_count_reads_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val_count")).unwrap());
    for i in 0..3u8 {
        let did = format!("did:zhtp:val-count{}", i);
        let did_hash = crate::storage::did_to_hash(&did);
        store
            .put_validator_record_direct(
                &did_hash,
                &crate::storage::StoredValidatorRecord {
                    consensus: crate::storage::ValidatorConsensusRecord {
                        identity_id: did,
                        consensus_key: [i; 2592],
                        stake: 100_000,
                        storage_provided: 1 << 40,
                        status: "active".to_string(),
                        oracle_key_id: None,
                    },
                    metadata: crate::storage::ValidatorMetadata::default(),
                },
            )
            .unwrap();
    }
    let mut bc = Blockchain::new_runtime_state();
    bc.store = Some(store);
    assert_eq!(bc.validator_count(), 3, "count comes from sled, not the in-mem shadow");
}

/// iter_token_contract_entries returns sled ids + metadata (#2637).
#[test]
fn iter_token_contract_entries_lists_sled_ids() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(SledStore::open(&temp.path().join("tok-entries")).unwrap());
    let token_id = [0x44u8; 32];
    let creator = crate::integration::crypto_integration::PublicKey::new([1u8; 2592]);
    let contract = crate::contracts::TokenContract::new(
        token_id,
        "Test".to_string(),
        "TST".to_string(),
        18,
        1_000_000,
        false,
        0,
        creator,
    );
    store.begin_block(0).unwrap();
    store.put_token_contract(&contract).unwrap();
    store.commit_block().unwrap();

    let mut bc = Blockchain::new().expect("blockchain construct");
    bc.set_store(store);
    let entries = bc.iter_token_contract_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, token_id);
    assert_eq!(entries[0].1.symbol, "TST");
}

/// Bootstrap install writes overlay + sled in one batch (#2639).
#[test]
fn install_bootstrap_validator_records_persists_to_sled() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val-bootstrap")).unwrap());
    let mut bc = Blockchain::new_runtime_state();
    bc.store = Some(store.clone());

    let written = bc
        .install_bootstrap_validator_records(vec![ValidatorInfo {
            identity_id: "did:zhtp:bootstrap-1".to_string(),
            stake: 100_000,
            storage_provided: 1 << 40,
            consensus_key: [9u8; 2592],
            networking_key: vec![1],
            rewards_key: vec![2],
            network_address: "10.0.0.1:9334".to_string(),
            commission_rate: 5,
            status: "active".to_string(),
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "bootstrap_genesis".to_string(),
            governance_proposal_id: None,
            oracle_key_id: None,
        }])
        .expect("install");
    assert_eq!(written, 1);
    assert_eq!(store.count_validator_records().unwrap(), 1);
    assert_eq!(bc.active_validators_for_consensus().len(), 1);
    assert_eq!(store.validator_record_schema_version().unwrap(), 1);
}

/// Repeated reads hit the generation/fingerprint cache; sled-only writes invalidate gen (#56).
#[test]
fn active_validator_infos_cache_invalidates_on_sled_write() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val-cache")).unwrap());
    let did = "did:zhtp:val-cache";
    let did_hash = crate::storage::did_to_hash(did);
    store
        .put_validator_record_direct(
            &did_hash,
            &crate::storage::StoredValidatorRecord {
                consensus: crate::storage::ValidatorConsensusRecord {
                    identity_id: did.to_string(),
                    consensus_key: [6u8; 2592],
                    stake: 100_000,
                    storage_provided: 1 << 40,
                    status: "active".to_string(),
                    oracle_key_id: None,
                },
                metadata: crate::storage::ValidatorMetadata {
                    networking_key: vec![],
                    rewards_key: vec![],
                    network_address: "h:1".to_string(),
                    commission_rate: 0,
                    registered_at: 1,
                    last_activity: 1,
                    blocks_validated: 0,
                    slash_count: 0,
                    admission_source: "test".to_string(),
                    governance_proposal_id: None,
                },
            },
        )
        .unwrap();

    let mut bc = Blockchain::new_runtime_state();
    bc.store = Some(store.clone());
    assert_eq!(bc.active_validator_infos().len(), 1);

    bc.persist_validator_record_direct(&ValidatorInfo {
        identity_id: "did:zhtp:val-cache-2".to_string(),
        stake: 200_000,
        storage_provided: 1 << 40,
        consensus_key: [7u8; 2592],
        networking_key: vec![],
        rewards_key: vec![],
        network_address: "h:2".to_string(),
        commission_rate: 0,
        status: "active".to_string(),
        registered_at: 1,
        last_activity: 1,
        blocks_validated: 0,
        slash_count: 0,
        admission_source: "test".to_string(),
        governance_proposal_id: None,
        oracle_key_id: None,
    })
    .unwrap();

    assert_eq!(bc.active_validator_infos().len(), 2);
}

/// In-memory non-active overlay must evict a sled-active record before persist (#56).
#[test]
fn active_validator_infos_inmem_unregister_evicts_sled_active() {
    let temp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(SledStore::open(&temp.path().join("val-overlay")).unwrap());
    let did = "did:zhtp:val-deact";
    let did_hash = crate::storage::did_to_hash(did);
    store
        .put_validator_record_direct(
            &did_hash,
            &crate::storage::StoredValidatorRecord {
                consensus: crate::storage::ValidatorConsensusRecord {
                    identity_id: did.to_string(),
                    consensus_key: [5u8; 2592],
                    stake: 100_000,
                    storage_provided: 1 << 40,
                    status: "active".to_string(),
                    oracle_key_id: None,
                },
                metadata: crate::storage::ValidatorMetadata {
                    networking_key: vec![],
                    rewards_key: vec![],
                    network_address: "h:1".to_string(),
                    commission_rate: 0,
                    registered_at: 1,
                    last_activity: 1,
                    blocks_validated: 0,
                    slash_count: 0,
                    admission_source: "test".to_string(),
                    governance_proposal_id: None,
                },
            },
        )
        .unwrap();

    let mut bc = Blockchain::new_runtime_state();
    bc.store = Some(store);
    bc.validator_registry.insert(
        did.to_string(),
        ValidatorInfo {
            identity_id: did.to_string(),
            stake: 100_000,
            storage_provided: 1 << 40,
            consensus_key: [5u8; 2592],
            networking_key: vec![],
            rewards_key: vec![],
            network_address: "h:1".to_string(),
            commission_rate: 0,
            status: "inactive".to_string(),
            registered_at: 1,
            last_activity: 2,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: "test".to_string(),
            governance_proposal_id: None,
            oracle_key_id: None,
        },
    );

    let active: Vec<_> = bc
        .active_validator_infos()
        .into_iter()
        .map(|v| v.identity_id)
        .collect();
    assert!(
        !active.contains(&did.to_string()),
        "inactive in-mem overlay must not leave sled-active in consensus set"
    );
}
