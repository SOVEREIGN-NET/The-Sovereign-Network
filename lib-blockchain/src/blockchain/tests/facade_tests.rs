//! Phase 1 (#2635) facade tests: sled-first reads on `Blockchain`.
//!
//! These lock in the contract that `token_balance` and
//! `identity_consensus_by_did` read the authoritative sled store when one is
//! attached, and degrade gracefully (in-mem / `None`) in store-less mode.

use super::*;
use crate::storage::{Address, IdentityConsensus, SledStore, TokenId};
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
