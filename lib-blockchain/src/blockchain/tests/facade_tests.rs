//! Phase 1 (#2635) facade tests: sled-first reads on `Blockchain`.
//!
//! These lock in the contract that `token_balance` and
//! `identity_consensus_by_did` read the authoritative sled store when one is
//! attached, and degrade gracefully (in-mem / `None`) in store-less mode.

use super::*;
use crate::storage::{Address, IdentityConsensus, SledStore, TokenId};
use std::sync::Arc;

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
