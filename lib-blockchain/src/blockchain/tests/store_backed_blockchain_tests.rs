use super::*;
use crate::block::{Block, BlockHeader};
use crate::storage::SledStore;
use crate::types::Hash;

fn make_header(height: u64, prev_hash: Hash) -> BlockHeader {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    BlockHeader {
        version: 1,
        previous_hash: prev_hash.into(),
        data_helix_root: Hash::default().into(),
        timestamp: 1_700_000_000 + height,
        height,
        verification_helix_root: [0u8; 32],
        state_root: Hash::default().into(),
        bft_quorum_root: [0u8; 32],
        block_hash: Hash::new(hash_bytes),
    }
}

#[tokio::test]
async fn test_store_backed_apply_genesis_and_block1() {
    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("test_store");
    let store = std::sync::Arc::new(SledStore::open(&store_path).unwrap());

    let mut bc = Blockchain::new_with_store(store.clone()).unwrap();

    let genesis_header = make_header(0, Hash::default());
    let genesis = Block::new(genesis_header.clone(), vec![]);
    bc.add_block(genesis.clone())
        .await
        .expect("genesis should apply without error");
    assert_eq!(
        bc.get_height(),
        1,
        "blockchain height should be 1 after genesis"
    );

    let block1_header = make_header(1, genesis_header.block_hash);
    let block1 = Block::new(block1_header, vec![]);
    bc.add_block(block1)
        .await
        .expect("block 1 should apply without error");
    assert_eq!(
        bc.get_height(),
        2,
        "blockchain height should be 2 after block 1"
    );

    assert_eq!(
        store.latest_height().unwrap(),
        1,
        "store latest_height should be 1 after two committed blocks"
    );
}

// cbe_token field removed from Blockchain (EPIC-001 Phase 1).
// Tests that verified cbe_token state on the Blockchain struct are no longer applicable.

/// CONS-513 regression (PR following #2683): `Blockchain::get_token_nonce`
/// must read sled FIRST when the BlockExecutor is wired. The pre-fix code
/// read the in-memory HashMap first, but PR #2675 stopped writing to the
/// HashMap in executor mode (sled is canonical), so the HashMap value
/// goes stale as soon as the BlockExecutor increments sled. That stale
/// value made the mempool/consensus pre-check accept a transaction whose
/// nonce the BlockExecutor would reject at commit — halting the live
/// chain at H=123044 on 2026-06-04 ("Invalid nonce: expected 2280, got
/// 2279").
#[tokio::test]
async fn test_get_token_nonce_reads_sled_first_under_executor() {
    use crate::storage::{Address, BlockchainStore, TokenId};

    let temp = tempfile::tempdir().unwrap();
    let store_path = temp.path().join("test_store");
    let store = std::sync::Arc::new(SledStore::open(&store_path).unwrap());

    let mut bc = Blockchain::new_with_store(store.clone()).unwrap();
    assert!(bc.has_executor(), "test setup expects executor wired");

    let token_id = [0xAAu8; 32];
    let sender = [0xBBu8; 32];
    let token = TokenId::new(token_id);
    let addr = Address::new(sender);

    // Sled holds the canonical nonce — write it via a block bracket as
    // production code does (SledStore requires `begin_block` / `commit_block`).
    store.begin_block(0).unwrap();
    store.set_token_nonce(&token, &addr, 2280).unwrap();
    store.commit_block().unwrap();
    assert_eq!(
        store.get_token_nonce(&token, &addr).unwrap(),
        2280,
        "precondition: sled holds 2280"
    );

    // Deliberately seed the in-memory HashMap with the STALE value the bug
    // produced in production. Pre-fix `get_token_nonce` returned this 2279
    // (HashMap-first), causing the mempool to accept a tx with nonce 2279.
    bc.insert_token_nonce_shadow(token_id, sender, 2279);

    // CONS-513: under executor mode, sled wins.
    assert_eq!(
        bc.get_token_nonce(&token_id, &sender),
        2280,
        "CONS-513: get_token_nonce MUST return the sled value (2280) under \
         executor mode, NOT the stale HashMap value (2279). Pre-fix this \
         returned 2279 and halted the chain at H=123044."
    );
}

/// Counter-test: in legacy (store-less) mode the HashMap is still
/// authoritative — sled isn't part of the picture.
#[tokio::test]
async fn test_get_token_nonce_uses_hashmap_in_storeless_mode() {
    let mut bc = Blockchain::new().unwrap();
    assert!(!bc.has_executor(), "storeless Blockchain has no executor");

    let token_id = [0xAAu8; 32];
    let sender = [0xBBu8; 32];

    // Empty HashMap → 0 (no nonce yet).
    assert_eq!(bc.get_token_nonce(&token_id, &sender), 0);

    // Populate HashMap → that value is the answer.
    bc.insert_token_nonce_shadow(token_id, sender, 7);
    assert_eq!(bc.get_token_nonce(&token_id, &sender), 7);
}
