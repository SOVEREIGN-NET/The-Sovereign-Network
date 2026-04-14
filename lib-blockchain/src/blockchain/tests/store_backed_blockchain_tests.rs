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
