//! Integration tests for RewardClaim mempool deduplication and executor rejection.
//!
//! Covers the P0 fix from PR #2844: duplicate same-DID welcome claims must not
//! occupy multiple mempool slots or silently no-op during block application.

use std::sync::Arc;

use lib_blockchain::execution::executor::BlockExecutor;
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::transaction::reward_claim::welcome_claim_key;
use tempfile::tempdir;

mod common;

use common::block_builders;
use common::reward_claim_harness::{mempool_blockchain, seed_executor_store, welcome_claim_tx, RewardClaimActors};

#[test]
fn duplicate_welcome_claim_rejected_from_mempool() {
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain(&actors);

    blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect("first welcome claim should enter mempool");
    assert_eq!(
        blockchain.get_pending_transactions().len(),
        1,
        "exactly one mempool entry after first submit"
    );

    let err = blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect_err("duplicate welcome claim must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("conflicting RewardClaim"),
        "expected mempool conflict rejection, got: {msg}"
    );
    assert_eq!(
        blockchain.get_pending_transactions().len(),
        1,
        "mempool must still hold only the first welcome claim"
    );
}

#[test]
fn executor_rejects_duplicate_welcome_claim_after_first_applied() {
    let actors = RewardClaimActors::generate();
    let temp = tempdir().expect("tempdir");
    let store: Arc<dyn BlockchainStore> = Arc::new(
        SledStore::open(temp.path().join("reward_claim_store")).expect("sled store"),
    );
    let executor = BlockExecutor::with_store(store.clone());

    let genesis = block_builders::genesis_block();
    executor.apply_block(&genesis).expect("apply genesis");

    let setup_block = seed_executor_store(&store, &genesis, &actors);

    let welcome_block = block_builders::block_at_height_with_txs(
        2,
        setup_block.header.block_hash,
        vec![welcome_claim_tx(&actors, 0)],
    );
    executor
        .apply_block(&welcome_block)
        .expect("first welcome claim should commit");
    assert_eq!(store.latest_height().unwrap(), 2);

    let welcome_key = welcome_claim_key(&actors.token_id, &actors.owner_did);
    assert!(
        store
            .get_bubl_reward_welcome(&welcome_key)
            .expect("read welcome marker")
            .is_some(),
        "welcome claim must be recorded on-chain after first apply"
    );

    // Nonce 1 so stateful validation reaches apply_reward_claim (nonce 0 would
    // be soft-dropped as ReplayDropped after the first claim increments treasury nonce).
    let duplicate_block = block_builders::block_at_height_with_txs(
        3,
        welcome_block.header.block_hash,
        vec![welcome_claim_tx(&actors, 1)],
    );
    let err = executor
        .apply_block(&duplicate_block)
        .expect_err("duplicate welcome claim must fail block apply");
    let msg = err.to_string();
    assert!(
        msg.contains("welcome already claimed"),
        "expected hard rejection, not silent no-op; got: {msg}"
    );
    assert_eq!(
        store.latest_height().unwrap(),
        2,
        "failed duplicate must roll back — chain stays at first committed claim"
    );
}