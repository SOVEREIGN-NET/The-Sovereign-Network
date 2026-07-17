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
use common::reward_claim_harness::{
    mempool_blockchain, mempool_blockchain_shadow_phantom_beneficiary,
    mempool_blockchain_unregistered_beneficiary, mempool_blockchain_unregistered_treasury,
    seed_executor_store, welcome_claim_tx, RewardClaimActors,
};

#[test]
fn registered_owner_did_accepted_into_mempool() {
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain(&actors);

    blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect("registered owner_did claim should enter mempool");
    assert_eq!(blockchain.get_pending_transactions().len(), 1);
}

#[test]
fn unregistered_treasury_signer_accepted_into_mempool() {
    // Spend-delegate is a node keystore, not a registered user identity.
    // Production claims failed with UnregisteredSender after restarts when
    // validate_sender_identity_exists scanned only in-memory wallets/identities.
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain_unregistered_treasury(&actors);

    blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect("RewardClaim must not require treasury identity registration");
    assert_eq!(blockchain.get_pending_transactions().len(), 1);
}

#[test]
fn shadow_only_owner_did_rejected_from_mempool() {
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain_shadow_phantom_beneficiary(&actors);

    assert!(
        blockchain.identity_exists(&actors.owner_did),
        "phantom DID must be visible to identity_exists (shadow)"
    );
    assert!(
        !blockchain
            .owner_identity_registered_in_store(&actors.owner_did)
            .expect("store attached"),
        "phantom DID must be absent from sled"
    );

    let err = blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect_err("shadow-only owner_did must not pass sled gate");
    let msg = err.to_string();
    assert!(
        msg.contains("verification failed"),
        "expected mempool rejection, got: {msg}"
    );
    assert!(blockchain.get_pending_transactions().is_empty());
}

#[test]
fn unregistered_owner_did_rejected_from_mempool() {
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain_unregistered_beneficiary(&actors);

    let err = blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect_err("RewardClaim for unregistered owner_did must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("verification failed"),
        "expected mempool validation rejection, got: {msg}"
    );
    assert!(
        blockchain.get_pending_transactions().is_empty(),
        "unregistered owner_did claim must not enter mempool"
    );
}

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
    // Same bytes → identical hash ("duplicate already pending"); re-signed
    // payload with same claim keys → pending_reward_claim_conflicts.
    assert!(
        msg.contains("conflicting RewardClaim") || msg.contains("duplicate already pending"),
        "expected mempool conflict/duplicate rejection, got: {msg}"
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