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
    mempool_blockchain, mempool_blockchain_rewards_module_without_token_contract,
    mempool_blockchain_shadow_phantom_beneficiary, mempool_blockchain_unregistered_beneficiary,
    mempool_blockchain_unregistered_treasury, seed_executor_store, welcome_claim_tx,
    welcome_claim_tx_from, RewardClaimActors,
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
fn non_delegate_signer_rejected_from_mempool() {
    // Without a mempool spend-delegate gate, any key with from==signer and a
    // registered owner_did would admit and then halt apply (non-delegate Err).
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain(&actors);
    let impostor = lib_crypto::KeyPair::generate().expect("impostor keypair");

    let err = blockchain
        .add_pending_transaction(welcome_claim_tx_from(&actors, 0, &impostor))
        .expect_err("non-delegate RewardClaim must be rejected at mempool");
    let msg = err.to_string();
    assert!(
        msg.contains("verification failed") || msg.contains("Unauthorized"),
        "expected mempool unauthorized rejection, got: {msg}"
    );
    assert!(
        blockchain.get_pending_transactions().is_empty(),
        "non-delegate claim must not enter mempool"
    );
}

#[test]
fn recipient_key_id_mismatch_rejected_from_mempool() {
    // Apply rejects recipient_key_id != key_id_from_did(owner_did). Must not
    // admit at mempool (halt vector #2924 review).
    use lib_blockchain::transaction::reward_claim::{
        expected_amount_for_event, RewardClaimData, RewardEventKind, REWARD_CLAIM_MEMO,
    };
    use lib_blockchain::transaction::signing::sign_transaction;
    use lib_blockchain::transaction::Transaction;
    use lib_crypto::SignatureAlgorithm;

    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain(&actors);
    let data = RewardClaimData {
        event: RewardEventKind::Welcome,
        owner_did: actors.owner_did.clone(),
        recipient_key_id: [0xABu8; 32], // deliberately not key_id of owner_did
        token_id: actors.token_id,
        from: actors.treasury.public_key.key_id,
        amount: expected_amount_for_event(RewardEventKind::Welcome, 1),
        nonce: 0,
        peer_did: None,
    };
    let mut tx = Transaction::new_reward_claim_with_chain_id(
        0x03,
        data,
        lib_crypto::Signature {
            signature: Vec::new(),
            public_key: actors.treasury.public_key.clone(),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        REWARD_CLAIM_MEMO.to_vec(),
    );
    sign_transaction(&mut tx, &actors.treasury.private_key).expect("sign");

    let err = blockchain
        .add_pending_transaction(tx)
        .expect_err("mismatched recipient_key_id must not enter mempool");
    let msg = err.to_string();
    assert!(
        msg.contains("verification failed") || msg.contains("Invalid"),
        "expected mempool rejection for recipient_key_id binding, got: {msg}"
    );
    assert!(blockchain.get_pending_transactions().is_empty());
}

#[test]
fn rewards_module_without_token_contract_rejected_from_mempool() {
    // GENESIS-3 H=1920 halt: pure AssetLaunch writes rewards_module_state but
    // no token_contracts row. Old mempool order checked rewards_module first and
    // admitted the claim; apply then failed and halted consensus after BFT.
    let actors = RewardClaimActors::generate();
    let mut blockchain = mempool_blockchain_rewards_module_without_token_contract(&actors);

    assert!(
        blockchain.get_rewards_module_state(&actors.token_id).is_some(),
        "fixture must expose rewards module (AssetLaunch path)"
    );
    assert!(
        blockchain.get_token_contract(&actors.token_id).is_none(),
        "fixture must omit token_contracts row"
    );

    let err = blockchain
        .add_pending_transaction(welcome_claim_tx(&actors, 0))
        .expect_err("RewardClaim without token contract must not enter mempool");
    let msg = err.to_string();
    assert!(
        msg.contains("verification failed") || msg.contains("Invalid"),
        "expected mempool rejection for missing token contract, got: {msg}"
    );
    assert!(
        blockchain.get_pending_transactions().is_empty(),
        "unapplyable RewardClaim must not enter mempool"
    );
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
fn executor_soft_drops_duplicate_welcome_claim_after_first_applied() {
    // #2924 review / #2908 option b: stateful eligibility fails at apply must
    // soft-drop the tx (block stays valid), not halt consensus.
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

    // Nonce 1 so we reach eligibility (nonce 0 would soft-drop as ReplayDropped).
    let duplicate_block = block_builders::block_at_height_with_txs(
        3,
        welcome_block.header.block_hash,
        vec![welcome_claim_tx(&actors, 1)],
    );
    executor
        .apply_block(&duplicate_block)
        .expect("duplicate welcome must soft-drop — block remains valid");
    assert_eq!(
        store.latest_height().unwrap(),
        3,
        "soft-dropped claim still advances height (tx in block, no state write)"
    );
    // Welcome marker set once; soft-drop must not re-write / double-pay.
    assert!(
        store
            .get_bubl_reward_welcome(&welcome_key)
            .expect("read welcome marker")
            .is_some(),
        "welcome marker must still be present after soft-dropped duplicate"
    );
}