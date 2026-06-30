//! GENESIS-2 (#2730): replay acceptance gates.
//!
//! ## CI scope (honest)
//! - `test_sov_native_wipe_replay_parity` — SOV genesis bootstrap + SOV transfers (#2725/#2741 fix class)
//! - `test_dao_token_creation_wipe_replay_parity` — `TokenCreation` + custom-token transfer (BUBL class)
//!
//! These do **not** replace the manual g4 fixture at ≥74k — they regression-test replay mechanics
//! that g4's failure class depends on. Empirical g4 parity requires `test_g4_checkpoint_replay_acceptance`.
//!
//! ## Manual g4 fixture
//! ```bash
//! cargo run -p tools --bin export_replay_fixture -- /opt/zhtp/data/testnet/sled /tmp/g4 --to-height 74010
//! G4_REPLAY_BLOCKS_PATH=/tmp/g4/blocks.v1.bin G4_REPLAY_SNAPSHOT_PATH=/tmp/g4/checkpoint.json \
//!   cargo test -p lib-blockchain --test g4_replay_acceptance_tests \
//!   test_g4_checkpoint_replay_acceptance -- --ignored --nocapture
//! ```

use std::sync::Arc;

use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::storage::{Address, TokenId};
use lib_blockchain::sync::G4_CHECKPOINT_HEIGHT_FLOOR;
use lib_blockchain::transaction::{
    token_creation::TokenCreationPayloadV1, TokenTransferData, Transaction, TransactionPayload,
};
use lib_blockchain::transaction::DEFAULT_TOKEN_CREATION_FEE;
use lib_blockchain::types::TransactionType;
use lib_blockchain::Blockchain;
use tempfile::TempDir;

mod common;
use common::block_builders::{block_at_height_with_txs, genesis_block};
use common::crypto_fixtures::dummy_signature;
use common::replay_gate::{
    bubl_like_token_id, cbe_treasury_address, compare_snapshots, first_n_genesis_sov_wallets,
    load_blocks_fixture, open_fresh_store, DaoTokenExpectation, ReplayCheckpointSnapshot,
};

use lib_blockchain::sync::ChainSync;

fn create_sov_transfer_tx(from: [u8; 32], to: [u8; 32], amount: u128, nonce: u64) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: dummy_signature(),
        memo: vec![],
        payload: TransactionPayload::TokenTransfer(TokenTransferData {
            token_id: [0u8; 32],
            from,
            to,
            amount,
            nonce,
        }),
    }
}

fn create_token_creation_tx(
    creator_key_id: [u8; 32],
    treasury_recipient: [u8; 32],
) -> Transaction {
    let payload = TokenCreationPayloadV1 {
        name: "Bubble".to_string(),
        symbol: "BUBL".to_string(),
        initial_supply: 1_000_000,
        decimals: 8,
        treasury_allocation_bps: 2_000,
        treasury_recipient,
    };
    let mut sig = dummy_signature();
    sig.public_key.key_id = creator_key_id;
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenCreation,
        inputs: vec![],
        outputs: vec![],
        fee: 0, // subsidised — avoids coupling to SOV fee debit in this gate
        signature: sig,
        memo: payload.encode_memo().expect("token creation memo"),
        payload: TransactionPayload::None,
    }
}

fn create_dao_token_transfer_tx(
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u128,
    nonce: u64,
) -> Transaction {
    let mut sig = dummy_signature();
    sig.public_key.key_id = from;
    Transaction {
        version: 2,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: sig,
        memo: vec![],
        payload: TransactionPayload::TokenTransfer(TokenTransferData {
            token_id,
            from,
            to,
            amount,
            nonce,
        }),
    }
}

fn build_sov_activity_chain() -> Vec<lib_blockchain::block::Block> {
    build_sov_activity_chain_to_height(6)
}

/// Longer chain so paginated import (50 blocks/page, as in `try_initial_sync_from_peer`)
/// spans multiple pages and exercises the continuation import path.
fn build_sov_activity_chain_to_height(last_height: u64) -> Vec<lib_blockchain::block::Block> {
    let wallets = first_n_genesis_sov_wallets(3);
    let genesis = genesis_block();
    let mut blocks = vec![genesis.clone()];
    let mut prev = genesis.header.block_hash;
    let mut sender_nonce = [0u64; 3];

    for height in 1..=last_height {
        let from_idx = (height as usize - 1) % wallets.len();
        let to_idx = height as usize % wallets.len();
        let nonce = sender_nonce[from_idx];
        sender_nonce[from_idx] += 1;
        let tx = create_sov_transfer_tx(wallets[from_idx], wallets[to_idx], 50, nonce);
        let block = block_at_height_with_txs(height, prev, vec![tx]);
        blocks.push(block.clone());
        prev = block.header.block_hash;
    }
    blocks
}

/// Mirrors production `BLOCKS_PER_PAGE` in `zhtp::runtime::try_initial_sync_from_peer`.
const INITIAL_SYNC_PAGE_SIZE: usize = 50;

fn import_blocks_paginated(sync: &ChainSync, blocks: Vec<lib_blockchain::block::Block>) {
    for chunk in blocks.chunks(INITIAL_SYNC_PAGE_SIZE) {
        sync.import_blocks(chunk.to_vec())
            .expect("paginated import must not hit Insufficient token balance");
    }
}

fn build_dao_token_activity_chain() -> (Vec<lib_blockchain::block::Block>, DaoTokenExpectation) {
    let wallets = first_n_genesis_sov_wallets(3);
    let creator = wallets[0];
    let treasury = wallets[1];
    let recipient = wallets[2];
    let token_id = bubl_like_token_id();

    let genesis = genesis_block();
    let block1 = block_at_height_with_txs(
        1,
        genesis.header.block_hash,
        vec![create_token_creation_tx(creator, treasury)],
    );
    // Creator holds 80% (800_000); transfer 10_000 to recipient.
    let block2 = block_at_height_with_txs(
        2,
        block1.header.block_hash,
        vec![create_dao_token_transfer_tx(token_id, creator, recipient, 10_000, 0)],
    );

    let expect = DaoTokenExpectation {
        token_id,
        symbol: "BUBL".to_string(),
        holder_wallet_id: recipient,
    };

    (vec![genesis, block1, block2], expect)
}

fn run_wipe_replay_parity(
    blocks: Vec<lib_blockchain::block::Block>,
    checkpoint_height: u64,
    sample_wallets: &[[u8; 32]],
    dao_expectations: &[DaoTokenExpectation],
) {
    let live_dir = TempDir::new().expect("live tempdir");
    let live_store = open_fresh_store(&live_dir);
    let live_sync = ChainSync::new(Arc::clone(&live_store));

    live_sync
        .import_blocks(blocks)
        .expect("live import must not hit Insufficient token balance");
    assert_eq!(
        live_store.latest_height().expect("live height"),
        checkpoint_height
    );

    let reference =
        ReplayCheckpointSnapshot::from_store_at_height(
            &*live_store,
            checkpoint_height,
            sample_wallets,
            dao_expectations,
        );

    let exported = live_sync.export_all_blocks().expect("export");

    let replay_dir = TempDir::new().expect("replay tempdir");
    let replay_store = open_fresh_store(&replay_dir);
    let replay_sync = ChainSync::new(Arc::clone(&replay_store));

    replay_sync
        .import_blocks(exported)
        .expect("wipe-and-replay must not hit Insufficient token balance");

    let replayed = ReplayCheckpointSnapshot::from_store_at_height(
        &*replay_store,
        checkpoint_height,
        sample_wallets,
        dao_expectations,
    );

    compare_snapshots("wipe-and-replay", &reference, &replayed).expect(
        "replay checkpoint must match live reference — see token_id/address/have/need above",
    );
}

/// SOV-native genesis bootstrap + SOV transfer replay parity (#2725 / #2741 fix class).
#[test]
fn test_sov_native_wipe_replay_parity() {
    let sample = first_n_genesis_sov_wallets(3);
    run_wipe_replay_parity(build_sov_activity_chain(), 6, &sample, &[]);
}

/// Paginated fresh sync must match single-shot wipe-and-replay (g4 page-2+ bug class).
#[test]
fn test_paginated_fresh_sync_replay_parity() {
    const CHECKPOINT: u64 = 60;
    let sample = first_n_genesis_sov_wallets(3);
    let blocks = build_sov_activity_chain_to_height(CHECKPOINT);

    let live_dir = TempDir::new().expect("live tempdir");
    let live_store = open_fresh_store(&live_dir);
    let live_sync = ChainSync::new(Arc::clone(&live_store));
    live_sync
        .import_blocks(blocks.clone())
        .expect("live single-shot import");

    let reference = ReplayCheckpointSnapshot::from_store_at_height(
        &*live_store,
        CHECKPOINT,
        &sample,
        &[],
    );

    let replay_dir = TempDir::new().expect("replay tempdir");
    let replay_store = open_fresh_store(&replay_dir);
    let replay_sync = ChainSync::new(Arc::clone(&replay_store));
    import_blocks_paginated(&replay_sync, blocks);

    assert_eq!(
        replay_store.latest_height().expect("paginated replay height"),
        CHECKPOINT
    );

    let replayed = ReplayCheckpointSnapshot::from_store_at_height(
        &*replay_store,
        CHECKPOINT,
        &sample,
        &[],
    );
    compare_snapshots("paginated-fresh-sync", &reference, &replayed).expect(
        "paginated import must match single-shot live reference",
    );
}

/// DAO `TokenCreation` + custom-token transfer replay parity (BUBL class — g4-adjacent).
#[test]
fn test_dao_token_creation_wipe_replay_parity() {
    let sample = first_n_genesis_sov_wallets(3);
    let (blocks, dao_expect) = build_dao_token_activity_chain();
    run_wipe_replay_parity(blocks, 2, &sample, &[dao_expect]);

    // Post-creation recipient must hold transferred BUBL atoms.
    let live_dir = TempDir::new().unwrap();
    let store = open_fresh_store(&live_dir);
    let sync = ChainSync::new(Arc::clone(&store));
    let (blocks, dao_expect) = build_dao_token_activity_chain();
    sync.import_blocks(blocks).unwrap();
    let token = TokenId::new(dao_expect.token_id);
    let bal = store
        .get_token_balance(
            &token,
            &Address::new(dao_expect.holder_wallet_id),
        )
        .unwrap();
    assert_eq!(bal, 10_000, "BUBL recipient balance after TokenCreation + transfer");
}

/// Genesis block-0 only: SOV shell, allocations, legacy CBE treasury seed.
#[test]
fn test_genesis_bootstrap_checkpoint_balances() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_fresh_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    sync.import_blocks(vec![genesis_block()])
        .expect("genesis import");

    let sov_token = TokenId::new(generate_lib_token_id());
    let contract = store
        .get_token_contract(&sov_token)
        .expect("read SOV contract")
        .expect("SOV native contract must exist after genesis bootstrap");
    assert_eq!(contract.symbol, "SOV");

    let cfg = GenesisConfig::from_embedded().expect("embedded genesis");
    let entries = cfg.sov_allocation_entries().expect("sov entries");
    assert!(entries.len() >= 3);

    for (wallet_id, expected) in entries.iter().take(3) {
        let have = store
            .get_token_balance(&sov_token, &Address::new(*wallet_id))
            .expect("read SOV balance");
        assert_eq!(
            have, *expected,
            "SOV genesis wallet {} balance mismatch after bootstrap: have={have} need={expected}",
            hex::encode(wallet_id)
        );
    }

    // TODO(GENESIS-6, #2734): rewrite when CBE founding tx replaces block-0 seed.
    let cbe_token = TokenId::new(Blockchain::derive_cbe_token_id_pub());
    let treasury = cbe_treasury_address();
    let cbe_bal = store
        .get_token_balance(&cbe_token, &treasury)
        .expect("read CBE treasury");
    assert_eq!(
        cbe_bal, GENESIS_TREASURY_ALLOCATION,
        "CBE DAO treasury after genesis: have={cbe_bal} need={GENESIS_TREASURY_ALLOCATION}"
    );

    // TokenCreation fee constant wired (sanity — not exercised when fee=0).
    let _ = DEFAULT_TOKEN_CREATION_FEE;
}

/// Manual g4 gate — export via `tools/export_replay_fixture`, replay here.
#[test]
#[ignore = "manual g4 fixture — export with tools/export_replay_fixture, set G4_REPLAY_* env vars"]
fn test_g4_checkpoint_replay_acceptance() {
    let blocks_path = std::env::var("G4_REPLAY_BLOCKS_PATH")
        .expect("G4_REPLAY_BLOCKS_PATH must point to blocks.v1.bin fixture");
    let snapshot_path = std::env::var("G4_REPLAY_SNAPSHOT_PATH")
        .expect("G4_REPLAY_SNAPSHOT_PATH must point to checkpoint.json");

    let reference =
        ReplayCheckpointSnapshot::load_json(snapshot_path.as_ref()).expect("load snapshot");
    assert!(
        reference.checkpoint_height >= G4_CHECKPOINT_HEIGHT_FLOOR,
        "g4 gate expects checkpoint >= {G4_CHECKPOINT_HEIGHT_FLOOR} (got {})",
        reference.checkpoint_height
    );

    let blocks = load_blocks_fixture(blocks_path.as_ref()).expect("load block fixture");
    assert!(
        !blocks.is_empty() && blocks[0].header.height == 0,
        "fixture must start at genesis (height 0)"
    );
    let last = blocks.last().expect("non-empty fixture").header.height;
    assert!(
        last >= reference.checkpoint_height,
        "fixture must cover checkpoint height {} (last block {last})",
        reference.checkpoint_height
    );

    let replay_dir = TempDir::new().expect("replay tempdir");
    let replay_store = open_fresh_store(&replay_dir);
    let replay_sync = ChainSync::new(Arc::clone(&replay_store));

    replay_sync.import_blocks(blocks).unwrap_or_else(|e| {
        panic!(
            "g4 replay failed before checkpoint {}: {e} \
             (look for Insufficient token balance — token/address/have/need in error)",
            reference.checkpoint_height
        );
    });

    reference
        .assert_matches_store(&*replay_store, "g4-checkpoint")
        .expect("g4 checkpoint balance parity");
}

/// Manual g4 gate via paginated import (production `try_initial_sync_from_peer` path).
#[test]
#[ignore = "manual g4 paginated fixture — same env vars as test_g4_checkpoint_replay_acceptance"]
fn test_g4_checkpoint_paginated_replay_acceptance() {
    let blocks_path = std::env::var("G4_REPLAY_BLOCKS_PATH")
        .expect("G4_REPLAY_BLOCKS_PATH must point to blocks.v1.bin fixture");
    let snapshot_path = std::env::var("G4_REPLAY_SNAPSHOT_PATH")
        .expect("G4_REPLAY_SNAPSHOT_PATH must point to checkpoint.json");

    let reference =
        ReplayCheckpointSnapshot::load_json(snapshot_path.as_ref()).expect("load snapshot");
    let blocks = load_blocks_fixture(blocks_path.as_ref()).expect("load block fixture");

    let replay_dir = TempDir::new().expect("replay tempdir");
    let replay_store = open_fresh_store(&replay_dir);
    let replay_sync = ChainSync::new(Arc::clone(&replay_store));

    import_blocks_paginated(&replay_sync, blocks);

    reference
        .assert_matches_store(&*replay_store, "g4-checkpoint-paginated")
        .expect("paginated g4 checkpoint balance parity");
}