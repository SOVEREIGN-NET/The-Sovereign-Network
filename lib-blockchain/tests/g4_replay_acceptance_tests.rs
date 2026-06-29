//! GENESIS-2 (#2730): g4 replay acceptance gate.
//!
//! Proves wipe-and-replay via `ChainSync::import_blocks` (genesis bootstrap path)
//! matches incremental live state for SOV-native balances and CBE DAO treasury.
//!
//! # CI (always on)
//! `test_genesis_bootstrap_wipe_replay_parity` — synthetic chain with genesis
//! SOV activity + token transfers; export → fresh sled → re-import.
//!
//! # Manual g4 fixture (ignored)
//! `test_g4_checkpoint_replay_acceptance` — replays a bincode block window
//! exported from a live validator and asserts against a JSON balance snapshot.
//!
//! ```bash
//! export G4_REPLAY_BLOCKS_PATH=/path/to/blocks.bin
//! export G4_REPLAY_SNAPSHOT_PATH=/path/to/checkpoint.json
//! cargo test -p lib-blockchain --test g4_replay_acceptance_tests \
//!   test_g4_checkpoint_replay_acceptance -- --ignored --nocapture
//! ```

use std::sync::Arc;

use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::storage::{Address, TokenId};
use lib_blockchain::sync::ChainSync;
use lib_blockchain::transaction::{TokenTransferData, Transaction, TransactionPayload};
use lib_blockchain::types::TransactionType;
use lib_blockchain::Blockchain;
use tempfile::TempDir;

mod common;
use common::block_builders::{block_at_height_with_txs, genesis_block};
use common::crypto_fixtures::dummy_signature;
use common::replay_gate::{
    compare_snapshots, first_n_genesis_sov_wallets, load_blocks_fixture, open_fresh_store,
    ReplayCheckpointSnapshot,
};

fn create_token_transfer_tx(
    from: [u8; 32],
    to: [u8; 32],
    amount: u128,
    nonce: u64,
) -> Transaction {
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
            token_id: [0u8; 32], // executor maps to canonical SOV
            from,
            to,
            amount,
            nonce,
        }),
    }
}

/// Build a short chain: genesis bootstrap + SOV transfers among genesis wallets.
fn build_sov_activity_chain() -> Vec<lib_blockchain::block::Block> {
    let wallets = first_n_genesis_sov_wallets(3);
    let genesis = genesis_block();
    let mut blocks = vec![genesis.clone()];
    let mut prev = genesis.header.block_hash;

    let mut sender_nonce = [0u64; 3];
    for height in 1..=6 {
        let from_idx = (height as usize - 1) % wallets.len();
        let to_idx = height as usize % wallets.len();
        let from = wallets[from_idx];
        let to = wallets[to_idx];
        let nonce = sender_nonce[from_idx];
        sender_nonce[from_idx] += 1;
        let tx = create_token_transfer_tx(from, to, 50, nonce);
        let block = block_at_height_with_txs(height, prev, vec![tx]);
        blocks.push(block.clone());
        prev = block.header.block_hash;
    }

    blocks
}

/// GENESIS-2 CI gate: genesis bootstrap wipe-and-replay parity.
#[test]
fn test_genesis_bootstrap_wipe_replay_parity() {
    let live_dir = TempDir::new().expect("live tempdir");
    let live_store = open_fresh_store(&live_dir);
    let live_sync = ChainSync::new(Arc::clone(&live_store));

    let blocks = build_sov_activity_chain();
    let import = live_sync
        .import_blocks(blocks)
        .expect("live import must not hit Insufficient token balance");
    assert_eq!(import.final_height, Some(6));

    let sample_wallets = first_n_genesis_sov_wallets(3);
    let reference = ReplayCheckpointSnapshot::from_store_at_height(&*live_store, 6, &sample_wallets);

    // CBE treasury must be present after genesis block-0 seed (legacy path until GENESIS-6).
    assert_eq!(
        reference.cbe_treasury_balance, GENESIS_TREASURY_ALLOCATION,
        "CBE DAO treasury must equal 20B atoms after genesis replay seed"
    );
    assert!(
        reference.sov_wallets.iter().all(|w| w.balance > 0),
        "all sampled genesis SOV wallets must be non-zero after live import"
    );

    let exported = live_sync
        .export_all_blocks()
        .expect("export live chain");

    // Wipe sled: fresh store, replay from exported blocks (production import path).
    let replay_dir = TempDir::new().expect("replay tempdir");
    let replay_store = open_fresh_store(&replay_dir);
    let replay_sync = ChainSync::new(Arc::clone(&replay_store));

    let replay = replay_sync
        .import_blocks(exported)
        .expect("wipe-and-replay must not hit Insufficient token balance");
    assert_eq!(replay.final_height, Some(6));

    let replayed = ReplayCheckpointSnapshot::from_store_at_height(&*replay_store, 6, &sample_wallets);

    compare_snapshots("wipe-and-replay", &reference, &replayed).expect(
        "replay checkpoint must match live reference — see token_id/address/have/need above",
    );
}

/// Assert genesis-only bootstrap seeds SOV contract + allocations + CBE treasury.
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

    let cbe_token = TokenId::new(Blockchain::derive_cbe_token_id_pub());
    let treasury = Address::new([0u8; 32]);
    let cbe_bal = store
        .get_token_balance(&cbe_token, &treasury)
        .expect("read CBE treasury");
    assert_eq!(
        cbe_bal, GENESIS_TREASURY_ALLOCATION,
        "CBE DAO treasury after genesis: have={cbe_bal} need={GENESIS_TREASURY_ALLOCATION}"
    );
}

/// Manual g4-class gate: requires fixture paths from a live validator export.
///
/// Export blocks (on a node with sled):
/// ```ignore
/// // Pseudocode — use ChainSync::export_blocks(0, checkpoint) on the node store
/// let blocks = sync.export_blocks(0, 74_010)?;
/// std::fs::write("blocks.bin", bincode::serialize(&blocks)?)?;
/// ```
///
/// Snapshot JSON schema: see `ReplayCheckpointSnapshot` in `common/replay_gate.rs`.
#[test]
#[ignore = "manual g4 fixture — set G4_REPLAY_BLOCKS_PATH and G4_REPLAY_SNAPSHOT_PATH"]
fn test_g4_checkpoint_replay_acceptance() {
    let blocks_path = std::env::var("G4_REPLAY_BLOCKS_PATH")
        .expect("G4_REPLAY_BLOCKS_PATH must point to bincode Vec<Block> fixture");
    let snapshot_path = std::env::var("G4_REPLAY_SNAPSHOT_PATH")
        .expect("G4_REPLAY_SNAPSHOT_PATH must point to ReplayCheckpointSnapshot JSON");

    let reference =
        ReplayCheckpointSnapshot::load_json(snapshot_path.as_ref()).expect("load snapshot");
    assert!(
        reference.checkpoint_height >= 74_010,
        "g4 gate expects checkpoint >= 74010 (got {})",
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

    replay_sync
        .import_blocks(blocks)
        .unwrap_or_else(|e| {
            panic!(
                "g4 replay failed before checkpoint {}: {e} \
                 (look for Insufficient token balance — token/address/have/need in error)",
                reference.checkpoint_height
            );
        });

    assert_eq!(
        replay_store.latest_height().expect("replay height"),
        last,
        "replay must reach fixture tip"
    );

    reference
        .assert_matches_store(&*replay_store, "g4-checkpoint")
        .expect("g4 checkpoint balance parity");
}