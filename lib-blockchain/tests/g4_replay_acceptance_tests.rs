//! GENESIS-2 (#2730): replay acceptance gates.
//!
//! ## Test map
//!
//! | Test | Guards |
//! |------|--------|
//! | `test_sov_native_wipe_replay_parity` | SOV genesis bootstrap + transfer wipe-replay (#2725/#2741) |
//! | `test_dao_token_creation_wipe_replay_parity` | `TokenCreation` + custom-token transfer (BUBL class) |
//! | `test_paginated_fresh_sync_replay_parity` | Page-2+ paginated sync regression (canonical import on continuation) |
//! | `test_g4_wallet74010_sequence_isolated_replay` | h=74010 forensics — **expected replay failure** until GENESIS-3 |
//! | `test_g4_wallet74010_sequence_tx_version_eight` | Rules out tx-version-8 as divergence cause |
//! | `test_genesis_bootstrap_checkpoint_balances` | Block-0 SOV shell (no bulk allocations) + CBE treasury seed |
//! | `test_g4_checkpoint_replay_acceptance` | Manual ≥74k fixture — full-chain empirical gate (ignored) |
//! | `test_g4_checkpoint_paginated_replay_acceptance` | Manual ≥74k fixture via paginated import (ignored) |
//! | `test_canonical_import_throughput_benchmark_10k` | `#[ignore]` ops floor — blocks/sec on 10k synthetic chain |
//!
//! ## CI scope (honest)
//! - `test_sov_native_wipe_replay_parity` — SOV genesis bootstrap + SOV transfers (#2725/#2741 fix class)
//! - `test_dao_token_creation_wipe_replay_parity` — `TokenCreation` + custom-token transfer (BUBL class)
//!
//! These do **not** replace the manual g4 fixture at ≥74k — they regression-test replay mechanics
//! that g4's failure class depends on. Empirical g4 parity requires `test_g4_checkpoint_replay_acceptance`.
//!
//! **Forensics @ h=74010 (wallet `0e2962d5…`):** current executor replay ends at **4100 SOV**
//! before the canonical **4150 SOV** self-transfer (`test_g4_wallet74010_sequence_isolated_replay`).
//! Live g1 applied that tx (sled nonce=4 at tip). The 50 SOV gap matches the h=73982 self-transfer
//! amount — pre-reset testnet state was built under older write paths; wipe-and-replay with today's
//! sled-canonical executor cannot re-derive it. **GENESIS-3 reset** is the clean gate, not a 74k replay patch.
//!
//! ## Manual g4 fixture
//! ```bash
//! cargo run -p tools --bin export_replay_fixture -- <sled-path> /tmp/g4 --to-height 74010
//! G4_REPLAY_BLOCKS_PATH=/tmp/g4/blocks.v1.bin G4_REPLAY_SNAPSHOT_PATH=/tmp/g4/checkpoint.json \
//!   cargo test -p lib-blockchain --test g4_replay_acceptance_tests \
//!   test_g4_checkpoint_replay_acceptance -- --ignored --nocapture
//! ```

use std::sync::Arc;

use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::storage::{Address, TokenId};

use lib_blockchain::transaction::{
    token_creation::TokenCreationPayloadV1, TokenTransferData, Transaction, TransactionPayload,
    WalletTransactionData,
};
use lib_blockchain::types::Hash;
use lib_blockchain::transaction::DEFAULT_TOKEN_CREATION_FEE;
use lib_blockchain::types::TransactionType;
use lib_blockchain::Blockchain;
use tempfile::TempDir;

mod common;
use common::block_builders::{block_at_height_with_txs, genesis_block};
use common::crypto_fixtures::{dummy_public_key, dummy_signature};
use common::replay_gate::{
    bubl_like_token_id, cbe_treasury_address, compare_snapshots, first_n_genesis_sov_wallets,
    load_blocks_fixture, open_fresh_store, replay_gate_test_wallets, DaoTokenExpectation,
    ReplayCheckpointSnapshot, G4_CHECKPOINT_HEIGHT_FLOOR,
};

use lib_blockchain::sync::ChainSync;

fn create_wallet_registration_tx(wallet_id: [u8; 32], initial_balance: u128) -> Transaction {
    let owner = dummy_public_key();
    Transaction {
        version: 8,
        chain_id: 0x03,
        transaction_type: TransactionType::WalletRegistration,
        inputs: vec![],
        outputs: vec![],
        fee: 0,
        signature: dummy_signature(),
        memo: vec![],
        payload: TransactionPayload::Wallet(WalletTransactionData {
            wallet_id: Hash::new(wallet_id),
            owner_identity_id: None,
            alias: None,
            wallet_name: "g4-repro".to_string(),
            wallet_type: "Primary".to_string(),
            public_key: owner.dilithium_pk.to_vec(),
            capabilities: 0,
            created_at: 0,
            registration_fee: 0,
            initial_balance,
            seed_commitment: Hash::zero(),
        }),
    }
}

fn create_sov_transfer_tx(from: [u8; 32], to: [u8; 32], amount: u128, nonce: u64) -> Transaction {
    create_sov_transfer_tx_version(from, to, amount, nonce, 8u32)
}

fn create_sov_transfer_tx_version(
    from: [u8; 32],
    to: [u8; 32],
    amount: u128,
    nonce: u64,
    version: u32,
) -> Transaction {
    Transaction {
        version,
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
    // h=1 wallet registrations + 6 transfer blocks (tip @ 7).
    build_sov_activity_chain_to_height(7)
}

/// Longer chain so paginated import (50 blocks/page, as in `try_initial_sync_from_peer`)
/// spans multiple pages and exercises the continuation import path.
fn build_sov_activity_chain_to_height(tip_height: u64) -> Vec<lib_blockchain::block::Block> {
    use common::replay_gate::{replay_gate_test_wallets, REPLAY_GATE_WALLET_MINT_ATOMS};

    let wallets = replay_gate_test_wallets(3);
    let genesis = genesis_block();
    let mut blocks = vec![genesis.clone()];
    let mut prev = genesis.header.block_hash;

    let reg_txs: Vec<_> = wallets
        .iter()
        .map(|w| create_wallet_registration_tx(*w, REPLAY_GATE_WALLET_MINT_ATOMS))
        .collect();
    let reg_block = block_at_height_with_txs(1, prev, reg_txs);
    blocks.push(reg_block.clone());
    prev = reg_block.header.block_hash;

    let mut sender_nonce = [0u64; 3];
    for height in 2..=tip_height {
        let from_idx = (height as usize - 2) % wallets.len();
        let to_idx = (height as usize - 1) % wallets.len();
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
    use common::replay_gate::{replay_gate_test_wallets, REPLAY_GATE_WALLET_MINT_ATOMS};

    let wallets = replay_gate_test_wallets(3);
    let creator = wallets[0];
    let treasury = wallets[1];
    let recipient = wallets[2];
    let token_id = bubl_like_token_id();

    let genesis = genesis_block();
    let block1 = block_at_height_with_txs(
        1,
        genesis.header.block_hash,
        wallets
            .iter()
            .map(|w| create_wallet_registration_tx(*w, REPLAY_GATE_WALLET_MINT_ATOMS))
            .collect(),
    );
    let block2 = block_at_height_with_txs(
        2,
        block1.header.block_hash,
        vec![create_token_creation_tx(creator, treasury)],
    );
    // Creator holds 80% (800_000); transfer 10_000 to recipient.
    let block3 = block_at_height_with_txs(
        3,
        block2.header.block_hash,
        vec![create_dao_token_transfer_tx(token_id, creator, recipient, 10_000, 0)],
    );

    let expect = DaoTokenExpectation {
        token_id,
        symbol: "BUBL".to_string(),
        holder_wallet_id: recipient,
    };

    (vec![genesis, block1, block2, block3], expect)
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

/// Isolated repro of g4 wallet `0e2962d5…` activity through the failing h=74010 tx.
/// Pins current executor semantics without replaying 74k prefix blocks.
///
/// **This test PASSES because replay diverges from live chain history at h=74010.**
/// The `import_blocks(vec![h4]).expect_err(...)` failure **is** the acceptance criterion
/// until GENESIS-3 reset ([#2731](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/2731)).
/// Do **not** "fix" this to make h4 succeed unless the reset is complete **or** you are
/// intentionally reintroducing the pre-#2641 write-path bug that double-credited the
/// h=73982 self-transfer on live validators.
#[test]
fn test_g4_wallet74010_sequence_isolated_replay() {
    const ATOMS: u128 = 1_000_000_000_000_000_000;
    let wallet: [u8; 32] =
        hex::decode("0e2962d527220810ffe8c78ae3290fdf37b25f9bbba1c9a69eac612193db78ab")
            .expect("wallet hex")
            .try_into()
            .expect("wallet len");
    let recipient: [u8; 32] =
        hex::decode("7beb2195d122ffa72b4cb124125c30eb540a19a36b69a143ff2b25c2bd32f3b7")
            .expect("recipient hex")
            .try_into()
            .expect("recipient len");

    let genesis = genesis_block();
    let mut prev = genesis.header.block_hash;
    let h1 = block_at_height_with_txs(
        1,
        prev,
        vec![create_wallet_registration_tx(wallet, 5000 * ATOMS)],
    );
    prev = h1.header.block_hash;
    let h2 = block_at_height_with_txs(
        2,
        prev,
        vec![create_sov_transfer_tx(wallet, wallet, 50 * ATOMS, 0)],
    );
    prev = h2.header.block_hash;
    let h3 = block_at_height_with_txs(
        3,
        prev,
        vec![create_sov_transfer_tx(wallet, recipient, 900 * ATOMS, 1)],
    );
    prev = h3.header.block_hash;
    let h4 = block_at_height_with_txs(
        4,
        prev,
        vec![create_sov_transfer_tx(wallet, wallet, 4150 * ATOMS, 2)],
    );

    let dir = TempDir::new().expect("tempdir");
    let store = open_fresh_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    sync.import_blocks(vec![genesis, h1, h2, h3])
        .expect("import through outbound transfer");

    let sov = TokenId::new(generate_lib_token_id());
    let bal = store
        .get_token_balance(&sov, &Address::new(wallet))
        .expect("read balance");
    assert_eq!(
        bal, 4100 * ATOMS,
        "after 5000 mint, zero-net 50 self-transfer, 900 outbound: have {bal}"
    );
    let nonce = store
        .get_token_nonce(&sov, &Address::new(wallet))
        .expect("read nonce");
    assert_eq!(nonce, 2, "outbound transfer must advance nonce to 2 before final leg");

    let err = sync
        .import_blocks(vec![h4])
        .expect_err("4150 self-transfer must fail — 50 SOV short of g4 canonical block");
    let msg = format!("{err}");
    assert!(
        msg.contains("Insufficient token balance") || msg.contains("InsufficientBalance"),
        "expected balance error, got: {msg}"
    );
}

/// Fixture uses tx version 8 — confirm version is not the replay/live divergence.
#[test]
fn test_g4_wallet74010_sequence_tx_version_eight() {
    const ATOMS: u128 = 1_000_000_000_000_000_000;
    let wallet: [u8; 32] =
        hex::decode("0e2962d527220810ffe8c78ae3290fdf37b25f9bbba1c9a69eac612193db78ab")
            .expect("wallet hex")
            .try_into()
            .expect("wallet len");
    let recipient: [u8; 32] =
        hex::decode("7beb2195d122ffa72b4cb124125c30eb540a19a36b69a143ff2b25c2bd32f3b7")
            .expect("recipient hex")
            .try_into()
            .expect("recipient len");

    let genesis = genesis_block();
    let mut prev = genesis.header.block_hash;
    let h1 = block_at_height_with_txs(
        1,
        prev,
        vec![create_wallet_registration_tx(wallet, 5000 * ATOMS)],
    );
    prev = h1.header.block_hash;
    let h2 = block_at_height_with_txs(
        2,
        prev,
        vec![create_sov_transfer_tx_version(wallet, wallet, 50 * ATOMS, 0, 8u32)],
    );
    prev = h2.header.block_hash;
    let h3 = block_at_height_with_txs(
        3,
        prev,
        vec![create_sov_transfer_tx_version(wallet, recipient, 900 * ATOMS, 1, 8u32)],
    );
    prev = h3.header.block_hash;
    let h4 = block_at_height_with_txs(
        4,
        prev,
        vec![create_sov_transfer_tx_version(wallet, wallet, 4150 * ATOMS, 2, 8u32)],
    );

    let dir = TempDir::new().expect("tempdir");
    let store = open_fresh_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));
    sync.import_blocks(vec![genesis, h1, h2, h3])
        .expect("import through outbound transfer");
    let sov = TokenId::new(generate_lib_token_id());
    let bal = store
        .get_token_balance(&sov, &Address::new(wallet))
        .expect("balance");
    assert_eq!(bal, 4100 * ATOMS);
    assert!(sync.import_blocks(vec![h4]).is_err());
}

/// SOV-native genesis bootstrap + SOV transfer replay parity (#2725 / #2741 fix class).
#[test]
fn test_sov_native_wipe_replay_parity() {
    let sample = first_n_genesis_sov_wallets(3);
    run_wipe_replay_parity(build_sov_activity_chain(), 7, &sample, &[]);
}

/// Floor estimate for ops: canonical-import throughput on a synthetic 10k SOV chain.
///
/// Run manually before estimating wipe-and-catch-up wall-clock:
/// `cargo test -p lib-blockchain --test g4_replay_acceptance_tests \
///   test_canonical_import_throughput_benchmark_10k -- --ignored --nocapture`
#[test]
#[ignore = "benchmark — run manually for canonical import throughput floor estimate"]
fn test_canonical_import_throughput_benchmark_10k() {
    const HEIGHT: u64 = 10_001;
    let blocks = build_sov_activity_chain_to_height(HEIGHT);

    let dir = TempDir::new().expect("tempdir");
    let store = open_fresh_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    let start = std::time::Instant::now();
    sync.import_blocks(blocks).expect("10k canonical import");
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64();
    let blocks_per_sec = HEIGHT as f64 / secs;

    eprintln!(
        "canonical import throughput: {HEIGHT} blocks in {secs:.1}s ({blocks_per_sec:.1} blocks/sec)"
    );
    eprintln!(
        "ops estimate: 177k blocks at {blocks_per_sec:.0}/s ≈ {:.0} min",
        177_000.0 / blocks_per_sec / 60.0
    );
}

/// Paginated fresh sync must match single-shot wipe-and-replay (g4 page-2+ bug class).
#[test]
fn test_paginated_fresh_sync_replay_parity() {
    const CHECKPOINT: u64 = 61;
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
    run_wipe_replay_parity(blocks, 3, &sample, &[dao_expect]);

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

/// Genesis block-0 only: SOV shell (no bulk allocations), legacy CBE treasury seed.
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
    assert!(
        entries.is_empty(),
        "GENESIS-3 genesis must not carry bulk sov_balances (have {})",
        entries.len()
    );

    let sample = replay_gate_test_wallets(1);
    let have = store
        .get_token_balance(&sov_token, &Address::new(sample[0]))
        .expect("read SOV balance");
    assert_eq!(have, 0, "no genesis SOV rows — balances enter via block txs");

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