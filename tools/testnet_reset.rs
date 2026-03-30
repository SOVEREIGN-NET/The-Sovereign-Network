/// Testnet Reset Tool
///
/// Extracts all identities and wallets from an existing sled store and
/// creates a brand-new sled with a minimal chain:
///   Block 0: genesis (empty)
///   Block 1: all IdentityRegistration + WalletRegistration txns
///   Block 2: TokenMint for each PRIMARY wallet at 5,000 SOV
///
/// Usage:
///   testnet_reset <source_sled_path> <output_sled_path>
///
/// Example:
///   testnet_reset /opt/zhtp/data/testnet/sled /opt/zhtp/data/testnet/sled-reset

use anyhow::Result;
use lib_blockchain::{
    block::{Block, BlockBuilder, create_genesis_block},
    contracts::utils::generate_lib_token_id,
    storage::{BlockchainStore, SledStore},
    transaction::{
        Transaction, TokenMintData,
        core::{IdentityTransactionData, WalletTransactionData},
    },
    types::{Difficulty, Hash},
};
use lib_crypto::types::{PublicKey, Signature, SignatureAlgorithm};
use std::path::PathBuf;
use std::sync::Arc;

const SOV_PER_WALLET: u128 = 500_000_000_000; // 5,000 SOV × 10^8

fn system_signature() -> Signature {
    Signature {
        signature: vec![0xAA; 64],
        public_key: PublicKey {
            dilithium_pk: vec![0u8; 1312],
            kyber_pk: vec![],
            key_id: [0u8; 32],
        },
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: 0,
    }
}

fn write_block(store: &Arc<dyn BlockchainStore>, block: Block) -> Result<()> {
    let height = block.header.height;
    store.begin_block(height)?;
    store.append_block(&block)?;
    store.commit_block()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: testnet_reset <source_sled> <output_sled>");
        std::process::exit(1);
    }

    let source_path = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);

    if output_path.exists() {
        eprintln!("ERROR: Output path already exists: {}", output_path.display());
        eprintln!("Remove it first to avoid overwriting.");
        std::process::exit(1);
    }

    println!("=== TESTNET RESET TOOL ===");
    println!("Source: {}", source_path.display());
    println!("Output: {}", output_path.display());
    println!();

    // ── 1. Open source sled and load blockchain state ─────────────────────
    println!("Loading source sled...");
    let source_store: Arc<dyn BlockchainStore> =
        Arc::new(SledStore::open(source_path.clone())?);

    let source_height = source_store
        .latest_height()
        .map_err(|e| anyhow::anyhow!("Source sled empty: {}", e))?;
    println!("  Source chain height: {}", source_height);

    println!("Replaying blockchain state from source (this may take a minute)...");
    let bc = lib_blockchain::Blockchain::load_from_store(source_store)?
        .ok_or_else(|| anyhow::anyhow!("No committed blocks in source sled"))?;

    let identities: Vec<IdentityTransactionData> =
        bc.identity_registry.values().cloned().collect();
    let wallets: Vec<WalletTransactionData> =
        bc.wallet_registry.values().cloned().collect();

    println!("  Identities extracted:  {}", identities.len());
    println!("  Wallets extracted:     {}", wallets.len());
    println!();

    // ── 2. Create output sled ─────────────────────────────────────────────
    println!("Creating fresh output sled...");
    let out_store: Arc<dyn BlockchainStore> =
        Arc::new(SledStore::open(output_path.clone())?);

    // ── 3. Block 0: genesis ───────────────────────────────────────────────
    println!("Writing Block 0 (genesis)...");
    let genesis = create_genesis_block();
    write_block(&out_store, genesis)?;

    // ── 4. Block 1: identity + wallet registrations ───────────────────────
    println!("Writing Block 1 ({} identities + {} wallets)...",
        identities.len(), wallets.len());

    let mut block1_txns: Vec<Transaction> = Vec::new();

    for id_data in &identities {
        let tx = Transaction::new_identity_registration(
            id_data.clone(),
            vec![],
            system_signature(),
            b"testnet-reset-identity".to_vec(),
        );
        block1_txns.push(tx);
    }

    for wallet_data in &wallets {
        // Zero initial_balance: SOV is minted separately in block 2 via TokenMint txs.
        // This prevents double-minting when process_wallet_transactions() runs.
        let mut wd = wallet_data.clone();
        wd.initial_balance = 0;
        let tx = Transaction::new_wallet_registration(
            wd,
            vec![],
            system_signature(),
            b"testnet-reset-wallet".to_vec(),
        );
        block1_txns.push(tx);
    }

    let block1 = build_block(1, block1_txns)?;
    write_block(&out_store, block1)?;

    // ── 5. Block 2: TokenMint 5,000 SOV per PRIMARY wallet only ──────────
    // Only Primary wallets receive the welcome bonus.
    // UBI, Savings, and other wallet types start at 0 SOV.
    let primary_wallets: Vec<&WalletTransactionData> = wallets
        .iter()
        .filter(|w| w.wallet_type.eq_ignore_ascii_case("primary"))
        .collect();

    println!("Writing Block 2 ({} primary wallet SOV mints at 5,000 SOV each)...", primary_wallets.len());
    println!("  (Skipping {} non-primary wallets)", wallets.len() - primary_wallets.len());

    let sov_token_id = generate_lib_token_id();
    let mut mint_txns: Vec<Transaction> = Vec::new();

    for wallet_data in &primary_wallets {
        let wallet_id_bytes: [u8; 32] = wallet_data
            .wallet_id
            .as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("wallet_id is not 32 bytes"))?;

        let mint_data = TokenMintData {
            token_id: sov_token_id,
            to: wallet_id_bytes,
            amount: SOV_PER_WALLET,
        };

        let tx = Transaction::new_token_mint(
            mint_data,
            system_signature(),
            b"testnet-reset-sov".to_vec(),
        );
        mint_txns.push(tx);
    }

    let block2 = build_block(2, mint_txns)?;
    write_block(&out_store, block2)?;

    // ── 6. Summary ────────────────────────────────────────────────────────
    let total_sov = primary_wallets.len() as u128 * SOV_PER_WALLET;
    println!();
    println!("=== RESET COMPLETE ===");
    println!("  Blocks written:         3 (height 0–2)");
    println!("  Identities:             {}", identities.len());
    println!("  Wallets (all types):    {}", wallets.len());
    println!("  Primary wallets minted: {}", primary_wallets.len());
    println!("  Total SOV minted:       {} SOV", total_sov / 100_000_000);
    println!("  Output sled:            {}", output_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Stop all 4 nodes");
    println!("  2. rsync {} to each node:", output_path.display());
    println!("     for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do");
    println!("       rsync -az --delete {} $node:/opt/zhtp/data/testnet/sled", output_path.display());
    println!("     done");
    println!("  3. Restart all nodes");

    Ok(())
}

/// Build a block at a given height from a list of transactions.
fn build_block(height: u64, transactions: Vec<Transaction>) -> Result<Block> {
    let prev_hash = Hash::default();
    BlockBuilder::new(prev_hash, height, Difficulty::default())
        .version(8)
        .timestamp(lib_blockchain::GENESIS_TIMESTAMP + height)
        .transactions(transactions)
        .build()
}
