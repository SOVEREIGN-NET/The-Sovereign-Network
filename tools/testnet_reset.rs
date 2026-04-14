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
    block::{Block, BlockBuilder},
    contracts::utils::generate_lib_token_id,
    genesis::GenesisConfig,
    storage::{BlockchainStore, SledStore},
    transaction::{
        Transaction, TokenMintData,
        core::{IdentityTransactionData, WalletTransactionData},
    },
    types::Difficulty,
};
use lib_crypto::types::{PublicKey, Signature, SignatureAlgorithm};
use std::path::PathBuf;
use std::sync::Arc;
use blake3;

const SOV_PER_WALLET: u128 = lib_types::sov::atoms(5_000); // 5,000 SOV × 10^18
/// Canonical wallet type string for Primary wallets (matches WalletType::Primary serialization).
const PRIMARY_WALLET_TYPE: &str = "Primary";
const MAX_TRANSACTIONS_PER_BLOCK: usize = 4096;
const TARGET_BLOCK_TIME: u64 = 10; // seconds

fn system_signature() -> Signature {
    // Construct a placeholder Dilithium public key and derive the key_id as blake3(dilithium_pk)
    let dilithium_pk = [0u8; 2592];
    let key_id_hash = blake3::hash(&dilithium_pk);
    let key_id: [u8; 32] = *key_id_hash.as_bytes();

    Signature {
        signature: vec![0xAA; 64],
        public_key: PublicKey {
            dilithium_pk,
            kyber_pk: [0u8; 1568],
            key_id,
        },
        algorithm: SignatureAlgorithm::DEFAULT,
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
    // Use canonical genesis from embedded config to ensure all nodes share the same block 0 hash.
    let genesis_config = GenesisConfig::from_embedded()?;
    let genesis_bc = genesis_config.build_block0()?;
    let genesis = genesis_bc.blocks.first()
        .ok_or_else(|| anyhow::anyhow!("build_block0() produced empty blockchain"))?
        .clone();
    write_block(&out_store, genesis.clone())?;

    // ── 4. Block 1: identity + wallet registrations ───────────────────────
    println!("Writing Block 1 ({} identities + {} wallets)...",
        identities.len(), wallets.len());

    // Ensure deterministic ordering: sort identities by DID and wallets by wallet_id
    let mut identities_sorted = identities.clone();
    let mut wallets_sorted = wallets.clone();
    identities_sorted.sort_by(|a, b| a.did.cmp(&b.did));
    wallets_sorted.sort_by(|a, b| a.wallet_id.cmp(&b.wallet_id));

    // Validate counts/sizes and fail fast with clear error
    let total_registrations = identities_sorted.len().saturating_add(wallets_sorted.len());
    if total_registrations > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(anyhow::anyhow!(
            "Too many identity+wallet registrations for a single block: {} > MAX_TRANSACTIONS_PER_BLOCK ({})",
            total_registrations,
            MAX_TRANSACTIONS_PER_BLOCK
        ));
    }

    let mut block1_txns: Vec<Transaction> = Vec::new();

    for id_data in &identities_sorted {
        let tx = Transaction::new_identity_registration(
            id_data.clone(),
            vec![],
            system_signature(),
            b"testnet-reset-identity".to_vec(),
        );
        block1_txns.push(tx);
    }

    for wallet_data in &wallets_sorted {
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
    
    // Validate we have at least one primary wallet for SOV distribution
    let primary_count = wallets.iter()
        .filter(|w| w.wallet_type.eq_ignore_ascii_case(PRIMARY_WALLET_TYPE))
        .count();
    if primary_count == 0 {
        return Err(anyhow::anyhow!(
            "No primary wallets found. At least one primary wallet is required for SOV distribution."
        ));
    }

    let block1 = build_block(1, &genesis, block1_txns)?;
    write_block(&out_store, block1.clone())?;

    // ── 5. Block 2: TokenMint 5,000 SOV per PRIMARY wallet only ──────────
    // Only Primary wallets receive the welcome bonus.
    // UBI, Savings, and other wallet types start at 0 SOV.
    let primary_wallets: Vec<&WalletTransactionData> = wallets_sorted
        .iter()
        .filter(|w| w.wallet_type.eq_ignore_ascii_case(PRIMARY_WALLET_TYPE))
        .collect();

    println!("Writing Block 2 ({} primary wallet SOV mints at 5,000 SOV each)...", primary_wallets.len());
    println!("  (Skipping {} non-primary wallets)", wallets_sorted.len() - primary_wallets.len());

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

    let block2 = build_block(2, &block1, mint_txns)?;
    write_block(&out_store, block2)?;

    // ── 6. Summary ────────────────────────────────────────────────────────
    let total_sov = primary_wallets.len() as u128 * SOV_PER_WALLET;
    println!();
    println!("=== RESET COMPLETE ===");
    println!("  Blocks written:         3 (height 0–2)");
    println!("  Identities:             {}", identities.len());
    println!("  Wallets (all types):    {}", wallets.len());
    println!("  Primary wallets minted: {}", primary_wallets.len());
    println!("  Total SOV minted:       {} SOV", lib_types::sov::to_display(total_sov));
    println!("  Output sled:            {}", output_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Stop all 4 nodes");
    println!("  2. rsync {} to each node:", output_path.display());
    println!("     for node in zhtp-g1 zhtp-g2 zhtp-g3 zhtp-g4; do");
    println!("       rsync -az --delete {}/ $node:/opt/zhtp/data/testnet/sled/", output_path.display());
    println!("     done");
    println!("  3. Restart all nodes");

    Ok(())
}

/// Build a block at a given height from a list of transactions.
fn build_block(height: u64, prev_block: &Block, transactions: Vec<Transaction>) -> Result<Block> {
    let prev_hash = prev_block.hash();
    let prev_timestamp = prev_block.header.timestamp;
    
    BlockBuilder::new(prev_hash, height, Difficulty::default())
        .version(lib_blockchain::BLOCKCHAIN_VERSION)
        .timestamp(prev_timestamp + TARGET_BLOCK_TIME)
        .transactions(transactions)
        .build()
}
