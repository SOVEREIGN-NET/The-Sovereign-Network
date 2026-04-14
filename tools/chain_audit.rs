/// Chain Audit Tool
///
/// Opens the sled store directly and counts every transaction type in every block,
/// then compares against in-memory state to find divergences.

use anyhow::Result;
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::types::transaction_type::TransactionType;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());

    println!("Opening sled at: {}", path);
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(PathBuf::from(&path))?);

    let latest_height = match store.latest_height() {
        Ok(h) => h,
        Err(e) => {
            println!("No committed blocks in sled ({})", e);
            return Ok(());
        }
    };

    println!("Chain height: {}", latest_height);
    println!("Scanning all {} blocks...\n", latest_height + 1);

    // Counters per transaction type
    let mut tx_counts: HashMap<String, u64> = HashMap::new();
    let mut total_blocks = 0u64;
    let mut empty_blocks = 0u64;
    let mut missing_blocks = 0u64;

    // Sets for comparison
    let mut identity_dids_in_blocks: HashSet<String> = HashSet::new();
    let mut wallet_ids_in_blocks: HashSet<String> = HashSet::new();
    let mut token_mint_wallets: HashMap<String, u128> = HashMap::new(); // wallet_id -> total minted
    let mut token_transfer_count = 0u64;
    let mut token_creation_count = 0u64;

    for height in 0..=latest_height {
        match store.get_block_by_height(height)? {
            Some(block) => {
                total_blocks += 1;
                // Verify stored height matches requested height
                if block.header.height != height {
                    eprintln!("  MISMATCH at sled key {}: block.header.height = {}", height, block.header.height);
                }
                if height < 3 {
                    println!("  Block {}: header.height={}, version={}, tx_count={}", height, block.header.height, block.header.version, block.transactions.len());
                }
                let tx_count = block.transactions.len();
                if tx_count == 0 {
                    empty_blocks += 1;
                }

                for tx in &block.transactions {
                    let type_name = format!("{:?}", tx.transaction_type);
                    *tx_counts.entry(type_name).or_insert(0) += 1;

                    match tx.transaction_type {
                        TransactionType::IdentityRegistration => {
                            if let Some(id_data) = tx.identity_data() {
                                identity_dids_in_blocks.insert(id_data.did.clone());
                            }
                        }
                        TransactionType::WalletRegistration => {
                            if let Some(w) = tx.wallet_data() {
                                wallet_ids_in_blocks.insert(hex::encode(w.wallet_id.as_bytes()));
                            }
                        }
                        TransactionType::TokenMint => {
                            if let Some(mint) = tx.token_mint_data() {
                                let recipient = hex::encode(&mint.to);
                                *token_mint_wallets.entry(recipient).or_insert(0) += mint.amount;
                            }
                        }
                        TransactionType::TokenTransfer => {
                            token_transfer_count += 1;
                        }
                        TransactionType::TokenCreation => {
                            token_creation_count += 1;
                        }
                        _ => {}
                    }
                }
            }
            None => {
                missing_blocks += 1;
                eprintln!("  WARNING: Missing block at height {}", height);
            }
        }
    }

    println!("=== BLOCK SUMMARY ===");
    println!("  Total blocks scanned: {}", total_blocks);
    println!("  Missing blocks:       {}", missing_blocks);
    println!("  Empty blocks:         {}", empty_blocks);
    println!("  Non-empty blocks:     {}", total_blocks - empty_blocks);
    println!();

    println!("=== TRANSACTIONS BY TYPE (from blocks) ===");
    let mut sorted: Vec<_> = tx_counts.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());
    for (tx_type, count) in &sorted {
        println!("  {:40} {}", tx_type, count);
    }
    let total_txs: u64 = tx_counts.values().sum();
    println!("  {:40} {}", "TOTAL", total_txs);
    println!();

    println!("=== IDENTITIES IN BLOCKS ===");
    println!("  IdentityRegistration txs in blocks: {}", identity_dids_in_blocks.len());
    println!();

    println!("=== WALLETS IN BLOCKS ===");
    println!("  WalletRegistration txs in blocks:   {}", wallet_ids_in_blocks.len());
    println!();

    println!("=== TOKEN MINTS IN BLOCKS ===");
    println!("  Unique wallets with TokenMint txs:  {}", token_mint_wallets.len());
    println!("  Total TokenTransfer txs:            {}", token_transfer_count);
    println!("  Total TokenCreation txs:            {}", token_creation_count);

    let total_minted: u128 = token_mint_wallets.values().sum();
    println!("  Total SOV minted via blocks:        {} (raw units)", total_minted);
    println!("  Total SOV minted via blocks:        {} SOV", total_minted / 100_000_000);
    println!();

    // Now load blockchain state and compare
    println!("=== LOADING BLOCKCHAIN STATE FOR COMPARISON ===");
    let bc = match lib_blockchain::Blockchain::load_from_store(store)? {
        Some(bc) => bc,
        None => {
            println!("  load_from_store returned None — no committed blocks.");
            return Ok(());
        }
    };

    println!("  identity_registry entries:  {}", bc.identity_registry.len());
    println!("  wallet_registry entries:    {}", bc.wallet_registry.len());

    println!();
    println!("=== IDENTITY → WALLET MAPPING ===");
    let mut sorted_ids: Vec<_> = bc.identity_registry.values().collect();
    sorted_ids.sort_by(|a, b| a.did.cmp(&b.did));
    for id in &sorted_ids {
        println!("  SID:     {}", id.did);
        println!("  name:    {}", id.display_name);
        for w in &id.owned_wallets {
            println!("  wallet:  {}", w);
        }
        println!();
    }

    let sov_id = lib_blockchain::contracts::utils::generate_lib_token_id();
    let sov_balance_count = bc.token_contracts
        .get(&sov_id)
        .map(|t| t.balances_len())
        .unwrap_or(0);
    let sov_total: u128 = bc.token_contracts
        .get(&sov_id)
        .map(|t| t.total_balance_sum())
        .unwrap_or(0);
    println!("  SOV token balance entries:  {}", sov_balance_count);
    println!("  SOV total supply in memory: {} (raw), {} SOV", sov_total, sov_total / 100_000_000);
    println!();

    println!("=== DIVERGENCE ANALYSIS ===");
    let identity_divergence = bc.identity_registry.len() as i64 - identity_dids_in_blocks.len() as i64;
    let wallet_divergence = bc.wallet_registry.len() as i64 - wallet_ids_in_blocks.len() as i64;
    let balance_divergence = sov_balance_count as i64 - token_mint_wallets.len() as i64;

    println!("  Identities: {} in memory vs {} in blocks  -> divergence: {}",
        bc.identity_registry.len(), identity_dids_in_blocks.len(), identity_divergence);
    println!("  Wallets:    {} in memory vs {} in blocks  -> divergence: {}",
        bc.wallet_registry.len(), wallet_ids_in_blocks.len(), wallet_divergence);
    println!("  Balances:   {} in memory vs {} minted in blocks -> divergence: {}",
        sov_balance_count, token_mint_wallets.len(), balance_divergence);

    if identity_divergence != 0 || wallet_divergence != 0 || balance_divergence != 0 {
        println!();
        println!("  WARNING: DIVERGENCE DETECTED — state exists in memory that is NOT in any block.");
        println!("  This state will be LOST if sled is wiped without a blockchain.dat fallback.");
    } else {
        println!();
        println!("  OK: No divergence — all state is block-authoritative.");
    }

    // List identities in memory but not in any block
    if identity_divergence > 0 {
        println!();
        println!("=== IDENTITIES IN MEMORY BUT NOT IN ANY BLOCK ===");
        for (did, _) in &bc.identity_registry {
            if !identity_dids_in_blocks.contains(did) {
                println!("  {}", did);
            }
        }
    }

    // List wallets in memory but not in any block
    if wallet_divergence > 0 {
        println!();
        println!("=== WALLETS IN MEMORY BUT NOT IN ANY BLOCK ===");
        for (wallet_id, wallet) in &bc.wallet_registry {
            if !wallet_ids_in_blocks.contains(wallet_id) {
                println!("  {} (type: {}, initial_balance: {})",
                    wallet_id, wallet.wallet_type, wallet.initial_balance);
            }
        }
    }

    Ok(())
}
