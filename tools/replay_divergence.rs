//! Hunt replay vs live-sled balance divergence for GENESIS-2 forensics.
//!
//! Usage:
//!   replay_divergence inspect-block <blocks.v1.bin> <height>
//!   replay_divergence find-divergence <live-sled> <blocks.v1.bin> <wallet-hex> [max-height]

use anyhow::{Context, Result};
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::storage::{Address, BlockchainStore, SledStore, TokenId};
use lib_blockchain::sync::{ChainSync, ReplayBlocksFixture};
use lib_blockchain::transaction::TransactionPayload;
use lib_blockchain::types::TransactionType;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

fn load_fixture(path: &Path) -> Result<Vec<lib_blockchain::block::Block>> {
    let data = std::fs::read(path)?;
    if let Ok(fixture) = ReplayBlocksFixture::decode(&data) {
        return Ok(fixture.blocks);
    }
    bincode::deserialize(&data).context("decode blocks fixture")
}

fn sov_token() -> TokenId {
    TokenId::new(generate_lib_token_id())
}

fn balance_at(store: &dyn BlockchainStore, wallet: &[u8; 32]) -> Result<u128> {
    Ok(store
        .get_token_balance(&sov_token(), &Address::new(*wallet))
        .unwrap_or(0))
}

fn replay_to_height(blocks: &[lib_blockchain::block::Block], height: u64) -> Result<Arc<dyn BlockchainStore>> {
    let slice: Vec<_> = blocks
        .iter()
        .filter(|b| b.header.height <= height)
        .cloned()
        .collect();
    anyhow::ensure!(!slice.is_empty(), "no blocks up to height {height}");
    anyhow::ensure!(
        slice.last().map(|b| b.header.height) == Some(height),
        "fixture missing block at height {height}"
    );
    let dir = TempDir::new()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(dir.path())?);
    let sync = ChainSync::new(Arc::clone(&store));
    sync.import_blocks(slice).context("replay import")?;
    Ok(store)
}

fn inspect_block(path: &Path, height: u64) -> Result<()> {
    let blocks = load_fixture(path)?;
    let block = blocks
        .iter()
        .find(|b| b.header.height == height)
        .with_context(|| format!("block {height} not in fixture"))?;

    println!("Block {height}: tx_count={}", block.transactions.len());
    println!("SOV token_id={}", hex::encode(generate_lib_token_id()));

    for (i, tx) in block.transactions.iter().enumerate() {
        println!("\n--- tx[{i}] type={:?} fee={} v={}", tx.transaction_type, tx.fee, tx.version);
        match &tx.transaction_type {
            TransactionType::TokenTransfer => {
                if let TransactionPayload::TokenTransfer(data) = &tx.payload {
                    println!(
                        "  TokenTransfer: token={} from={} to={} amount={} nonce={}",
                        hex::encode(data.token_id),
                        hex::encode(data.from),
                        hex::encode(data.to),
                        data.amount,
                        data.nonce
                    );
                } else {
                    println!("  TokenTransfer payload missing TokenTransferData");
                }
            }
            TransactionType::WalletRegistration | TransactionType::WalletUpdate => {
                if let Some(wd) = tx.wallet_data() {
                    println!(
                        "  {:?}: wallet_id={} initial_balance={} type={}",
                        tx.transaction_type,
                        hex::encode(wd.wallet_id.as_array()),
                        wd.initial_balance,
                        wd.wallet_type
                    );
                } else {
                    println!("  {:?} (no wallet_data)", tx.transaction_type);
                }
            }
            other => println!("  (other type: {other:?})"),
        }
        println!("  signer key_id={}", hex::encode(tx.signature.public_key.key_id));
    }
    Ok(())
}

fn scan_wallet_transfers(
    blocks_path: &Path,
    wallet_hex: &str,
    from_height: u64,
    to_height: u64,
) -> Result<()> {
    let wallet_bytes = hex::decode(wallet_hex).context("wallet hex")?;
    anyhow::ensure!(wallet_bytes.len() == 32, "wallet must be 32 bytes");
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&wallet_bytes);

    let blocks = load_fixture(blocks_path)?;
    println!(
        "TokenTransfer activity for {} in [{from_height}, {to_height}]",
        wallet_hex
    );
    for block in blocks.iter().filter(|b| {
        b.header.height >= from_height && b.header.height <= to_height
    }) {
        for (i, tx) in block.transactions.iter().enumerate() {
            if tx.transaction_type != TransactionType::TokenTransfer {
                continue;
            }
            let TransactionPayload::TokenTransfer(data) = &tx.payload else {
                continue;
            };
            if data.from != wallet && data.to != wallet {
                continue;
            }
            let dir = if data.from == wallet { "debit" } else { "credit" };
            println!(
                "  h={} tx[{i}] {dir} amount={} nonce={} counterparty={}",
                block.header.height,
                data.amount,
                data.nonce,
                hex::encode(if data.from == wallet { data.to } else { data.from })
            );
        }
    }
    Ok(())
}

/// Single-pass incremental replay; sample balances at milestones.
fn incremental_milestones(
    blocks_path: &Path,
    wallet_hex: &str,
    max_height: u64,
) -> Result<()> {
    let wallet_bytes = hex::decode(wallet_hex).context("wallet hex")?;
    anyhow::ensure!(wallet_bytes.len() == 32, "wallet must be 32 bytes");
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&wallet_bytes);

    let blocks = load_fixture(blocks_path)?;
    let milestones: Vec<u64> = [
        0, 1, 50, 1000, 10000, 50000, 70000, 73000, 73800, 73900, 73950, 73980, 73990, 74000,
        74005, 74008, 74009, 74010,
    ]
    .into_iter()
    .filter(|h| *h <= max_height)
    .collect();

    let dir = TempDir::new()?;
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(dir.path())?);
    let sync = ChainSync::new(Arc::clone(&store));

    let mut cursor = 0usize;
    let mut next_milestone = 0usize;

    while cursor < blocks.len() && next_milestone < milestones.len() {
        let target = milestones[next_milestone];
        let end = blocks
            .iter()
            .position(|b| b.header.height > target)
            .unwrap_or(blocks.len());
        if end > cursor {
            let chunk: Vec<_> = blocks[cursor..end].to_vec();
            sync.import_blocks(chunk).context("incremental import")?;
            cursor = end;
        }
        let bal = balance_at(store.as_ref(), &wallet)?;
        eprintln!("replay height={target:>6} balance={bal}");
        next_milestone += 1;
    }

    // Live sled tip balance (includes blocks > max_height — informational only).
    Ok(())
}

fn find_wallet_in_chain(blocks_path: &Path, wallet_hex: &str) -> Result<()> {
    let wallet_bytes = hex::decode(wallet_hex).context("wallet hex")?;
    anyhow::ensure!(wallet_bytes.len() == 32, "wallet must be 32 bytes");
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&wallet_bytes);

    let blocks = load_fixture(blocks_path)?;
    println!("Scanning for wallet {wallet_hex} in all block txs");
    for block in &blocks {
        for (i, tx) in block.transactions.iter().enumerate() {
            let mut hit = false;
            if let TransactionPayload::TokenTransfer(d) = &tx.payload {
                if d.from == wallet || d.to == wallet {
                    hit = true;
                    println!(
                        "  h={} tx[{i}] TokenTransfer amount={} nonce={} from={} to={}",
                        block.header.height,
                        d.amount,
                        d.nonce,
                        hex::encode(d.from),
                        hex::encode(d.to)
                    );
                }
            }
            if let Some(wd) = tx.wallet_data() {
                if wd.wallet_id.as_array() == wallet {
                    hit = true;
                    println!(
                        "  h={} tx[{i}] {:?} initial_balance={} type={}",
                        block.header.height,
                        tx.transaction_type,
                        wd.initial_balance,
                        wd.wallet_type
                    );
                }
            }
            if !hit {
                if tx.signature.public_key.key_id == wallet {
                    println!(
                        "  h={} tx[{i}] {:?} signer_key_id=wallet",
                        block.header.height, tx.transaction_type
                    );
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let cmd = args
        .first()
        .cloned()
        .unwrap_or_else(|| "help".to_string());

    match cmd.as_str() {
        "inspect-block" => {
            let path = Path::new(args.get(1).context("blocks path")?);
            let height: u64 = args.get(2).context("height")?.parse()?;
            inspect_block(path, height)?;
        }
        "scan-wallet" => {
            let blocks = Path::new(args.get(1).context("blocks path")?);
            let wallet = args.get(2).context("wallet hex")?;
            let from_h: u64 = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(73_900);
            let to_h: u64 = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(74_010);
            scan_wallet_transfers(blocks, wallet, from_h, to_h)?;
        }
        "find-wallet" => {
            let blocks = Path::new(args.get(1).context("blocks path")?);
            let wallet = args.get(2).context("wallet hex")?;
            find_wallet_in_chain(blocks, wallet)?;
        }
        "milestones" => {
            let blocks = Path::new(args.get(1).context("blocks path")?);
            let wallet = args.get(2).context("wallet hex")?;
            let max_h: u64 = args
                .get(3)
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(74_010);
            incremental_milestones(blocks, wallet, max_h)?;
        }
        "balance-at" => {
            let blocks = Path::new(args.get(1).context("blocks path")?);
            let wallet = args.get(2).context("wallet hex")?;
            let height: u64 = args.get(3).context("height")?.parse()?;
            let wallet_bytes = hex::decode(wallet).context("wallet hex")?;
            anyhow::ensure!(wallet_bytes.len() == 32, "wallet must be 32 bytes");
            let mut w = [0u8; 32];
            w.copy_from_slice(&wallet_bytes);
            let store = replay_to_height(&load_fixture(blocks)?, height)?;
            let bal = balance_at(store.as_ref(), &w)?;
            println!("replay height={height} balance={bal}");
        }
        "live-balance" => {
            let sled = Path::new(args.get(1).context("sled path")?);
            let wallet = args.get(2).context("wallet hex")?;
            let wallet_bytes = hex::decode(wallet).context("wallet hex")?;
            anyhow::ensure!(wallet_bytes.len() == 32, "wallet must be 32 bytes");
            let mut w = [0u8; 32];
            w.copy_from_slice(&wallet_bytes);
            let store = SledStore::open(sled)?;
            let h = store.latest_height().unwrap_or(0);
            let bal = balance_at(&store, &w)?;
            let token = sov_token();
            let nonce = store
                .get_token_nonce(&token, &Address::new(w))
                .unwrap_or(0);
            println!("live sled height={h} balance={bal} nonce={nonce}");
        }
        _ => {
            eprintln!(
                "Usage:\n  \
                 replay_divergence inspect-block <blocks.v1.bin> <height>\n  \
                 replay_divergence scan-wallet <blocks.v1.bin> <wallet-hex> [from-h] [to-h]\n  \
                 replay_divergence find-wallet <blocks.v1.bin> <wallet-hex>\n  \
                 replay_divergence milestones <blocks.v1.bin> <wallet-hex> [max-height]\n  \
                 replay_divergence balance-at <blocks.v1.bin> <wallet-hex> <height>\n  \
                 replay_divergence live-balance <sled-path> <wallet-hex>"
            );
        }
    }
    Ok(())
}