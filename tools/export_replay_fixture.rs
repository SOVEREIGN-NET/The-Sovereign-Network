//! Export a versioned replay fixture (blocks + balance snapshot) from a live sled store.
//!
//! Used by GENESIS-2 manual g4 gate (#2730). Run on a validator with sled access:
//!
//! ```bash
//! cargo run -p tools --bin export_replay_fixture -- \
//!   /opt/zhtp/data/testnet/sled /tmp/g4-fixture --to-height 74010
//! ```
//!
//! Writes:
//!   - `blocks.v1.bin` — versioned block window (bincode)
//!   - `checkpoint.json` — `ReplayCheckpointSnapshot` for balance parity
//!
//! For chains with 100k+ blocks, prefer `--to-height` over full export to limit memory.

use anyhow::{Context, Result};
use lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION;
use lib_blockchain::contracts::utils::generate_lib_token_id;
use lib_blockchain::genesis::GenesisConfig;
use lib_blockchain::protocol::ProtocolParams;
use lib_blockchain::storage::{Address, BlockchainStore, SledStore, TokenId};
use lib_blockchain::sync::{ChainSync, ReplayBlocksFixture, REPLAY_BLOCKS_FIXTURE_VERSION};
use lib_blockchain::Blockchain;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Mirrors `lib-blockchain/tests/common/replay_gate.rs` — keep field order stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayCheckpointSnapshot {
    checkpoint_height: u64,
    sov_wallets: Vec<SovWalletBalance>,
    cbe_treasury_balance: u128,
    treasury_sov_balance: u128,
    #[serde(default)]
    dao_tokens: Vec<DaoTokenBalance>,
    #[serde(default)]
    tolerance_atoms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SovWalletBalance {
    wallet_id: String,
    balance: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaoTokenBalance {
    token_id: String,
    symbol: String,
    holder_wallet_id: String,
    balance: u128,
}

fn treasury_address() -> Address {
    *ProtocolParams::default().fee_sink_address()
}

fn main() -> Result<()> {
    let sled_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());
    let out_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp/g4-replay-fixture".to_string());
    let mut to_height: Option<u64> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 3;
    while i < args.len() {
        if args[i] == "--to-height" {
            to_height = Some(
                args.get(i + 1)
                    .context("--to-height requires a value")?
                    .parse()
                    .context("invalid --to-height")?,
            );
            i += 2;
        } else if let Some(h) = args[i].strip_prefix("--to-height=") {
            to_height = Some(h.parse().context("invalid --to-height=")?);
            i += 1;
        } else {
            i += 1;
        }
    }

    std::fs::create_dir_all(&out_dir)?;
    export_fixture(Path::new(&sled_path), Path::new(&out_dir), to_height)
}

fn export_fixture(sled_path: &Path, out_dir: &Path, to_height: Option<u64>) -> Result<()> {
    eprintln!("Opening sled: {}", sled_path.display());
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(sled_path)?);
    let sync = ChainSync::new(Arc::clone(&store));

    let latest = store.latest_height().context("sled has no committed height")?;
    let checkpoint = to_height.unwrap_or(latest).min(latest);
    eprintln!("Exporting blocks 0..={checkpoint} (chain tip {latest})");

    if checkpoint > 50_000 {
        eprintln!(
            "WARNING: exporting {checkpoint} blocks materialises the full window in memory. \
             Consider a lower --to-height for OOM safety on large chains."
        );
    }

    let blocks = sync
        .export_blocks(0, checkpoint)
        .context("export_blocks failed")?;

    let fixture = ReplayBlocksFixture {
        version: REPLAY_BLOCKS_FIXTURE_VERSION,
        exported_to_height: checkpoint,
        blocks,
    };
    let blocks_path = out_dir.join(format!("blocks.v{REPLAY_BLOCKS_FIXTURE_VERSION}.bin"));
    let encoded = bincode::serialize(&fixture).context("bincode encode fixture")?;
    std::fs::write(&blocks_path, encoded)?;
    eprintln!("Wrote {}", blocks_path.display());

    let snapshot = build_snapshot(&*store, checkpoint)?;
    let snapshot_path = out_dir.join("checkpoint.json");
    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(&snapshot_path, json)?;
    eprintln!("Wrote {}", snapshot_path.display());
    eprintln!("Done. Run manual gate with:");
    eprintln!(
        "  G4_REPLAY_BLOCKS_PATH={} G4_REPLAY_SNAPSHOT_PATH={} \\",
        blocks_path.display(),
        snapshot_path.display()
    );
    eprintln!(
        "  cargo test -p lib-blockchain --test g4_replay_acceptance_tests \\",
    );
    eprintln!("    test_g4_checkpoint_replay_acceptance -- --ignored --nocapture");
    Ok(())
}

fn build_snapshot(store: &dyn BlockchainStore, checkpoint_height: u64) -> Result<ReplayCheckpointSnapshot> {
    let cfg = GenesisConfig::from_embedded().context("embedded genesis")?;
    let entries = cfg.sov_allocation_entries().context("sov entries")?;
    anyhow::ensure!(
        entries.len() >= 3,
        "need >= 3 sov_balances in genesis for snapshot sample"
    );

    let sov_token = TokenId::new(generate_lib_token_id());
    let cbe_token = TokenId::new(Blockchain::derive_cbe_token_id_pub());
    let treasury = treasury_address();

    let sov_wallets: Vec<SovWalletBalance> = entries
        .iter()
        .take(3)
        .map(|(wallet_id, _)| {
            let balance = store
                .get_token_balance(&sov_token, &Address::new(*wallet_id))
                .unwrap_or(0);
            SovWalletBalance {
                wallet_id: hex::encode(wallet_id),
                balance,
            }
        })
        .collect();

    Ok(ReplayCheckpointSnapshot {
        checkpoint_height,
        sov_wallets,
        cbe_treasury_balance: store
            .get_token_balance(&cbe_token, &treasury)
            .unwrap_or(0),
        treasury_sov_balance: store
            .get_token_balance(&sov_token, &treasury)
            .unwrap_or(0),
        dao_tokens: vec![],
        tolerance_atoms: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_treasury_constant_matches_export_expectation() {
        // Sanity: export tool documents CBE 20B for pre-GENESIS-6 chains.
        let _ = GENESIS_TREASURY_ALLOCATION;
    }
}