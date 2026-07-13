//! Read-only audit of sovereign `assets` sled records (epic Q7 migration).
//!
//! Usage:
//!   cargo run -p tools --bin audit_sovereign_assets -- /path/to/sled

use anyhow::{Context, Result};
use lib_blockchain::contracts::sovereign_asset::{
    deserialize_sovereign_asset, DaoClass, GovernanceModuleState, SovereignAsset,
};
use std::path::PathBuf;

const TREE_ASSETS: &str = "assets";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireFormat {
    Current,
    LegacyMigrated,
}

fn detect_wire_format(bytes: &[u8]) -> WireFormat {
    if bincode::deserialize::<SovereignAsset>(bytes).is_ok() {
        WireFormat::Current
    } else {
        WireFormat::LegacyMigrated
    }
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/.zhtp/data/testnet/sled".to_string());

    println!("Opening sled (read-only audit): {}", path);
    let db = sled::open(PathBuf::from(&path))
        .with_context(|| format!("failed to open sled at {path}"))?;
    let assets = db
        .open_tree(TREE_ASSETS)
        .context("failed to open assets tree")?;

    let mut total = 0u64;
    let mut legacy = 0u64;
    let mut current = 0u64;
    let mut errors = 0u64;
    let mut pending_burn = 0u64;

    println!();
    println!("{:-<100}", "");
    println!(
        "{:<18} {:<8} {:<8} {:<6} {:<8} {:<10} {}",
        "asset_id", "format", "class", "burn", "treasury", "supply", "symbol"
    );
    println!("{:-<100}", "");

    for entry in assets.iter() {
        let (key, value) = entry.context("assets tree iteration failed")?;
        let asset_id: [u8; 32] = key
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid asset key length {}", key.len()))?;

        let format = detect_wire_format(&value);
        match deserialize_sovereign_asset(&value) {
            Ok(asset) => {
                total += 1;
                match format {
                    WireFormat::Current => current += 1,
                    WireFormat::LegacyMigrated => legacy += 1,
                }
                if asset.pending_burn_bps.is_some() {
                    pending_burn += 1;
                }
                println!(
                    "{:<18} {:<8} {:<8} {:<6} {:<8} {:<10} {}",
                    hex::encode(&asset_id[..4]),
                    match format {
                        WireFormat::Current => "current",
                        WireFormat::LegacyMigrated => "legacy",
                    },
                    asset.dao_class.as_str(),
                    asset.burn_bps,
                    asset.treasury_key_id.map(|_| "yes").unwrap_or("no"),
                    asset.total_supply,
                    asset.symbol,
                );
            }
            Err(e) => {
                errors += 1;
                eprintln!(
                    "ERROR asset {}: {}",
                    hex::encode(asset_id),
                    e
                );
            }
        }
    }

    println!("{:-<100}", "");
    println!("=== SOVEREIGN ASSET SLED AUDIT ===");
    println!("  Total records:        {}", total);
    println!("  Current wire format:  {}", current);
    println!("  Legacy (migrated):    {}", legacy);
    println!("  Deserialize errors:   {}", errors);
    println!("  pending_burn_bps:     {}", pending_burn);

    let mut pending_authority = 0u64;
    let mut pending_below_80k = 0u64;
    if let Ok(gov_tree) = db.open_tree("asset_governance") {
        for entry in gov_tree.iter().flatten() {
            if let Ok(state) = bincode::deserialize::<GovernanceModuleState>(&entry.1) {
                if let Some(p) = state.pending_transfer {
                    pending_authority += 1;
                    if p.effective_height < 80_000 {
                        pending_below_80k += 1;
                        println!(
                            "  WARN pending_transfer asset={} effective_height={}",
                            hex::encode(&entry.0),
                            p.effective_height
                        );
                    }
                }
            }
        }
    }
    println!("  asset_governance pending_transfer: {}", pending_authority);
    println!("  pending_transfer before 80k:       {}", pending_below_80k);

    for tree_name in ["asset_rewards", "asset_curve"] {
        let count = db
            .open_tree(tree_name)
            .map(|t| t.iter().count())
            .unwrap_or(0);
        println!("  {tree_name}:            {count}");
    }

    if total > 0 {
        let fp = assets
            .iter()
            .filter_map(|e| e.ok())
            .filter_map(|(_, v)| deserialize_sovereign_asset(&v).ok())
            .filter(|a| a.dao_class == DaoClass::Fp)
            .count();
        let np = total as usize - fp;
        println!("  dao_class FP:         {}", fp);
        println!("  dao_class NP:         {}", np);
    }

    if errors > 0 {
        anyhow::bail!("audit failed: {} deserialize errors", errors);
    }

    println!();
    if total == 0 {
        println!("OK: no sovereign asset records (empty assets tree).");
    } else if legacy > 0 {
        println!(
            "OK: all {} records deserialize; {} legacy rows migrated to dao_class=Fp, burn_bps=0.",
            total, legacy
        );
    } else {
        println!("OK: all {} records deserialize in current wire format.", total);
    }

    Ok(())
}