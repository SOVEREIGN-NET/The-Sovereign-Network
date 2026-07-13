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
const TREE_TOKEN_NONCES: &str = "token_nonces";

fn print_token_nonce(path: &str, token_hex: &str, holder_hex: &str) -> Result<()> {
    let token = parse_hex_32(token_hex, "token_id")?;
    let holder = parse_hex_32(holder_hex, "holder_key_id")?;
    let db = sled::open(path).with_context(|| format!("failed to open sled at {path}"))?;
    let tree = db
        .open_tree(TREE_TOKEN_NONCES)
        .context("failed to open token_nonces tree")?;
    let mut key = [0u8; 65];
    key[0] = 0x01;
    key[1..33].copy_from_slice(&token);
    key[33..65].copy_from_slice(&holder);
    let nonce = match tree.get(&key)? {
        Some(bytes) if bytes.len() == 8 => u64::from_be_bytes(bytes.as_ref().try_into().unwrap()),
        Some(bytes) => anyhow::bail!("invalid nonce length {}", bytes.len()),
        None => 0,
    };
    println!("{{\"token_id\":\"{token_hex}\",\"holder\":\"{holder_hex}\",\"nonce\":{nonce}}}");
    Ok(())
}

fn parse_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).with_context(|| format!("{label} hex"))?;
    anyhow::ensure!(bytes.len() == 32, "{label} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

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
    let argv: Vec<String> = std::env::args().collect();
    let path = argv
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/opt/zhtp/.zhtp/data/testnet/sled".to_string());
    if argv.get(2).map(String::as_str) == Some("--token-nonce") {
        let token_hex = argv
            .get(3)
            .context("usage: audit_sovereign_assets <sled> --token-nonce <token_id> <holder_key_id>")?;
        let holder_hex = argv.get(4).context("missing holder_key_id")?;
        return print_token_nonce(&path, token_hex, holder_hex);
    }

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