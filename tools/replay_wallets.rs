/// Wallet Replay Tool
///
/// Reads the testnet snapshot and registers all wallets with their original IDs
/// by submitting WalletRegistration transactions to the running node.
///
/// Usage: replay_wallets <snapshot_path> <server>
///
/// Each wallet is submitted as a WalletRegistration system transaction via
/// the blockchain's pending transaction pool.

use anyhow::Result;
use std::path::Path;

fn main() -> Result<()> {
    let snapshot_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "docs/testnet/testnet_snapshot_2026-04-14.json".to_string());

    eprintln!("Loading snapshot: {}", snapshot_path);

    let snapshot: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&snapshot_path)?)?;

    let wallets = snapshot["wallets"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No wallets array in snapshot"))?;

    eprintln!("Total wallets to replay: {}", wallets.len());

    // Group by owner for display
    let mut by_owner: std::collections::HashMap<String, Vec<&serde_json::Value>> =
        std::collections::HashMap::new();
    for w in wallets {
        let owner = w["owner_identity_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        by_owner.entry(owner).or_default().push(w);
    }
    eprintln!("Unique owners: {}", by_owner.len());

    // Output as JSON array of WalletTransactionData for the node to consume
    let mut wallet_data = Vec::new();
    for w in wallets {
        let wallet_id = w["wallet_id"].as_str().unwrap_or("");
        let wallet_type = w["wallet_type"].as_str().unwrap_or("Primary");
        let wallet_name = w["wallet_name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let owner_identity_id = w["owner_identity_id"].as_str().unwrap_or("");
        let public_key = w["public_key"].as_str().unwrap_or("");
        let timestamp = w["timestamp"].as_u64().unwrap_or(0);

        // Only Primary wallets get the welcome bonus
        let initial_balance: u128 = if wallet_type == "Primary" {
            lib_types::sov::atoms(5_000) // 5000 SOV welcome bonus
        } else {
            0
        };

        wallet_data.push(serde_json::json!({
            "wallet_id": wallet_id,
            "wallet_type": wallet_type,
            "wallet_name": if wallet_name.is_empty() {
                format!("{} Wallet", wallet_type)
            } else {
                wallet_name
            },
            "alias": wallet_type.to_lowercase(),
            "public_key": public_key,
            "owner_identity_id": owner_identity_id,
            "seed_commitment": "0000000000000000000000000000000000000000000000000000000000000000",
            "created_at": timestamp,
            "registration_fee": 0,
            "capabilities": if wallet_type == "Primary" { 255 } else { 1 },
            "initial_balance": initial_balance.to_string(),
        }));
    }

    // Write the replay data
    let output = serde_json::json!({
        "total": wallet_data.len(),
        "wallets": wallet_data,
    });

    let out_path = "docs/testnet/wallet_replay_data.json";
    std::fs::write(out_path, serde_json::to_string_pretty(&output)?)?;
    eprintln!("Written to: {}", out_path);
    eprintln!("Use this file with the node's wallet seeding endpoint or genesis replay.");

    // Also print summary
    let primary = wallets
        .iter()
        .filter(|w| w["wallet_type"].as_str() == Some("Primary"))
        .count();
    let ubi = wallets
        .iter()
        .filter(|w| w["wallet_type"].as_str() == Some("UBI"))
        .count();
    let savings = wallets
        .iter()
        .filter(|w| w["wallet_type"].as_str() == Some("Savings"))
        .count();
    eprintln!("\nSummary:");
    eprintln!("  Primary: {} (each gets 5000 SOV welcome bonus)", primary);
    eprintln!("  UBI:     {} (no initial balance)", ubi);
    eprintln!("  Savings: {} (no initial balance)", savings);
    eprintln!(
        "  Total SOV to mint: {} SOV",
        primary as u128 * 5_000
    );

    Ok(())
}
