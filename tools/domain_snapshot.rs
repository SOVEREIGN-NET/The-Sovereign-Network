/// Domain Snapshot Tool
///
/// Extracts all domain records from the sled DomainRegistry for replay after reset.
/// Usage: domain_snapshot <sled_path> <output_dir>

use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());
    let out_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp".to_string());

    eprintln!("Opening sled at: {}", path);

    // Open sled directly and read domain records
    let db = sled::open(&path)?;

    // The domain registry stores records in a tree
    let mut domains = Vec::new();

    // Try the domain_records tree
    for tree_name in &["domain_records", "domains", "web4_domains"] {
        if let Ok(tree) = db.open_tree(tree_name) {
            eprintln!("Scanning tree '{}' ({} entries)...", tree_name, tree.len());
            for item in tree.iter() {
                let (key, value) = item?;
                let domain_name = String::from_utf8_lossy(&key).to_string();
                let record_json = String::from_utf8_lossy(&value).to_string();
                domains.push(serde_json::json!({
                    "domain": domain_name,
                    "record": serde_json::from_str::<serde_json::Value>(&record_json)
                        .unwrap_or_else(|_| {
                            // Binary record — store as hex
                            serde_json::json!({"raw_hex": hex::encode(&value)})
                        }),
                }));
            }
        }
    }

    // Also check the blockchain's domain_registry (on-chain domains)
    // These are stored as part of the blockchain state, not in a separate tree

    let out_path = format!("{}/domain_snapshot.json", out_dir);
    let json = serde_json::to_string_pretty(&serde_json::json!({
        "total_domains": domains.len(),
        "domains": domains,
    }))?;
    std::fs::write(&out_path, &json)?;

    eprintln!("\n=== DOMAIN SNAPSHOT ===");
    eprintln!("  Total domains: {}", domains.len());
    eprintln!("  Written to: {}", out_path);

    Ok(())
}
