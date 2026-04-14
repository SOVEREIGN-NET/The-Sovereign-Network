/// Testnet Snapshot Tool
///
/// Opens the sled store and exports all identities, wallets, and CBE transactions
/// as JSON for replay after a testnet reset.

use anyhow::Result;
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::types::transaction_type::TransactionType;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

fn get_cbe_token_id() -> [u8; 32] {
    lib_blockchain::Blockchain::derive_cbe_token_id_pub()
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());

    let out_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp".to_string());

    eprintln!("Opening sled at: {}", path);
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(PathBuf::from(&path))?);

    let latest_height = match store.latest_height() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("No committed blocks in sled ({})", e);
            return Ok(());
        }
    };

    let cbe_token_id = get_cbe_token_id();
    eprintln!("Chain height: {}", latest_height);
    eprintln!("Scanning {} blocks...", latest_height + 1);

    // Collect all data in a single pass
    let mut identities: Vec<serde_json::Value> = Vec::new();
    let mut wallets: Vec<serde_json::Value> = Vec::new();
    let mut cbe_transfers: Vec<serde_json::Value> = Vec::new();

    // Track seen DIDs/wallet IDs for deduplication (block replay may re-register)
    let mut seen_dids: HashMap<String, usize> = HashMap::new(); // did -> index in identities
    let mut seen_wallets: HashMap<String, usize> = HashMap::new(); // wallet_id_hex -> index

    for height in 0..=latest_height {
        let block = match store.get_block_by_height(height)? {
            Some(b) => b,
            None => continue,
        };

        for tx in &block.transactions {
            match tx.transaction_type {
                TransactionType::IdentityRegistration => {
                    if let Some(id_data) = tx.identity_data() {
                        let did = id_data.did.clone();
                        let signer_key_id = hex::encode(tx.signature.public_key.key_id);
                        let dilithium_pk_hex = hex::encode(&tx.signature.public_key.dilithium_pk);
                        let kyber_pk_hex = hex::encode(&tx.signature.public_key.kyber_pk);
                        let display_name = id_data.display_name.clone();
                        let identity_type = id_data.identity_type.clone();
                        let owned_wallets = id_data.owned_wallets.clone();

                        let entry = serde_json::json!({
                            "height": height,
                            "did": did,
                            "display_name": display_name,
                            "identity_type": identity_type,
                            "owned_wallets": owned_wallets,
                            "key_id": signer_key_id,
                            "dilithium_pk": dilithium_pk_hex,
                            "kyber_pk": kyber_pk_hex,
                            "timestamp": tx.signature.timestamp,
                        });

                        if let Some(idx) = seen_dids.get(&did) {
                            // Later registration overwrites earlier (re-registration)
                            identities[*idx] = entry;
                        } else {
                            seen_dids.insert(did, identities.len());
                            identities.push(entry);
                        }
                    }
                }
                TransactionType::WalletRegistration => {
                    if let Some(w) = tx.wallet_data() {
                        let wallet_id_hex = hex::encode(w.wallet_id.as_bytes());
                        let owner_identity_id = w.owner_identity_id
                            .as_ref()
                            .map(|h| hex::encode(h.as_bytes()))
                            .unwrap_or_default();
                        let wallet_type = w.wallet_type.clone();
                        let wallet_name = w.wallet_name.clone();
                        let public_key_hex = hex::encode(&w.public_key);
                        let signer_key_id = hex::encode(tx.signature.public_key.key_id);

                        let entry = serde_json::json!({
                            "height": height,
                            "wallet_id": wallet_id_hex,
                            "owner_identity_id": owner_identity_id,
                            "wallet_type": wallet_type,
                            "wallet_name": wallet_name,
                            "public_key": public_key_hex,
                            "signer_key_id": signer_key_id,
                            "timestamp": tx.signature.timestamp,
                        });

                        if let Some(idx) = seen_wallets.get(&wallet_id_hex) {
                            wallets[*idx] = entry;
                        } else {
                            seen_wallets.insert(wallet_id_hex, wallets.len());
                            wallets.push(entry);
                        }
                    }
                }
                TransactionType::TokenTransfer => {
                    if let Some(d) = tx.token_transfer_data() {
                        if d.token_id == cbe_token_id {
                            cbe_transfers.push(serde_json::json!({
                                "height": height,
                                "tx_hash": hex::encode(tx.hash().as_bytes()),
                                "from": hex::encode(d.from),
                                "to": hex::encode(d.to),
                                "amount": d.amount.to_string(),
                                "nonce": d.nonce,
                                "signer_key_id": hex::encode(tx.signature.public_key.key_id),
                                "timestamp": tx.signature.timestamp,
                            }));
                        }
                    }
                }
                TransactionType::TokenMint => {
                    if let Some(d) = tx.token_mint_data() {
                        if d.token_id == cbe_token_id {
                            cbe_transfers.push(serde_json::json!({
                                "height": height,
                                "tx_hash": hex::encode(tx.hash().as_bytes()),
                                "type": "TokenMint",
                                "to": hex::encode(d.to),
                                "amount": d.amount.to_string(),
                                "signer_key_id": hex::encode(tx.signature.public_key.key_id),
                                "timestamp": tx.signature.timestamp,
                            }));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Write output files
    let snapshot = serde_json::json!({
        "snapshot_height": latest_height,
        "snapshot_date": chrono_like_now(),
        "identities": identities,
        "wallets": wallets,
        "cbe_transfers": cbe_transfers,
        "summary": {
            "total_identities": identities.len(),
            "total_wallets": wallets.len(),
            "total_cbe_transfers": cbe_transfers.len(),
            "total_cbe_atoms_transferred": cbe_transfers.iter()
                .filter_map(|t| t["amount"].as_str()?.parse::<u128>().ok())
                .sum::<u128>().to_string(),
        }
    });

    let out_path = format!("{}/testnet_snapshot.json", out_dir);
    let json = serde_json::to_string_pretty(&snapshot)?;
    std::fs::write(&out_path, &json)?;

    eprintln!("\n=== SNAPSHOT SUMMARY ===");
    eprintln!("  Identities:      {}", identities.len());
    eprintln!("  Wallets:         {}", wallets.len());
    eprintln!("  CBE transfers:   {}", cbe_transfers.len());
    eprintln!("  Written to:      {}", out_path);

    Ok(())
}

fn chrono_like_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", dur.as_secs())
}
