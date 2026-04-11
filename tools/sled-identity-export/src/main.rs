/// Sled identity exporter v3
/// Reads wallets tree, extracts public keys, reconstructs DIDs via blake3(pk).
/// identity_id = blake3(dilithium5_public_key) — confirmed in lib-identity/src/identity/manager.rs:89

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// We'll try multiple wallet record formats since we don't know exact layout.
// The key insight: wallet_type string is readable, and public_key is 2592 bytes (Dilithium5).
// We scan for the public_key by looking for the 2592-byte field.

#[derive(Debug, Serialize, Deserialize)]
struct WalletRecordV1 {
    pub wallet_id: [u8; 32],
    pub public_key: Vec<u8>,
    pub wallet_type: String,
    pub owner_identity_id: Option<[u8; 32]>,
    pub created_at: u64,
}

// Alternative: wallet_id as 16-byte UUID
#[derive(Debug, Serialize, Deserialize)]
struct WalletRecordV1b {
    pub wallet_id: [u8; 16],
    pub public_key: Vec<u8>,
    pub wallet_type: String,
    pub owner_identity_id: Option<[u8; 32]>,
    pub created_at: u64,
}

// IdentityMetadata (new format, already confirmed working for 1 entry)
#[derive(Debug, Serialize, Deserialize)]
struct IdentityMetadata {
    did: String,
    display_name: String,
    pub public_key: Vec<u8>,
    ownership_proof: Vec<u8>,
    controlled_nodes: Vec<String>,
    owned_wallets: Vec<String>,
    attributes: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ExportedIdentity {
    did: String,
    display_name: String,
    public_key: String,
    identity_type: String,
    wallet_type: String,
    created_at: u64,
}

#[derive(Serialize)]
struct StateExport {
    identities: Vec<ExportedIdentity>,
    total_wallets_scanned: usize,
    deser_errors: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: sled-identity-export <sled-dir> <output.json>");
        std::process::exit(1);
    }
    let sled_path = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);

    println!("Opening sled at {:?}", sled_path);
    let db = sled::open(&sled_path).expect("Failed to open sled");

    let wallets_tree = db.open_tree("wallets").expect("open wallets");
    let identity_meta_tree = db.open_tree("identity_meta").expect("open identity_meta");

    println!("wallets entries: {}", wallets_tree.len());
    println!("identity_meta entries: {}", identity_meta_tree.len());

    // Map: identity_hash -> (display_name, public_key_hex, wallet_type, created_at)
    let mut identity_map: HashMap<String, ExportedIdentity> = HashMap::new();
    let mut deser_errors = 0usize;
    let mut total = 0usize;

    for result in wallets_tree.iter() {
        let (_key, value) = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("wallets iteration error: {}", err);
                deser_errors += 1;
                continue;
            }
        };
        total += 1;

        // Try V1: wallet_id=[u8;32]
        if let Ok(rec) = bincode::deserialize::<WalletRecordV1>(&value) {
            if rec.public_key.len() == 2592 && !rec.wallet_type.is_empty() {
                let pk_hash = blake3::hash(&rec.public_key);
                let did = format!("did:zhtp:{}", hex::encode(pk_hash.as_bytes()));
                let pk_hex = hex::encode(&rec.public_key);

                let entry = identity_map.entry(did.clone()).or_insert(ExportedIdentity {
                    did: did.clone(),
                    display_name: String::new(),
                    public_key: pk_hex,
                    identity_type: "human".to_string(),
                    wallet_type: rec.wallet_type.clone(),
                    created_at: rec.created_at,
                });
                // Prefer "Primary Wallet" type for the display entry
                if rec.wallet_type == "Primary Wallet" {
                    entry.wallet_type = rec.wallet_type;
                    entry.created_at = rec.created_at;
                }
                continue;
            }
        }

        // Try V1b: wallet_id=[u8;16]
        if let Ok(rec) = bincode::deserialize::<WalletRecordV1b>(&value) {
            if rec.public_key.len() == 2592 && !rec.wallet_type.is_empty() {
                let pk_hash = blake3::hash(&rec.public_key);
                let did = format!("did:zhtp:{}", hex::encode(pk_hash.as_bytes()));
                let pk_hex = hex::encode(&rec.public_key);

                let entry = identity_map.entry(did.clone()).or_insert(ExportedIdentity {
                    did: did.clone(),
                    display_name: String::new(),
                    public_key: pk_hex,
                    identity_type: "human".to_string(),
                    wallet_type: rec.wallet_type.clone(),
                    created_at: rec.created_at,
                });
                if rec.wallet_type == "Primary Wallet" {
                    entry.wallet_type = rec.wallet_type;
                    entry.created_at = rec.created_at;
                }
                continue;
            }
        }

        // Fallback: scan value bytes for a 2592-byte run that could be a Dilithium5 key
        // preceded by 8-byte length prefix
        let v = value.as_ref();
        let target_len: u64 = 2592;
        let target_bytes = target_len.to_le_bytes();
        let mut found = false;
        for i in 0..v.len().saturating_sub(8 + 2592) {
            if &v[i..i+8] == &target_bytes {
                let pk = &v[i+8..i+8+2592];
                // Quick sanity: not all zeros
                if pk.iter().any(|&b| b != 0) {
                    let pk_hash = blake3::hash(pk);
                    let did = format!("did:zhtp:{}", hex::encode(pk_hash.as_bytes()));
                    identity_map.entry(did.clone()).or_insert(ExportedIdentity {
                        did,
                        display_name: String::new(),
                        public_key: hex::encode(pk),
                        identity_type: "human".to_string(),
                        wallet_type: "unknown".to_string(),
                        created_at: 0,
                    });
                    found = true;
                    break;
                }
            }
        }
        if !found {
            deser_errors += 1;
        }
    }

    // Also pull display names from identity_meta tree
    for result in identity_meta_tree.iter() {
        let (_key, value) = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("wallets iteration error: {}", err);
                deser_errors += 1;
                continue;
            }
        };
        if let Ok(meta) = bincode::deserialize::<IdentityMetadata>(&value) {
            if meta.did.starts_with("did:zhtp:") {
                if let Some(entry) = identity_map.get_mut(&meta.did) {
                    entry.display_name = meta.display_name;
                } else {
                    let pk_hash = blake3::hash(&meta.public_key);
                    let computed_did = format!("did:zhtp:{}", hex::encode(pk_hash.as_bytes()));
                    if meta.did != computed_did {
                        eprintln!("Warning: identity_meta DID mismatch; stored DID {} does not match computed DID {}",
                            meta.did, computed_did);
                    }
                    identity_map.insert(computed_did.clone(), ExportedIdentity {
                        did: computed_did.clone(),
                        display_name: meta.display_name,
                        public_key: hex::encode(&meta.public_key),
                        identity_type: "human".to_string(),
                        wallet_type: "unknown".to_string(),
                        created_at: 0,
                    });
                }
            }
        }
    }

    let mut identities: Vec<ExportedIdentity> = identity_map.into_values().collect();
    identities.sort_by(|a, b| a.did.cmp(&b.did));

    println!("\nTotal wallets scanned: {}", total);
    println!("Unique identities reconstructed: {}", identities.len());
    println!("Entries without 2592-byte pk found: {}", deser_errors);

    let export = StateExport {
        identities,
        total_wallets_scanned: total,
        deser_errors,
    };
    let json = serde_json::to_string_pretty(&export).expect("json");
    std::fs::write(&output_path, &json).expect("write");
    println!("Written to {:?}", output_path);
}
