/// Wallet Probe — read-only investigation tool.
///
/// Given a sled path and a hex identity id (or DID), it:
///  - locates the identity in identity_registry by DID key OR by either
///    derivation: blake3(dilithium) / blake3(dilithium||kyber)
///  - prints the identity record + both computed derivations
///  - scans wallet_registry for wallets owned by EITHER derivation
///  - prints registry totals
///
/// Usage: wallet_probe <sled_path> <hex_id_or_did>

use anyhow::Result;
use lib_blockchain::storage::{BlockchainStore, SledStore};
use lib_blockchain::Blockchain;
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/zhtp/data/testnet/sled".to_string());
    let target = std::env::args()
        .nth(2)
        .unwrap_or_default()
        .trim_start_matches("did:zhtp:")
        .to_lowercase();

    println!("Opening sled at: {}", path);
    let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(PathBuf::from(&path))?);

    let mut blockchain = match Blockchain::load_from_store(store)? {
        Some(bc) => bc,
        None => {
            println!("No committed blocks in sled.");
            return Ok(());
        }
    };

    println!(
        "Post-tx-replay (no genesis): identities={} wallets={}",
        blockchain.identity_count(),
        blockchain.wallet_count()
    );

    // load_from_store replays transactions only — genesis identities/wallets
    // are populated by apply_genesis_state via direct inserts in build_block0,
    // NOT via transactions. Apply genesis so the registry matches what a
    // running node actually serves.
    match lib_blockchain::genesis::GenesisConfig::from_embedded() {
        Ok(gen) => match gen.apply_genesis_state(&mut blockchain) {
            Ok(()) => println!("Applied embedded genesis state."),
            Err(e) => println!("apply_genesis_state failed: {}", e),
        },
        Err(e) => println!("from_embedded failed: {}", e),
    }

    println!("Chain height: {}", blockchain.get_height());
    println!("identity_registry entries: {}", blockchain.identity_count());
    println!("wallet_registry   entries: {}", blockchain.wallet_count());
    println!("target id/did: {}\n", target);

    // ── Locate the identity ────────────────────────────────────────────────
    let mut matched: Option<(String, [u8; 32], [u8; 32])> = None; // (did, dil_hash, combined_hash)
    for (did, id) in blockchain.identity_registry_snapshot() {
        if id.public_key.len() < 32 {
            continue;
        }
        let dil = lib_crypto::hash_blake3(&id.public_key);
        let combined = if !id.kyber_public_key.is_empty() {
            lib_crypto::hash_blake3(
                &[&id.public_key[..], &id.kyber_public_key[..]].concat(),
            )
        } else {
            dil
        };
        let did_hex = did.trim_start_matches("did:zhtp:").to_lowercase();
        if did_hex == target
            || hex::encode(dil) == target
            || hex::encode(combined) == target
        {
            println!("=== IDENTITY MATCHED ===");
            println!("  registry DID key : {}", did);
            println!("  display_name     : {}", id.display_name);
            println!("  public_key len   : {} bytes", id.public_key.len());
            println!("  kyber_public_key : {} bytes", id.kyber_public_key.len());
            println!("  blake3(dilithium)            = {}", hex::encode(dil));
            println!("  blake3(dilithium||kyber)     = {}", hex::encode(combined));
            println!("  owned_wallets ({}):", id.owned_wallets.len());
            for w in &id.owned_wallets {
                println!("    - {}", w);
            }
            matched = Some((did.clone(), dil, combined));
            break;
        }
    }
    let (did, dil_hash, combined_hash) = match matched {
        Some(m) => m,
        None => {
            println!("!! No identity in registry matches that id/did by any derivation.");
            return Ok(());
        }
    };

    // ── Scan wallet_registry for wallets owned by either derivation ────────
    println!("\n=== WALLETS OWNED BY EITHER DERIVATION ===");
    let did_bytes = hex::decode(did.trim_start_matches("did:zhtp:")).unwrap_or_default();
    let mut hits = 0;
    for (wallet_id_hex, w) in blockchain.wallet_registry_snapshot() {
        let owner = match &w.owner_identity_id {
            Some(o) => o.as_bytes().to_vec(),
            None => continue,
        };
        let matches_dil = owner.as_slice() == dil_hash.as_slice();
        let matches_combined = owner.as_slice() == combined_hash.as_slice();
        let matches_did = owner.as_slice() == did_bytes.as_slice();
        if matches_dil || matches_combined || matches_did {
            hits += 1;
            let tag = if matches_dil {
                "blake3(dilithium)"
            } else if matches_combined {
                "blake3(dil||kyber)"
            } else {
                "DID-bytes"
            };
            println!(
                "  wallet {} type={} owner={} [{}] initial_balance={}",
                wallet_id_hex,
                w.wallet_type,
                hex::encode(&owner),
                tag,
                w.initial_balance
            );
        }
    }
    println!("\n{} wallet(s) owned by this identity across all derivations.", hits);

    // ── Also: every distinct owner_identity_id in the registry (sample) ────
    if hits == 0 {
        println!("\n=== SAMPLE: first 10 wallet owners in registry (for derivation comparison) ===");
        for (wid, w) in blockchain.wallet_registry_snapshot().into_iter().take(10) {
            println!(
                "  wallet {} owner={:?}",
                wid,
                w.owner_identity_id.as_ref().map(|o| hex::encode(o.as_bytes()))
            );
        }
    }

    Ok(())
}
