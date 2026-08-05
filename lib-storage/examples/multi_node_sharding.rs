//! Multi-Node Sharding & Post-Quantum Verification (Simulation)
//!
//! This simulation verifies:
//! 1. Distribution of PQ-encrypted shards across multiple independent DHT instances.
//! 2. Fault tolerance when one "node" (DHT instance) is lost.
//! 3. Use of raw byte storage to ensure Reed-Solomon integrity.

use lib_storage::erasure::ErasureCoding;
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig, StorageConfig, EconomicManagerConfig, ErasureConfig, StorageTier};
use lib_crypto::{KeyPair, hybrid_encrypt, hybrid_decrypt, hash_blake3};
use lib_identity::ZhtpIdentity;
use lib_identity::types::{IdentityType, NodeId};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("--- Sovereign Network Multi-Node Sharding Simulation (RAW BYTES) ---");

    // 1. Setup Identities
    let alice_identity = ZhtpIdentity::new_unified(IdentityType::Human, Some(25), Some("US".to_string()), "AliceDevice", None)?;
    let node1_id = NodeId::from_did_device("did:zhtp:node1", "server")?;
    let node2_id = NodeId::from_did_device("did:zhtp:node2", "server")?;

    // 2. Initialize Two Independent Storage/DHT Instances
    println!("\n[1] Starting two independent DHT nodes...");

    let config1 = UnifiedStorageConfig {
        node_id: node1_id,
        addresses: vec!["127.0.0.1:9001".to_string()],
        economic_config: EconomicManagerConfig::default(),
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
            dht_persist_path: None,
        },
        erasure_config: ErasureConfig { data_shards: 2, parity_shards: 3 },
    };
    let mut storage1 = UnifiedStorageSystem::new(config1).await?;

    let config2 = UnifiedStorageConfig {
        node_id: node2_id,
        addresses: vec!["127.0.0.1:9002".to_string()],
        economic_config: EconomicManagerConfig::default(),
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
            dht_persist_path: None,
        },
        erasure_config: ErasureConfig { data_shards: 2, parity_shards: 3 },
    };
    let mut storage2 = UnifiedStorageSystem::new(config2).await?;

    // 3. Prepare Data & PQ-Encryption
    let secret_doc = b"Sovereign Network Phase 2: Distributed Sharding is ACTIVE. This data is split across nodes using Kyber1024 and Reed-Solomon.".to_vec();
    println!("\n[2] Encrypting document with Post-Quantum CRYSTALS-Kyber1024 + ChaCha20...");
    let encrypted_blob = hybrid_encrypt(&secret_doc, &alice_identity.public_key)?;

    // 4. Shard the Encrypted Data (2 Data, 3 Parity)
    let data_shards = 2;
    let parity_shards = 3;
    let ec = ErasureCoding::new(data_shards, parity_shards)?;
    let shards = ec.encode(&encrypted_blob)?;
    println!("[3] Encrypted blob split into 5 total shards (2 data + 3 parity)");

    // 5. Distribute Shards across nodes
    println!("\n[4] Distributing shards across the local mesh...");
    let content_id = hash_blake3(&encrypted_blob);
    let mut shard_keys = Vec::new();

    let mut all_raw_shards = shards.data_shards.clone();
    all_raw_shards.extend(shards.parity_shards.clone());

    for (i, shard_data) in all_raw_shards.iter().enumerate() {
        let key_str = format!("sim-shard-{}", i); // Key for store_domain_record
        shard_keys.push(key_str.clone());

        if i < 3 {
            println!("    → Shard {} stored on NODE 1 (Key: {})", i, key_str);
            storage1.store_domain_record(&key_str, shard_data).await?;
        } else {
            println!("    → Shard {} stored on NODE 2 (Key: {})", i, key_str);
            storage2.store_domain_record(&key_str, shard_data).await?;
        }
    }

    // 6. SIMULATE CATASTROPHIC FAILURE: Node 1 goes offline!
    println!("\n[5] 💥 CATASTROPHE: Node 1 has been physically destroyed!");
    drop(storage1);

    // 7. Recovery from Node 2
    println!("\n[6] Attempting recovery using ONLY the 2 shards remaining on Node 2...");
    let mut available_indices = Vec::new();
    let mut retrieved_shards: Vec<Vec<u8>> = Vec::new();

    for i in 0..5 {
        let key_str = &shard_keys[i];
        // Use get_domain_record for RAW access
        match storage2.get_domain_record(key_str).await {
            Ok(Some(data)) => {
                println!("    ✅ Found Shard {} on Node 2 ({} bytes)", i, data.len());
                available_indices.push(i);
                retrieved_shards.push(data);
            },
            _ => {
                println!("    ❌ Shard {} is UNREACHABLE (was on Node 1)", i);
            }
        }
    }

    // Reconstruct
    println!("\n[7] Reconstructing encrypted blob from {} available shards...", retrieved_shards.len());

    let mut recovery_data_shards = vec![vec![0u8; shards.shard_size]; data_shards];
    let mut recovery_parity_shards = vec![vec![0u8; shards.shard_size]; parity_shards];

    for (idx, &original_pos) in available_indices.iter().enumerate() {
        if original_pos < data_shards {
            recovery_data_shards[original_pos] = retrieved_shards[idx].clone();
        } else {
            recovery_parity_shards[original_pos - data_shards] = retrieved_shards[idx].clone();
        }
    }

    let recovery_shards = lib_storage::erasure::EncodedShards {
        data_shards: recovery_data_shards,
        parity_shards: recovery_parity_shards,
        shard_size: shards.shard_size,
        original_size: shards.original_size,
    };

    let reconstructed_encrypted = ec.decode(&recovery_shards, &available_indices)?;

    // 8. Final Decryption
    println!("\n[8] Decrypting reconstructed blob with Alice's Post-Quantum Private Key...");
    let alice_kp = alice_identity.private_key.as_ref().unwrap();
    let alice_keypair = KeyPair {
        public_key: alice_identity.public_key.clone(),
        private_key: alice_kp.clone(),
    };

    let decrypted_doc = hybrid_decrypt(&reconstructed_encrypted, &alice_keypair)?;

    println!("\n✅ VERIFICATION SUCCESSFUL!");
    println!("   Document Content: \"{}\"", String::from_utf8_lossy(&decrypted_doc));

    assert_eq!(decrypted_doc, secret_doc);
    println!("\nSimulation Complete. Multi-node fault tolerance and PQ-Security are VERIFIED.");

    Ok(())
}
