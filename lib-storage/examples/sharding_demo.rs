//! Sharding and Post-Quantum Encryption Demo
//!
//! This demo demonstrates:
//! 1. Splitting data into shards using Reed-Solomon Erasure Coding.
//! 2. Encrypting each shard with Post-Quantum CRYSTALS-Kyber + ChaCha20.
//! 3. Simulating distributed storage with unique DHT keys.
//! 4. Reconstructing original data even when multiple shards are lost.

use lib_storage::erasure::ErasureCoding;
use lib_crypto::{KeyPair, hybrid_encrypt, hybrid_decrypt, hash_blake3, Hash};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("--- Sovereign Network Sharding & PQ-Encryption Demo ---");

    // 1. Initial Data
    let original_data = b"This is a highly confidential document stored on the Sovereign Network. It is protected by Post-Quantum Cryptography and distributed across multiple nodes using Reed-Solomon sharding.".to_vec();
    println!("Original Data ({} bytes): \"{}\"", original_data.len(), String::from_utf8_lossy(&original_data));

    // 2. Setup Erasure Coding (4 data shards, 2 parity shards)
    // This allows us to lose ANY 2 shards and still recover everything.
    let data_shards = 4;
    let parity_shards = 2;
    let ec = ErasureCoding::new(data_shards, parity_shards)?;
    println!("\n[1] Initializing Erasure Coding: {} data shards, {} parity shards", data_shards, parity_shards);

    // 3. Encode Data into Shards
    let shards = ec.encode(&original_data)?;
    println!("[2] Data split into {} total shards ({} bytes each)", data_shards + parity_shards, shards.shard_size);

    // 4. Encrypt Shards using Post-Quantum Hybrid Encryption
    // In a real scenario, each shard might be encrypted for a different set of authorized nodes.
    let owner_keypair = KeyPair::generate()?;
    println!("\n[3] Encrypting shards with Post-Quantum CRYSTALS-Kyber1024 + ChaCha20-Poly1305...");

    let mut encrypted_shards = Vec::new();
    let mut dht_keys = Vec::new();

    // Combine data and parity shards for processing
    let mut all_raw_shards = shards.data_shards.clone();
    all_raw_shards.extend(shards.parity_shards.clone());

    for (i, raw_shard) in all_raw_shards.iter().enumerate() {
        // Hybrid encryption (Kyber KEM + ChaCha symmetric)
        let encrypted = hybrid_encrypt(raw_shard, &owner_keypair.public_key)?;

        // Generate a unique DHT key for this specific shard
        // Format: hash("shard:{content_id}:{index}")
        let content_id = hash_blake3(&original_data);
        let shard_key_input = format!("shard:{}:{}", hex::encode(content_id), i);
        let dht_key = Hash::from_bytes(&hash_blake3(shard_key_input.as_bytes())[..32]);

        println!("    Shard {}: Key = {}... ({} bytes encrypted)",
            i, hex::encode(&dht_key.as_bytes()[..8]), encrypted.len());

        encrypted_shards.push(encrypted);
        dht_keys.push(dht_key);
    }

    // 5. Simulate Shard Loss (Chaos Monkey)
    // We will "lose" shard 0 and shard 4 (one data, one parity).
    println!("\n[4] 💥 SIMULATING NETWORK PARTITION: Losing Shard 0 and Shard 4...");
    let mut available_indices = Vec::new();
    let mut received_shards = Vec::new();

    for i in 0..(data_shards + parity_shards) {
        if i == 0 || i == 4 {
            continue; // Shard lost!
        }
        available_indices.push(i);
        received_shards.push(encrypted_shards[i].clone());
    }

    // 6. Decrypt and Reconstruct
    println!("\n[5] Attempting recovery from {} remaining shards...", received_shards.len());

    // First, decrypt the shards we have
    let mut decrypted_shards = Vec::new();
    for enc_shard in &received_shards {
        let dec = hybrid_decrypt(enc_shard, &owner_keypair)?;
        decrypted_shards.push(dec);
    }

    // Re-organize for the Erasure Decoder
    // The decoder needs a specific structure to know which shards are missing
    let mut recovery_data_shards = vec![vec![0u8; shards.shard_size]; data_shards];
    let mut recovery_parity_shards = vec![vec![0u8; shards.shard_size]; parity_shards];

    for (idx, &original_pos) in available_indices.iter().enumerate() {
        if original_pos < data_shards {
            recovery_data_shards[original_pos] = decrypted_shards[idx].clone();
        } else {
            recovery_parity_shards[original_pos - data_shards] = decrypted_shards[idx].clone();
        }
    }

    let recovery_shards = lib_storage::erasure::EncodedShards {
        data_shards: recovery_data_shards,
        parity_shards: recovery_parity_shards,
        shard_size: shards.shard_size,
        original_size: shards.original_size,
    };

    let reconstructed_data = ec.decode(&recovery_shards, &available_indices)?;

    println!("\n[6] ✅ RECOVERY SUCCESSFUL!");
    println!("    Reconstructed Data: \"{}\"", String::from_utf8_lossy(&reconstructed_data));

    assert_eq!(reconstructed_data, original_data);
    println!("\nDemo completed successfully. Sharding and Post-Quantum encryption are verified.");

    Ok(())
}
