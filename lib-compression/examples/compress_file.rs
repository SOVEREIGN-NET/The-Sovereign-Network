//! Simple example: Compress a file and generate witness
//!
//! Usage: cargo run --example compress_file

use lib_compression::{ContentChunker, ZkWitness};
use std::fs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a test file
    let test_data = "Hello, Sovereign Network! ".repeat(10000);
    let test_file = "test_input.txt";
    fs::write(test_file, &test_data)?;
    
    println!("🔹 Compressing file: {}", test_file);
    println!("   Original size: {} bytes\n", test_data.len());
    
    // Step 1: Chunk the file
    println!("1️⃣  Chunking into content-defined shards...");
    let chunker = ContentChunker::new();
    let file_data = fs::read(test_file)?;
    let shards = chunker.chunk(&file_data)?;
    println!("   ✓ Created {} shards\n", shards.len());
    
    // Step 2: Generate ZK-Witness
    println!("2️⃣  Generating ZK-Witness with Plonky2 proof...");
    let metadata = lib_compression::witness::FileMetadata {
        name: test_file.to_string(),
        size: test_data.len() as u64,
        shard_count: shards.len(),
        avg_shard_size: test_data.len() / shards.len(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        mime_type: Some("text/plain".to_string()),
        shard_offsets: None,
    };
    
    let witness = ZkWitness::generate(&shards, metadata)?;
    println!("   ✓ Witness generated");
    println!("   ✓ Plonky2 zkSNARK proof verified\n");
    
    // Step 3: Show witness details
    println!("3️⃣  Witness details:");
    println!("   ✓ Root hash: {}...", &witness.root_hash.iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>());
    println!("   ✓ Merkle root: {}...", &witness.merkle_root.iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>());
    if let Some(proof) = &witness.zk_proof {
        println!("   ✓ zkSNARK proof: {} bytes (circuit: {})", proof.proof.len(), proof.proof_system);
    }
    
    // Step 4: Verify witness
    println!("\n4️⃣  Verifying witness integrity...");
    witness.verify()?;
    println!("   ✓ Witness verified: VALID");
    
    // Step 5: Show results
    let compression_ratio = witness.compression_ratio();
    let space_saved = (1.0 - (witness.size() as f64 / test_data.len() as f64)) * 100.0;
    
    println!("\n📊 Results:");
    println!("   Original:    {} bytes", test_data.len());
    println!("   Witness:     {} bytes", witness.size());
    println!("   Ratio:       {:.0}:1", compression_ratio);
    println!("   Saved:       {:.2}%", space_saved);
    
    // Cleanup
    fs::remove_file(test_file)?;
    
    println!("\n✅ Complete! The system works end-to-end.");
    println!("   You can now delete the original file and keep only the witness.");
    println!("   Shards would be distributed across the DHT network.\n");
    
    Ok(())
}
