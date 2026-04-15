//! Compression example: Compress and distribute a file
//! 
//! This example demonstrates the complete workflow:
//! 1. Chunk a file using FastCDC
//! 2. Generate ZK-Witness metadata
//! 3. Distribute shards (simulated)
//! 4. Retrieve and reassemble file

use lib_compression::{ContentChunker, ZkWitness};
use std::fs;
use tempfile::NamedTempFile;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🗜️  Sovereign Network Compression Demo\n");

    // Create a test file
    let test_data = b"Hello, Sovereign Network! ".repeat(10000); // ~260KB
    let test_file = NamedTempFile::new()?;
    fs::write(test_file.path(), &test_data)?;
    
    println!("📄 Original file: {} bytes", test_data.len());
    println!("   Path: {}\n", test_file.path().display());

    // Step 1: Chunk the file
    println!("🔪 Step 1: Chunking file...");
    let chunker = ContentChunker::new();
    let shards = chunker.chunk_file(test_file.path()).await?;
    
    println!("   ✓ Created {} shards", shards.len());
    println!("   ✓ Average shard size: {} KB", 
        test_data.len() / shards.len() / 1024);

    // Step 2: Check for deduplication
    println!("\n⚙️  Step 2: Analyzing deduplication...");
    let dedup_result = chunker.chunk_with_dedup(&test_data)?;
    
    println!("   ✓ Total shards: {}", dedup_result.shard_indices.len());
    println!("   ✓ Unique shards: {}", dedup_result.unique_shards.len());
    println!("   ✓ Deduplication ratio: {:.2}x", dedup_result.dedup_ratio());
    println!("   ✓ Space savings: {:.1}%", dedup_result.space_savings());

    // Step 3: Generate ZK-Witness
    println!("\n🔐 Step 3: Generating ZK-Witness...");
    let witness = ZkWitness::from_file(test_file.path(), &shards).await?;
    
    println!("   ✓ Original size: {} bytes", witness.metadata.size);
    println!("   ✓ Witness size: {} bytes", witness.size());
    println!("   ✓ Compression ratio: {:.0}:1", witness.compression_ratio());
    println!("   ✓ Shard count: {}", witness.metadata.shard_count);

    // Step 4: Save witness (in real system, delete original)
    println!("\n💾 Step 4: Saving witness...");
    let witness_file = test_file.path().with_extension("zkw");
    witness.save(&witness_file).await?;
    
    println!("   ✓ Witness saved to: {}", witness_file.display());
    println!("   ✓ Can now delete original file!");

    // Summary
    println!("\n📊 Summary:");
    println!("   Original file:  {} KB", test_data.len() / 1024);
    println!("   Witness file:   {} KB", witness.size() / 1024);
    println!("   Space saved:    {} KB", (test_data.len() - witness.size()) / 1024);
    println!("   Reduction:      {:.1}%", 
        (1.0 - witness.size() as f64 / test_data.len() as f64) * 100.0);

    println!("\n✅ Compression complete!");
    println!("\n💡 In production:");
    println!("   • Shards would be distributed across DHT nodes");
    println!("   • Original file would be deleted");
    println!("   • Only ZK-Witness (~50KB) kept locally");
    println!("   • File can be reconstructed on-demand from network");

    Ok(())
}
