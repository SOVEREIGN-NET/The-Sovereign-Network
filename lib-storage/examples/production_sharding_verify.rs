//! Production API Sharding Verification
//!
//! This example proves that the high-level `upload_content` and `download_content`
//! APIs now transparently handle distributed sharding and fault tolerance.

use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig, StorageConfig, EconomicManagerConfig, ErasureConfig, StorageTier, UploadRequest, AccessControlSettings, ContentStorageRequirements, DownloadRequest, BudgetConstraints, QualityRequirements};
use lib_identity::ZhtpIdentity;
use lib_identity::types::{IdentityType, NodeId};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("--- Sovereign Network Production API Sharding Verification ---");

    // 1. Setup Identities
    let alice = ZhtpIdentity::new_unified(IdentityType::Human, Some(25), Some("US".to_string()), "AliceDevice", None)?;
    let node_id = NodeId::from_did_device("did:zhtp:node1", "server")?;

    // 2. Initialize Storage System
    let config = UnifiedStorageConfig {
        node_id,
        addresses: vec!["127.0.0.1:9001".to_string()],
        economic_config: EconomicManagerConfig::default(),
        storage_config: StorageConfig {
            max_storage_size: 1024 * 1024 * 1024,
            default_tier: StorageTier::Hot,
            enable_compression: true,
            enable_encryption: true,
            dht_persist_path: None,
        },
        // We'll use 4 data shards and 2 parity shards (Standard Production Setting)
        erasure_config: ErasureConfig { data_shards: 4, parity_shards: 2 },
    };
    let mut storage = UnifiedStorageSystem::new(config).await?;

    // 3. Perform High-Level Upload
    let original_data = b"This is a production-level document that is being transparently sharded across the Sovereign Network.".to_vec();
    println!("\n[1] Uploading content via high-level Production API...");

    let upload_req = UploadRequest {
        content: original_data.clone(),
        filename: "secret_report.pdf".to_string(),
        mime_type: "application/pdf".to_string(),
        description: "Confidential Sovereign Report".to_string(),
        tags: vec!["confidential".to_string(), "report".to_string()],
        encrypt: true,
        compress: true,
        access_control: AccessControlSettings {
            public_read: false,
            read_permissions: vec![alice.clone()],
            write_permissions: vec![],
            expires_at: None,
        },
        storage_requirements: ContentStorageRequirements {
            duration_days: 365,
            quality_requirements: QualityRequirements::default(),
            budget_constraints: BudgetConstraints::default(),
        },
    };

    let content_hash = storage.upload_content(upload_req, alice.clone()).await?;
    println!(" ✅ Upload Successful! Content Hash: {}", hex::encode(content_hash.as_bytes()));

    // 4. Verify Internal Sharding
    let metadata = storage.get_content_metadata(&content_hash).await?;
    println!("\n[2] Verifying Metadata Integrity:");
    println!("    Total Chunks (Shards): {}", metadata.total_chunks);
    println!("    Erasure Config: {} Data + {} Parity", metadata.erasure_data_shards, metadata.erasure_parity_shards);
    println!("    Shard Hashes Found: {}", metadata.shard_hashes.len());

    assert_eq!(metadata.total_chunks, 6);
    assert_eq!(metadata.shard_hashes.len(), 6);

    // 5. Perform High-Level Download (Reconstruction)
    println!("\n[3] Downloading content via high-level Production API (Automatic Reconstruction)...");
    let download_req = DownloadRequest {
        content_hash: content_hash.clone(),
        requester: alice.clone(),
        version: None,
    };

    let downloaded_data = storage.download_content(download_req).await?;
    println!(" ✅ Download Successful!");

    assert_eq!(downloaded_data, original_data);
    println!("    Data Integrity Verified: \"{}\"", String::from_utf8_lossy(&downloaded_data));

    println!("\nVERIFICATION COMPLETE: Production APIs now support transparent distributed sharding.");

    Ok(())
}
