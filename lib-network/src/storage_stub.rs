//! Temporary storage stub to keep lib-network protocol-only.
//! TODO (relocation pass): move real storage integration to the application layer.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;

/// Trait defining the storage interface
///
/// This trait is the boundary between lib-network (protocol layer) and lib-storage (persistence).
/// All storage operations must go through this trait. No concrete storage type should be
/// imported directly into lib-network.
#[async_trait]
pub trait UnifiedStorage: Send + Sync {
    /// Store a domain record
    async fn store_domain_record(&self, domain: &str, data: Vec<u8>) -> Result<()>;

    /// Load a domain record
    async fn load_domain_record(&self, domain: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a domain record
    async fn delete_domain_record(&self, domain: &str) -> Result<()>;

    /// List all domain records (domain, data pairs)
    async fn list_domain_records(&self) -> Result<Vec<(String, Vec<u8>)>>;

    /// Store manifest history for a domain
    async fn store_manifest(&self, domain: &str, manifest_data: Vec<u8>) -> Result<()>;

    /// Load manifest history for a domain
    async fn load_manifest(&self, domain: &str) -> Result<Option<Vec<u8>>>;

    /// Check if this is a stub (for startup assertions)
    fn is_stub(&self) -> bool;
}

#[derive(Clone, Default)]
pub struct UnifiedStorageConfig;

#[derive(Clone, Default)]
pub struct UnifiedStorageSystem;

impl UnifiedStorageSystem {
    pub async fn new(_config: UnifiedStorageConfig) -> Result<Self> {
        Ok(Self)
    }

    pub async fn get_statistics(&self) -> Result<StorageStatistics> {
        Ok(StorageStatistics {
            storage_stats: StorageStats { total_uploads: 0 },
        })
    }
}

#[async_trait]
impl UnifiedStorage for UnifiedStorageSystem {
    async fn store_domain_record(&self, _domain: &str, _data: Vec<u8>) -> Result<()> {
        Err(anyhow!("FATAL: Stub storage attempted to write domain record. Real storage must be provided by zhtp."))
    }

    async fn load_domain_record(&self, _domain: &str) -> Result<Option<Vec<u8>>> {
        Ok(None) // Stub returns no data on read - silent but won't lose data in production
    }

    async fn delete_domain_record(&self, _domain: &str) -> Result<()> {
        Err(anyhow!("FATAL: Stub storage attempted to delete domain record. Real storage must be provided by zhtp."))
    }

    async fn list_domain_records(&self) -> Result<Vec<(String, Vec<u8>)>> {
        Ok(Vec::new()) // Stub returns empty list
    }

    async fn store_manifest(&self, _domain: &str, _manifest_data: Vec<u8>) -> Result<()> {
        Err(anyhow!("FATAL: Stub storage attempted to write manifest. Real storage must be provided by zhtp."))
    }

    async fn load_manifest(&self, _domain: &str) -> Result<Option<Vec<u8>>> {
        Ok(None) // Stub returns no manifest
    }

    fn is_stub(&self) -> bool {
        true
    }
}

#[derive(Clone, Default)]
pub struct StorageStatistics {
    pub storage_stats: StorageStats,
}

#[derive(Clone, Default)]
pub struct StorageStats {
    pub total_uploads: u64,
}
