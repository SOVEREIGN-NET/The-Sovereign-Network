//! Temporary storage stub to keep lib-network protocol-only.
//! TODO (relocation pass): move real storage integration to the application layer.

use anyhow::Result;

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

#[derive(Clone, Default)]
pub struct StorageStatistics {
    pub storage_stats: StorageStats,
}

#[derive(Clone, Default)]
pub struct StorageStats {
    pub total_uploads: u64,
}
