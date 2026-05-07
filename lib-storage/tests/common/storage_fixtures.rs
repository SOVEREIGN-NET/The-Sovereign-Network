//! Shared storage test fixtures for lib-storage integration tests.
//!
//! Centralises backend and config construction so test files do not each
//! need their own copy of the same boilerplate.

use anyhow::Result;
use lib_identity::types::NodeId;
use lib_storage::{
    EconomicManagerConfig, ErasureConfig, StorageConfig, StorageTier, UnifiedStorageConfig,
};
use lib_storage::backend::SledBackend;
use tempfile::TempDir;

/// Open a temporary Sled backend. The returned `TempDir` must be kept alive
/// for the duration of the test — dropping it removes the backing directory.
pub fn test_backend() -> Result<(SledBackend, TempDir)> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("sled_db");
    let backend = SledBackend::open(&db_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok((backend, temp_dir))
}

/// A `UnifiedStorageConfig` wired to `node_id` and `port` with sensible test defaults.
pub fn test_config(node_id: NodeId, port: u16) -> UnifiedStorageConfig {
    UnifiedStorageConfig {
        node_id,
        addresses: vec![format!("127.0.0.1:{}", port)],
        economic_config: EconomicManagerConfig {
            default_duration_days: 30,
            base_price_per_gb_day: 1000,
            enable_escrow: true,
            escrow_release_threshold: 0.8,
            max_contract_duration: 365,
            min_contract_value: 100,
            quality_monitoring_interval: 3600,
            penalty_enforcement_enabled: true,
            reward_distribution_enabled: true,
            market_pricing_enabled: false,
        },
        storage_config: StorageConfig {
            max_storage_size: 1_000_000,
            default_tier: StorageTier::Warm,
            enable_compression: false,
            enable_encryption: false,
            dht_persist_path: None,
        },
        erasure_config: ErasureConfig {
            data_shards: 3,
            parity_shards: 2,
        },
    }
}
