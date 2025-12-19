//! Storage stub used when the `storage` feature is disabled.
//! Provides placeholder types to satisfy protocol interfaces without pulling lib-storage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type ContentHash = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub content_type: Option<String>,
    pub expires_at: Option<u64>,
}

pub type CachedContent = Vec<u8>;
pub type StorageSearchQuery = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub distributed_enabled: bool,
    pub default_replication: u32,
    pub price_per_gb_day: u64,
    pub max_content_size: usize,
    pub default_encryption: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            distributed_enabled: true,
            default_replication: 3,
            price_per_gb_day: 1000,
            max_content_size: 100 * 1024 * 1024,
            default_encryption: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageContract {
    pub id: String,
    pub content_id: String,
    pub duration_days: u32,
    pub replication: u32,
    pub total_cost: u64,
    pub providers: Vec<String>,
}

#[derive(Debug)]
pub struct StorageIntegration {
    pub content_cache: HashMap<String, CachedContent>,
    pub config: StorageConfig,
}

impl StorageIntegration {
    pub fn new(config: StorageConfig) -> anyhow::Result<Self> {
        Ok(Self {
            content_cache: HashMap::new(),
            config,
        })
    }
}
