//! State versioning system for historical queries and state management
//!
//! Provides block-height based versioning to track contract state evolution
//! across blocks, enabling historical queries and state pruning.

use super::errors::StorageResult;
use super::persistent::PersistentStorage;

/// Manages versioned access to contract state based on block heights
///
/// Keys are stored as `state:{block_height}:{original_key}` to maintain
/// historical versions. This allows querying state at any historical block height
/// and enables pruning of old versions for storage efficiency.
pub struct StateVersionManager {
    storage: PersistentStorage,
    /// Maximum number of historical versions to keep (default: 1000)
    /// Older versions are automatically pruned
    max_versions_to_keep: u64,
}

impl StateVersionManager {
    /// Create a new state version manager
    pub fn new(storage: PersistentStorage, max_versions_to_keep: Option<u64>) -> Self {
        StateVersionManager {
            storage,
            max_versions_to_keep: max_versions_to_keep.unwrap_or(1000),
        }
    }

    /// Generate a versioned key for block height-based lookup
    fn make_versioned_key(block_height: u64, key: &[u8]) -> Vec<u8> {
        let mut versioned = Vec::new();
        versioned.extend_from_slice(b"state:");
        versioned.extend_from_slice(&block_height.to_be_bytes());
        versioned.extend_from_slice(b":");
        versioned.extend_from_slice(key);
        versioned
    }

    /// Get metadata prefix for last finalized height
    fn last_finalized_key() -> &'static [u8] {
        b"meta:last_finalized_height"
    }

    /// Store versioned state for a specific block height
    pub fn store_versioned(
        &self,
        block_height: u64,
        key: &[u8],
        value: &[u8],
    ) -> StorageResult<()> {
        let versioned_key = Self::make_versioned_key(block_height, key);
        self.storage.set(&versioned_key, value)?;
        Ok(())
    }

    /// Get state at a specific block height
    pub fn get_versioned(&self, key: &[u8], block_height: u64) -> StorageResult<Option<Vec<u8>>> {
        let versioned_key = Self::make_versioned_key(block_height, key);
        self.storage.get(&versioned_key)
    }

    /// Get the latest state value (highest block height)
    pub fn get_latest(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        // For now, scan for the highest version
        // TODO: Optimize with a manifest tracking latest versions
        let prefix = format!("state:*:");
        let entries = self.storage.scan_prefix(prefix.as_bytes())?;

        let mut latest_value: Option<Vec<u8>> = None;
        let mut latest_height: u64 = 0;

        for (versioned_key, value) in entries {
            if let Some(height) = Self::extract_height_from_key(&versioned_key) {
                if height > latest_height {
                    latest_height = height;
                    latest_value = Some(value);
                }
            }
        }

        Ok(latest_value)
    }

    /// Extract block height from a versioned key
    fn extract_height_from_key(versioned_key: &[u8]) -> Option<u64> {
        // Format: state:{height}:{key}
        if !versioned_key.starts_with(b"state:") {
            return None;
        }

        let rest = &versioned_key[6..]; // Skip "state:"
        let mut height_bytes = [0u8; 8];
        if rest.len() >= 8 {
            height_bytes.copy_from_slice(&rest[..8]);
            Some(u64::from_be_bytes(height_bytes))
        } else {
            None
        }
    }

    /// Update the last finalized height metadata
    pub fn update_last_finalized_height(&self, height: u64) -> StorageResult<()> {
        let height_bytes = height.to_be_bytes();
        self.storage.set(Self::last_finalized_key(), &height_bytes)?;
        Ok(())
    }

    /// Get the last finalized block height
    pub fn get_last_finalized_height(&self) -> StorageResult<Option<u64>> {
        match self.storage.get(Self::last_finalized_key())? {
            Some(bytes) => {
                if bytes.len() == 8 {
                    let mut height_bytes = [0u8; 8];
                    height_bytes.copy_from_slice(&bytes);
                    Ok(Some(u64::from_be_bytes(height_bytes)))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Prune versions older than (current_height - max_versions_to_keep)
    pub fn prune_old_versions(&self, current_height: u64) -> StorageResult<u64> {
        let min_height = current_height.saturating_sub(self.max_versions_to_keep);

        // Scan and delete all versions before min_height
        let mut deleted_count = 0u64;
        for height in 0..min_height {
            let prefix = format!("state:{}:", height);
            let count = self.storage.delete_prefix(prefix.as_bytes())?;
            deleted_count += count;
        }

        Ok(deleted_count)
    }

    /// Set the maximum number of versions to keep
    pub fn set_max_versions_to_keep(&mut self, max: u64) {
        self.max_versions_to_keep = max;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_versioned_key_generation() {
        let key = StateVersionManager::make_versioned_key(100, b"test_key");
        assert!(key.starts_with(b"state:"));
        assert!(key.contains(&b':')); // At least two colons for version and key separator
    }

    #[test]
    fn test_height_extraction() {
        let key = StateVersionManager::make_versioned_key(42, b"key");
        let extracted = StateVersionManager::extract_height_from_key(&key);
        assert_eq!(extracted, Some(42));
    }

    #[test]
    fn test_last_finalized_height() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = StateVersionManager::new(storage, Some(100));

        // Should be None initially
        assert_eq!(manager.get_last_finalized_height().unwrap(), None);

        // Update and retrieve
        manager.update_last_finalized_height(42).unwrap();
        assert_eq!(manager.get_last_finalized_height().unwrap(), Some(42));
    }
}
