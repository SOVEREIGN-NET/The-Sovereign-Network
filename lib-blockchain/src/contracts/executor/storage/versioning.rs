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

    /// Get the latest state value (highest block height) for a specific key
    pub fn get_latest(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        // Key format: "state:" (6) + height_be (8) + ":" (1) + original_key
        const KEY_OFFSET: usize = 6 + 8 + 1;

        let prefix = b"state:";
        let entries = self.storage.scan_prefix(prefix)?;

        let mut latest_value: Option<Vec<u8>> = None;
        let mut latest_height: Option<u64> = None;

        for (versioned_key, value) in entries {
            if versioned_key.len() <= KEY_OFFSET {
                continue;
            }
            if &versioned_key[KEY_OFFSET..] != key {
                continue;
            }
            if let Some(height) = Self::extract_height_from_key(&versioned_key) {
                if latest_height.map_or(true, |h| height > h) {
                    latest_height = Some(height);
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
        self.storage
            .set(Self::last_finalized_key(), &height_bytes)?;
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

        // Scan all state: entries and delete those below min_height.
        // Heights are stored as big-endian bytes, not decimal strings, so we
        // must decode via extract_height_from_key rather than format a string prefix.
        let entries = self.storage.scan_prefix(b"state:")?;
        let mut deleted_count = 0u64;
        for (versioned_key, _) in entries {
            if let Some(height) = Self::extract_height_from_key(&versioned_key) {
                if height < min_height {
                    self.storage.delete(&versioned_key)?;
                    deleted_count += 1;
                }
            }
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

    #[test]
    fn test_get_latest_returns_correct_key_not_highest_height_across_all_keys() {
        // Regression test: get_latest must filter by key, not just find the
        // entry with the highest block height across all keys in storage.
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = StateVersionManager::new(storage, Some(100));

        // Store two different keys at different heights
        manager.store_versioned(1, b"key_a", b"a_at_1").unwrap();
        manager.store_versioned(5, b"key_b", b"b_at_5").unwrap();
        manager.store_versioned(3, b"key_a", b"a_at_3").unwrap();

        // get_latest(key_a) must return "a_at_3", not "b_at_5"
        assert_eq!(
            manager.get_latest(b"key_a").unwrap(),
            Some(b"a_at_3".to_vec())
        );
        assert_eq!(
            manager.get_latest(b"key_b").unwrap(),
            Some(b"b_at_5".to_vec())
        );
        // Unknown key returns None
        assert_eq!(manager.get_latest(b"key_c").unwrap(), None);
    }

    #[test]
    fn test_prune_old_versions_actually_deletes_using_binary_height_keys() {
        // Regression test: prune used format!("state:{}:", height) (decimal string)
        // but keys encode height as big-endian bytes. Pruning was silently a no-op.
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = StateVersionManager::new(storage, Some(2));

        manager.store_versioned(1, b"k", b"v1").unwrap();
        manager.store_versioned(2, b"k", b"v2").unwrap();
        manager.store_versioned(3, b"k", b"v3").unwrap();

        // current_height=4, max_versions=2 → prune heights < 2
        let deleted = manager.prune_old_versions(4).unwrap();
        assert_eq!(deleted, 1, "expected height-1 entry to be deleted");

        assert_eq!(manager.get_versioned(b"k", 1).unwrap(), None);
        assert_eq!(
            manager.get_versioned(b"k", 2).unwrap(),
            Some(b"v2".to_vec())
        );
        assert_eq!(
            manager.get_versioned(b"k", 3).unwrap(),
            Some(b"v3".to_vec())
        );
    }
}
