//! Write-Ahead Log (WAL) recovery for crash resilience
//!
//! Recovers contract state from incomplete write operations during node crashes,
//! ensuring data consistency and enabling safe restarts.

use super::errors::{StorageError, StorageResult};
use super::persistent::PersistentStorage;

/// Recovery statistics from WAL processing
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub wal_entries_found: u64,
    pub entries_recovered: u64,
    pub entries_discarded: u64,
    pub last_finalized_height: Option<u64>,
}

/// Manages Write-Ahead Log (WAL) recovery on startup
///
/// The WAL protocol:
/// 1. Before finalizing block state, write WAL entry with all pending changes
/// 2. Execute the writes to storage
/// 3. Clear the WAL entry after successful commit
/// 4. On startup, scan for non-empty WAL entries (indicates incomplete block)
/// 5. Discard incomplete blocks to maintain consistency
pub struct WalRecoveryManager {
    storage: PersistentStorage,
}

impl WalRecoveryManager {
    /// Create a new WAL recovery manager
    pub fn new(storage: PersistentStorage) -> Self {
        WalRecoveryManager { storage }
    }

    /// Recover from crash by processing incomplete WAL entries
    ///
    /// # Recovery logic
    /// 1. Load last finalized block height
    /// 2. Scan all WAL entries
    /// 3. For each WAL entry > last finalized height:
    ///    - If WAL data exists (non-empty): block is incomplete, discard
    ///    - If WAL data is empty: block was finalized, delete WAL entry
    /// 4. Clean up stale metadata
    pub fn recover_from_crash(&self) -> StorageResult<RecoveryStats> {
        let mut stats = RecoveryStats {
            wal_entries_found: 0,
            entries_recovered: 0,
            entries_discarded: 0,
            last_finalized_height: self.get_last_finalized_height()?,
        };

        // Scan all WAL entries
        let wal_entries = self.storage.scan_prefix(b"wal:")?;
        stats.wal_entries_found = wal_entries.len() as u64;

        let last_finalized = stats.last_finalized_height.unwrap_or(0);

        for (wal_key, wal_data) in wal_entries {
            let height = self.extract_height_from_wal_key(&wal_key)?;

            if height <= last_finalized {
                // Block was already finalized, clean up WAL entry
                self.storage.delete(&wal_key)?;
                stats.entries_recovered += 1;
            } else if wal_data.is_empty() {
                // Block was finalized but WAL wasn't cleared, delete the entry
                self.storage.delete(&wal_key)?;
                stats.entries_recovered += 1;
            } else {
                // Block is incomplete (WAL data exists but wasn't cleared)
                // Discard this block's changes
                self.discard_incomplete_block(height)?;
                stats.entries_discarded += 1;

                // Clean up the WAL entry
                self.storage.delete(&wal_key)?;
            }
        }

        Ok(stats)
    }

    /// Discard all state changes for an incomplete block
    ///
    /// Removes all versioned state entries for this block height
    fn discard_incomplete_block(&self, height: u64) -> StorageResult<()> {
        let prefix = format!("state:{}:", height);
        self.storage.delete_prefix(prefix.as_bytes())?;
        Ok(())
    }

    /// Get the last finalized block height from metadata
    fn get_last_finalized_height(&self) -> StorageResult<Option<u64>> {
        match self.storage.get(b"meta:last_finalized_height")? {
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

    /// Extract block height from WAL key
    fn extract_height_from_wal_key(&self, wal_key: &[u8]) -> StorageResult<u64> {
        // Format: wal:{height}
        if !wal_key.starts_with(b"wal:") {
            return Err(StorageError::WalRecovery(
                "Invalid WAL key format".to_string(),
            ));
        }

        let height_bytes = &wal_key[4..];
        if height_bytes.len() != 8 {
            return Err(StorageError::WalRecovery(
                "Invalid WAL height encoding".to_string(),
            ));
        }

        let mut height = [0u8; 8];
        height.copy_from_slice(height_bytes);
        Ok(u64::from_be_bytes(height))
    }

    /// Check if WAL indicates an incomplete block
    pub fn is_incomplete_block(&self, height: u64) -> StorageResult<bool> {
        let wal_key = self.make_wal_key(height);
        match self.storage.get(&wal_key)? {
            Some(data) => Ok(!data.is_empty()),
            None => Ok(false),
        }
    }

    /// Make a WAL key for a block height
    fn make_wal_key(&self, height: u64) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(b"wal:");
        key.extend_from_slice(&height.to_be_bytes());
        key
    }

    /// Clean up old WAL entries before a certain height
    pub fn cleanup_old_wal(&self, before_height: u64) -> StorageResult<u64> {
        let wal_entries = self.storage.scan_prefix(b"wal:")?;
        let mut deleted_count = 0u64;

        for (wal_key, _) in wal_entries {
            if let Ok(height) = self.extract_height_from_wal_key(&wal_key) {
                if height < before_height {
                    self.storage.delete(&wal_key)?;
                    deleted_count += 1;
                }
            }
        }

        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_wal_key_generation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = WalRecoveryManager::new(storage);

        let key = manager.make_wal_key(100);
        assert!(key.starts_with(b"wal:"));
    }

    #[test]
    fn test_height_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = WalRecoveryManager::new(storage);

        let key = manager.make_wal_key(42);
        let height = manager.extract_height_from_wal_key(&key).unwrap();
        assert_eq!(height, 42);
    }

    #[test]
    fn test_incomplete_block_detection() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = WalRecoveryManager::new(storage.clone());

        // Initially no incomplete blocks
        assert!(!manager.is_incomplete_block(100).unwrap());

        // Mark block 100 as incomplete
        let wal_key = manager.make_wal_key(100);
        storage.set(&wal_key, b"incomplete_data").unwrap();

        // Now it should be detected
        assert!(manager.is_incomplete_block(100).unwrap());
    }

    #[test]
    fn test_recovery_stats() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let manager = WalRecoveryManager::new(storage.clone());

        // No WAL entries yet
        let stats = manager.recover_from_crash().unwrap();
        assert_eq!(stats.wal_entries_found, 0);

        // Add a WAL entry for height 100
        let wal_key = manager.make_wal_key(100);
        storage.set(&wal_key, b"data").unwrap();

        // Recover again
        let stats = manager.recover_from_crash().unwrap();
        assert_eq!(stats.wal_entries_found, 1);
    }
}
