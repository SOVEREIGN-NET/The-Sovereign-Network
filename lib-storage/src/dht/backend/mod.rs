//! Storage backend trait for DhtStorage
//!
//! Provides abstraction over different storage implementations (in-memory HashMap,
//! persistent sled, etc.). This enables DhtStorage to work with various backends
//! without knowing implementation details.
//!
//! # Design
//!
//! - **Byte-level interface**: Works with `&[u8]` keys and values for flexibility
//! - **Sync operations**: All methods are synchronous (async conversion at DhtStorage level)
//! - **Clone semantics**: Backends are cheaply cloneable (wrapped in Arc where needed)
//! - **Previous value tracking**: Put/remove return previous values for usage tracking
//!
//! # Implementations
//!
//! - `HashMapBackend`: In-memory, suitable for testing and development
//! - `SledBackend`: Persistent, suitable for production

pub mod memory;
pub mod sled_backend;

#[cfg(test)]
pub mod tests;

use anyhow::Result;
use std::fmt;

pub use memory::HashMapBackend;
pub use sled_backend::SledBackend;

/// Storage backend trait
///
/// Abstracts over different storage mechanisms (HashMap, sled, etc.)
/// All implementations must be thread-safe (Send + Sync) and cheaply cloneable.
///
/// # Clone Semantics
///
/// The Clone trait is required for flexibility in async contexts and testing.
/// **Implementations must make Clone cheap** (typically O(1) via Arc wrapping)
/// since clones happen frequently throughout the codebase. Cloning should not
/// duplicate the underlying storage, only create a new handle to it.
pub trait StorageBackend: Send + Sync + Clone + fmt::Debug {
    /// Insert or update a key-value pair
    ///
    /// Returns the previous value if the key existed.
    /// Must be atomic (no partial updates on failure).
    ///
    /// # Arguments
    /// - `key`: Byte string key
    /// - `value`: Byte string value
    ///
    /// # Returns
    /// - `Ok(Some(prev_value))`: Key existed, returning old value
    /// - `Ok(None)`: Key is new
    /// - `Err(e)`: Storage error
    fn put(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Retrieve a value by key
    ///
    /// # Arguments
    /// - `key`: Byte string key
    ///
    /// # Returns
    /// - `Ok(Some(value))`: Key found with value
    /// - `Ok(None)`: Key not found
    /// - `Err(e)`: Storage error
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Remove a key-value pair
    ///
    /// Returns the removed value if the key existed.
    ///
    /// # Arguments
    /// - `key`: Byte string key
    ///
    /// # Returns
    /// - `Ok(Some(prev_value))`: Key existed, returning removed value
    /// - `Ok(None)`: Key didn't exist
    /// - `Err(e)`: Storage error
    fn remove(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Check if a key exists
    ///
    /// # Arguments
    /// - `key`: Byte string key
    ///
    /// # Returns
    /// - `Ok(true)`: Key exists
    /// - `Ok(false)`: Key doesn't exist
    /// - `Err(e)`: Storage error
    fn contains_key(&self, key: &[u8]) -> Result<bool>;

    /// Iterate over all keys
    ///
    /// Returns a vector of all keys in the backend.
    /// For large backends, this may be expensive.
    ///
    /// # Returns
    /// - `Ok(keys)`: Vector of all keys
    /// - `Err(e)`: Storage error
    fn keys(&self) -> Result<Vec<Vec<u8>>>;

    /// Get all keys matching a prefix
    ///
    /// Returns a vector of all keys that start with the given prefix.
    ///
    /// # Arguments
    /// - `prefix`: Byte string prefix
    ///
    /// # Returns
    /// - `Ok(keys)`: Vector of matching keys
    /// - `Err(e)`: Storage error
    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>>;

    /// Flush pending writes to durable storage
    ///
    /// For in-memory backends, this is a no-op.
    /// For persistent backends, this ensures data is written to disk.
    ///
    /// # Returns
    /// - `Ok(())`: Flush successful
    /// - `Err(e)`: Flush failed
    fn flush(&self) -> Result<()>;

    /// Get number of entries in storage
    ///
    /// # Performance Warning
    ///
    /// This operation may be O(n) for some backends (e.g., SledBackend iterates
    /// through all entries). Use sparingly in hot paths. Consider maintaining
    /// a separate counter in DhtStorage if frequent len() calls are needed.
    ///
    /// # Returns
    /// - `Ok(count)`: Number of key-value pairs
    /// - `Err(e)`: Storage error
    fn len(&self) -> Result<usize>;

    /// Check if storage is empty
    ///
    /// Default implementation uses len().
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Get backend type name for debugging/logging
    ///
    /// # Returns
    /// Short string identifying backend type (e.g., "memory", "sled")
    fn backend_type(&self) -> &'static str;

    /// Clear all entries (for testing)
    ///
    /// # Returns
    /// - `Ok(())`: Clear successful
    /// - `Err(e)`: Clear failed
    #[cfg(test)]
    fn clear(&self) -> Result<()>;
}
