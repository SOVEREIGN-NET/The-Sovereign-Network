//! Generic typed `Table` abstraction over `BlockchainStore` keyspaces.
//!
//! Blockchain-state-tiering epic, BST-101 (`docs/epics/blockchain-state-tiering-epic.md`).
//!
//! Before this, every persisted dataset needed its own bespoke
//! `get_X`/`put_X`/`delete_X`/`iter_X` quadruple on `BlockchainStore`, each
//! wired through the `SledStore` trees, the WAL, and migration code. A new
//! dataset is now a single `impl Table` declaration: it names a keyspace,
//! a key encoding, and a value type, and gets typed CRUD for free via the
//! `TableAccess` extension trait.
//!
//! The store side stays object-safe — `BlockchainStore` exposes only the
//! byte-level `get_raw`/`stage_raw`/`iter_raw` primitives, and `TableAccess`
//! layers the generic typed API on top with a blanket impl.

use super::{BlockchainStore, StorageError, StorageResult};

/// A typed, versioned key→value dataset backed by one storage keyspace.
pub trait Table {
    /// Stable on-disk keyspace name (a `SledStore` tree). Protocol — once a
    /// table ships, its `NAME` never changes.
    const NAME: &'static str;

    /// Schema version of `Value`. Bump on any incompatible change to the
    /// serialized form; drives the future per-table migration registry
    /// (BST-104). New tables start at `1`.
    const VERSION: u32;

    /// Logical key type. `?Sized` so `[u8]` / `str` keys work directly.
    type Key: ?Sized;

    /// Stored value — serialized with bincode.
    type Value: serde::Serialize + serde::de::DeserializeOwned;

    /// Encode a key to its on-disk byte form.
    fn encode_key(key: &Self::Key) -> Vec<u8>;
}

/// Typed CRUD over any [`BlockchainStore`], built on the object-safe
/// `*_raw` primitives. Blanket-implemented — callers just `use TableAccess`
/// and call `store.get::<SomeTable>(&key)`.
pub trait TableAccess {
    /// Read and decode the value for `key`.
    fn get<T: Table>(&self, key: &T::Key) -> StorageResult<Option<T::Value>>;

    /// Stage an insert of `value` for `key`. Must run within
    /// `begin_block`/`commit_block`; lands atomically with the block.
    fn stage<T: Table>(&self, key: &T::Key, value: &T::Value) -> StorageResult<()>;

    /// Stage a delete of `key`. Must run within `begin_block`/`commit_block`.
    fn stage_delete<T: Table>(&self, key: &T::Key) -> StorageResult<()>;

    /// Decode every `(raw_key, value)` pair in the table.
    fn iter<T: Table>(&self) -> StorageResult<Vec<(Vec<u8>, T::Value)>>;
}

impl<S: BlockchainStore + ?Sized> TableAccess for S {
    fn get<T: Table>(&self, key: &T::Key) -> StorageResult<Option<T::Value>> {
        match self.get_raw(T::NAME, &T::encode_key(key))? {
            Some(bytes) => Ok(Some(decode::<T>(&bytes)?)),
            None => Ok(None),
        }
    }

    fn stage<T: Table>(&self, key: &T::Key, value: &T::Value) -> StorageResult<()> {
        let bytes =
            bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.stage_raw(T::NAME, &T::encode_key(key), Some(&bytes))
    }

    fn stage_delete<T: Table>(&self, key: &T::Key) -> StorageResult<()> {
        self.stage_raw(T::NAME, &T::encode_key(key), None)
    }

    fn iter<T: Table>(&self) -> StorageResult<Vec<(Vec<u8>, T::Value)>> {
        let mut out = Vec::new();
        for entry in self.iter_raw(T::NAME)? {
            let (raw_key, raw_value) = entry?;
            out.push((raw_key, decode::<T>(&raw_value)?));
        }
        Ok(out)
    }
}

fn decode<T: Table>(bytes: &[u8]) -> StorageResult<T::Value> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
