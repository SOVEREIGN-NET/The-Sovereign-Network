//! Storage backend abstraction layer
//!
//! This module provides a unified interface for persistent key-value storage,
//! allowing different backend implementations (sled, SQLite, etc.) to be used
//! interchangeably.
//!
//! # Architecture
//!
//! - [`StorageBackend`]: Core trait defining key-value operations
//! - [`SledBackend`]: Production-ready sled-based implementation for hot KV data
//! - [`SqliteBackend`]: SQLite-based implementation for structured queryable data
//! - [`BatchOp`]: Batch operation types for atomic writes
//!
//! # Use Cases
//!
//! - DHT routing tables (sled)
//! - Peer cache (sled)
//! - Nonce tracking (sled)
//! - Metadata and contracts (SQLite)
//! - Audit logging (SQLite)

pub mod traits;
mod sled_backend;

#[cfg(feature = "sqlite")]
pub mod sqlite_backend;

pub use traits::{BackendStats, StorageKey};
pub use sled_backend::{SledBackend, SledTree, BatchOp, StorageBackend, StorageError, Result};

#[cfg(feature = "sqlite")]
pub use sqlite_backend::SqliteBackend;
