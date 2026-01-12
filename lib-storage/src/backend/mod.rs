//! Storage backend abstraction layer
//!
//! This module provides a unified interface for persistent key-value storage,
//! allowing different backend implementations (sled, RocksDB, etc.) to be used
//! interchangeably.
//!
//! # Architecture
//!
//! - [`StorageBackend`]: Core trait defining key-value operations
//! - [`SledBackend`]: Production-ready sled-based implementation
//! - [`SledTree`]: Namespaced tree for logical data separation
//! - [`BatchOp`]: Batch operation types for atomic writes
//!
//! # Use Cases
//!
//! - DHT routing tables
//! - Peer cache
//! - Nonce tracking
//! - Hot key-value data

mod sled_backend;

pub use sled_backend::{SledBackend, SledTree, BatchOp, StorageBackend, StorageError, Result};
