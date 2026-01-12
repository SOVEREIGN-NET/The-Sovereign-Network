//! Storage backend implementations
//!
//! This module provides pluggable storage backends for structured data.
//! The primary implementation is SQLite for queryable metadata, contracts,
//! and audit logging.

pub mod traits;

#[cfg(feature = "sqlite")]
pub mod sqlite_backend;

pub use traits::{BackendStats, BatchOp, StorageBackend, StorageKey};

#[cfg(feature = "sqlite")]
pub use sqlite_backend::SqliteBackend;
