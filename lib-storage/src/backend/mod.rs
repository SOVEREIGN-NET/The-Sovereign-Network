//! Storage backend implementations
//!
//! This module provides pluggable storage backends for structured data.
//! The primary implementation is SQLite for queryable metadata, contracts,
//! and audit logging.

#[cfg(feature = "sqlite")]
pub mod sqlite_backend;

#[cfg(feature = "sqlite")]
pub use sqlite_backend::SqliteBackend;
