//! Storage backend abstractions.
//!
//! This module defines the traits and enums for pluggable storage backends.

pub mod traits;

pub use traits::{BatchOp, StorageBackend};
