//! Compatibility adapters for lib-identity
//!
//! This module provides adapters for migrating between different versions
//! of identity-related types and for interoperability with other crates
//! in the ZHTP ecosystem.
//!
//! # Available Adapters
//!
//! - [`ProofsSecretAdapter`](proofs_adapter::ProofsSecretAdapter): Converts
//!   between 32-byte cryptographic secrets and u64 values for lib-proofs
//!   compatibility.
//!
//! # Usage
//!
//! ```rust
//! use lib_identity::compat::ProofsSecretAdapter;
//!
//! // Convert 32-byte secret to u64
//! let secret: [u8; 32] = [1u8; 32];
//! let value = ProofsSecretAdapter::to_u64(&secret);
//!
//! // Convert u64 back to 32-byte secret
//! let restored = ProofsSecretAdapter::from_u64(value);
//! ```

pub mod proofs_adapter;
pub use proofs_adapter::ProofsSecretAdapter;
