//! ZHTP Client - Authenticated QUIC transport for all control-plane operations
//!
//! This is the single transport layer for all CLI commands. All mutating operations
//! (identity creation, domain registration, wallet transfers, etc.) MUST use this
//! authenticated QUIC transport.
//!
//! # Architecture
//!
//! ```text
//! CLI Command
//!     ↓
//! ZhtpClient (authenticated QUIC)
//!     ↓
//! QUIC + UHP v2 handshake
//!     ↓
//! Node API handlers
//! ```
//!
//! # Security Model
//!
//! - QUIC provides transport encryption (TLS 1.3)
//! - UHP provides mutual authentication (Dilithium signatures)
//! - UHP v2 provides post-quantum key exchange (Kyber1024)
//! - AuthContext binds each request to the authenticated session
//!
//! HTTP is NOT allowed for control-plane operations.

#[cfg(feature = "quic")]
mod zhtp_client;

#[cfg(feature = "quic")]
pub use zhtp_client::{ZhtpClient, ZhtpClientConfig};
