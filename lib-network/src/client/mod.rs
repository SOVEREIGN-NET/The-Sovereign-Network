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
//! QUIC + UHP + Kyber handshake
//!     ↓
//! Node API handlers
//! ```
//!
//! # Security Model
//!
//! - QUIC provides transport encryption (TLS 1.3)
//! - UHP provides mutual authentication (Dilithium signatures)
//! - Kyber provides post-quantum key exchange
//! - AuthContext binds each request to the authenticated session
//!
//! HTTP is NOT allowed for control-plane operations.

mod zhtp_client;

pub use zhtp_client::{ZhtpClient, ZhtpClientConfig};
