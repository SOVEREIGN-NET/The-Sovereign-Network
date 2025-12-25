//! ZHTP Protocol Suite
//!
//! Unified Handshake and Transport Protocol:
//! - ZHTP authentication with identity verification
//! - Post-quantum Kyber512 key exchange
//! - ChaCha20Poly1305 encryption with message-type domain separation
//! - ZHTP mesh encryption adapter with session context
//! - Cryptographic binding to peer identity

pub mod zhtp_auth;
pub mod zhtp_encryption;
pub mod zhtp_mesh_encryption;

// Re-exports for convenience
pub use self::zhtp_auth::*;
pub use self::zhtp_encryption::*;
pub use self::zhtp_mesh_encryption::*;
