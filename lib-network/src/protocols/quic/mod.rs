//! QUIC Mesh Protocol Suite
//!
//! Modern transport with post-quantum cryptography:
//! - QUIC connection handling with UHP+Kyber authentication
//! - Application-level ChaCha20Poly1305 encryption on top of TLS 1.3
//! - UHP handshake protocol with Dilithium signatures
//! - Kyber key exchange for quantum resistance
//! - Web4 API dispatcher for HTTPS tunneling

pub mod quic_mesh;
pub mod quic_encryption;
pub mod quic_handshake;
pub mod quic_api_dispatcher;

// Re-exports for convenience
pub use self::quic_mesh::{QuicMeshProtocol, PqcQuicConnection};
pub use self::quic_encryption::QuicApplicationEncryption;
pub use self::quic_handshake::*;
pub use self::quic_api_dispatcher::*;
