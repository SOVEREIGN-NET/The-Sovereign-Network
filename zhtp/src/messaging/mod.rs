//! Post-quantum encrypted peer-to-peer messaging.
//!
//! All encryption/decryption happens client-side. The server (node) is a
//! relay + temporary dead drop. QUIC is the only transport.

pub mod envelope;
pub mod session;
pub mod ratchet;
pub mod deposit;
pub mod presence;
pub mod handler;
pub mod inbound_stream;
