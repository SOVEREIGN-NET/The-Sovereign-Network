//! Post-quantum encrypted peer-to-peer messaging.
//!
//! All encryption/decryption happens client-side. The server (node) is a
//! relay + temporary dead drop. QUIC is the only transport.
//!
//! Delivery model (BUBL / epic #2896): deposit first, peek on poll/inbound,
//! delete only on client ack or 48h TTL. Deposits are sled-durable.

pub mod envelope;
pub mod session;
pub mod ratchet;
pub mod deposit;
pub mod did_resolve;
pub mod metrics;
pub mod presence;
pub mod handler;
pub mod inbound_stream;
