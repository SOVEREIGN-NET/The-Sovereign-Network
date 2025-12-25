//! LoRaWAN Protocol Suite
//!
//! Wide-area network protocol with post-quantum encryption support:
//! - LoRaWAN frame handling
//! - ChaCha20Poly1305 encryption with frame counter domain separation
//! - HKDF key derivation for frame keys

pub mod gateway_auth;
pub mod lorawan;
pub mod lorawan_encryption;

// Re-exports for convenience
pub use self::lorawan::*;
pub use self::lorawan_encryption::LoRaWANEncryption;
pub use self::gateway_auth::{GatewayAttestation, LoRaDeviceMessage, LoRaWANGatewayAuth, LoRaWanUhpBinding};
