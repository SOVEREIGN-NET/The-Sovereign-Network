//! Proof of Useful Work (PoUW) stamp for per-message anti-spam

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUwStamp {
    pub sender_device_key_id: [u8; 32],
    pub challenge: Vec<u8>,
    pub message_hash: [u8; 32],
    pub stamp_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub signature_algorithm: lib_crypto::types::SignatureAlgorithm,
}
