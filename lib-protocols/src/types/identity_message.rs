//! Identity messaging types (per-device fan-out)

use serde::{Deserialize, Serialize};

/// TTL for identity messages
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageTtl {
    NoStore,
    Hours24,
    Days7,
    Days30,
}

impl MessageTtl {
    pub fn as_seconds(self) -> u64 {
        match self {
            MessageTtl::NoStore => 0,
            MessageTtl::Hours24 => 24 * 60 * 60,
            MessageTtl::Days7 => 7 * 24 * 60 * 60,
            MessageTtl::Days30 => 30 * 24 * 60 * 60,
        }
    }
}

/// Encrypted payload for a specific recipient device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePayload {
    pub device_id: String,
    pub ciphertext: Vec<u8>,
}

/// Envelope for per-device encrypted payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEnvelope {
    pub message_id: u64,
    pub sender_did: String,
    pub recipient_did: String,
    pub created_at: u64,
    pub ttl: MessageTtl,
    pub retain_until_ttl: bool,
    pub pouw_stamp: Option<crate::types::PoUwStamp>,
    pub payloads: Vec<DevicePayload>,
}

/// Sealed-sender envelope for next-hop routing (Phase 4 baseline)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSenderEnvelope {
    pub next_hop: String,
    pub ciphertext: Vec<u8>,
    pub padding_len: u32,
}

/// Message kinds (intended to be inside encrypted payloads)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityMessageKind {
    UserMessage,
    Control(ControlMessageType),
    Receipt(ReceiptType),
    GroupStateUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlMessageType {
    DeviceAdd,
    DeviceRemove,
    GroupUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptType {
    Delivery,
    Read,
}

/// Delivery receipt payload (to be encrypted end-to-end)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub message_id: u64,
    pub device_id: String,
    pub delivered_at: u64,
    pub signature: Vec<u8>,
    pub signature_algorithm: lib_crypto::types::SignatureAlgorithm,
}

/// Read receipt payload (to be encrypted end-to-end)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadReceipt {
    pub message_id: u64,
    pub device_id: String,
    pub read_at: u64,
    pub signature: Vec<u8>,
    pub signature_algorithm: lib_crypto::types::SignatureAlgorithm,
}
