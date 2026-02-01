//! Identity payloads (opaque to network, used by clients)

use serde::{Deserialize, Serialize};

use super::{
    IdentityMessageKind,
    DeliveryReceipt,
    ReadReceipt,
    GroupStateUpdate,
};

/// Opaque payload embedded inside encrypted device payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPayload {
    pub kind: IdentityMessageKind,
    pub body: Vec<u8>,
}

impl IdentityPayload {
    pub fn user_message(body: Vec<u8>) -> Self {
        Self {
            kind: IdentityMessageKind::UserMessage,
            body,
        }
    }

    pub fn control_message(kind: super::ControlMessageType, body: Vec<u8>) -> Self {
        Self {
            kind: IdentityMessageKind::Control(kind),
            body,
        }
    }

    pub fn delivery_receipt(receipt: &DeliveryReceipt) -> Result<Self, String> {
        let body = bincode::serialize(receipt)
            .map_err(|e| format!("Failed to serialize delivery receipt: {}", e))?;
        Ok(Self {
            kind: IdentityMessageKind::Receipt(super::ReceiptType::Delivery),
            body,
        })
    }

    pub fn read_receipt(receipt: &ReadReceipt) -> Result<Self, String> {
        let body = bincode::serialize(receipt)
            .map_err(|e| format!("Failed to serialize read receipt: {}", e))?;
        Ok(Self {
            kind: IdentityMessageKind::Receipt(super::ReceiptType::Read),
            body,
        })
    }

    pub fn group_state_update(update: &GroupStateUpdate) -> Result<Self, String> {
        let body = bincode::serialize(update)
            .map_err(|e| format!("Failed to serialize group update: {}", e))?;
        Ok(Self {
            kind: IdentityMessageKind::GroupStateUpdate,
            body,
        })
    }
}
