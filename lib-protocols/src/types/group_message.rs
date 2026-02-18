//! Group messaging types (capped groups, epoch rekey)

use serde::{Deserialize, Serialize};

pub const DEFAULT_GROUP_CAP: usize = 16;
pub const MAX_GROUP_CAP: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMember {
    pub member_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupChange {
    Add(Vec<GroupMember>),
    Remove(Vec<GroupMember>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStateUpdate {
    pub group_id: GroupId,
    pub epoch: u64,
    pub admin_key: String,
    pub change: GroupChange,
    pub signed_payload: Vec<u8>,
    pub signature_algorithm: lib_crypto::types::SignatureAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    pub group_id: GroupId,
    pub epoch: u64,
    pub sender_device_id: String,
    pub ciphertext: Vec<u8>,
}

/// Derived epoch sender key (opaque bytes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEpochKey {
    pub epoch: u64,
    pub key_material: [u8; 32],
}
