use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;

/// DAO entry stored in the registry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAOEntry {
    pub dao_id: [u8; 32],
    pub token_addr: [u8; 32],
    pub class: String,
    pub metadata_hash: Option<[u8; 32]>,
    pub treasury: PublicKey,
    pub owner: PublicKey,
    pub created_at: u64,
}

/// Metadata view returned by queries
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAOMetadata {
    pub dao_id: [u8; 32],
    pub token_addr: [u8; 32],
    pub class: String,
    pub metadata_hash: Option<[u8; 32]>,
    pub treasury: PublicKey,
    pub owner: PublicKey,
    pub created_at: u64,
}
