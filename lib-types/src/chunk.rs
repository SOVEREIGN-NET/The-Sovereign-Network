use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkMetadata {
    pub size: u64,
    pub checksum: [u8; 32],
}
