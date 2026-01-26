use blake3::Hash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub const LENGTH: usize = 32;

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<Hash> for NodeId {
    fn from(h: Hash) -> Self {
        NodeId(*h.as_bytes())
    }
}
