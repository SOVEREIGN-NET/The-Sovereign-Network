use serde::{Deserialize, Serialize};

use crate::NodeId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtNode {
    pub id: NodeId,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtPeerIdentity {
    pub node_id: NodeId,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: NodeId,
    pub status: PeerStatus,
    pub stats: PeerStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerStatus {
    Healthy,
    Unreachable,
    Banned,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerStats {
    pub last_seen: u64,
    pub failures: u32,
}
