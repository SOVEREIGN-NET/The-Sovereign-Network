use serde::{Deserialize, Serialize};

use crate::NodeId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtMessage {
    pub from: NodeId,
    pub kind: DhtMessageType,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DhtMessageType {
    Ping,
    Pong,
    Store,
    FindNode,
    FindValue,
}
