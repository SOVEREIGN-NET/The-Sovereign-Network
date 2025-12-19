use crate::NodeId;

pub trait DhtTransport: Send + Sync {
    fn send(&self, to: NodeId, data: Vec<u8>) -> Result<(), TransportError>;
}

#[derive(Debug)]
pub enum TransportError {
    Unreachable,
    Timeout,
    Other(String),
}
