use crate::protocols::NetworkProtocol;
use crate::NodeId;

/// Mesh server configuration
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Node ID for this mesh node
    pub node_id: NodeId,
    /// Listen port (0 = no TCP port for pure mesh)
    pub listen_port: u16,
    /// Maximum peer connections
    pub max_peers: u32,
    /// Supported protocols
    pub protocols: Vec<NetworkProtocol>,
    /// Listen addresses (empty for pure mesh)
    pub listen_addresses: Vec<String>,
    /// Bootstrap peers for initial discovery
    pub bootstrap_peers: Vec<String>,
}
