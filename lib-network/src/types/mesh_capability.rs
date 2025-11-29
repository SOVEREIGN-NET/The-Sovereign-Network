use serde::{Deserialize, Serialize};
use crate::protocols::NetworkProtocol;

/// Mesh node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshCapability {
    /// Can provide routing and relay services
    MeshRelay { capacity_mbps: u32 },
    /// Can store data for the network
    DataStorage { capacity_gb: u32 },
    /// Can perform computations
    Computing { cpu_cores: u32, ram_gb: u32 },
    /// Long-range communication capability
    LongRangeComm { protocols: Vec<NetworkProtocol> },
    /// Content distribution
    ContentDistribution,
    /// ZK proof generation
    ZkProofGeneration,
}

/// Resources shared by a mesh node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedResources {
    /// Mesh relay bandwidth available (kbps)
    pub relay_bandwidth_kbps: u32,
    /// Storage space available (GB)
    pub storage_gb: u32,
    /// Compute power available (arbitrary units)
    pub compute_power: u32,
    /// Battery/power status (percentage)
    pub battery_percentage: Option<u8>,
    /// Uptime reliability score (0.0 to 1.0)
    pub reliability_score: f64,
}
