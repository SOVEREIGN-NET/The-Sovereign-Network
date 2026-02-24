//! ZHTP Mesh Protocol - Decentralized Network Communication
//! 
//! This package implements peer-to-peer mesh networking protocol for direct
//! device communication without relying on traditional infrastructure. Features:
//! 
//! - Direct peer-to-peer mesh networking through multiple protocols
//! - Long-range communication via LoRaWAN, WiFi Direct, and Bluetooth LE
//! - Economic incentives for mesh participation and resource sharing
//! - Zero-knowledge privacy for all communications
//! - Post-quantum cryptographic security
//! - Native ZHTP protocol (not HTTP) designed for mesh networks
//! - DHT client layer that uses lib-storage as the DHT implementation backend

// Issue #739: TLS certificate pinning is now implemented via discovery cache.
// Re-enable the compile-time safety block to prevent unsafe-bootstrap in release.
#[cfg(all(not(debug_assertions), feature = "unsafe-bootstrap"))]
compile_error!("unsafe-bootstrap must not be enabled in release builds - use TLS certificate pinning via discovery cache (Issue #739)");

// Re-exports for external use (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::mesh::server::ZhtpMeshServer;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::mesh::connection::MeshConnection;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::mesh::statistics::MeshProtocolStats;
pub use crate::types::*;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::discovery::*;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::relays::*;

// Unified Peer Identity System (replaces separate NodeId, PeerId, PublicKey systems)
pub use crate::identity::{UnifiedPeerId, PeerIdMapper, PeerMapperConfig};

// Unified Peer Registry (single source of truth for all peer data)
pub use crate::peer_registry::{
    PeerRegistry, PeerEntry, SharedPeerRegistry, new_shared_registry,
    PeerEndpoint, ConnectionMetrics, NodeCapabilities, GeographicLocation,
    DhtPeerInfo, DiscoveryMethod, PeerTier, RegistryStats,
    // New security features
    RegistryConfig, DEFAULT_MAX_PEERS, DEFAULT_PEER_TTL_SECS,
};

// Peer Reputation System (Byzantine fault handling - Gap 6)
pub use crate::peer_reputation::{
    PeerReputation, PeerReputationManager, ReputationEvent,
};
pub use crate::identity_store_forward::{IdentityStoreForward, IdentityQueueStats};

// Unified Handshake Protocol exports (always available)
// NOTE: NodeIdentity is a lightweight version containing only public fields from ZhtpIdentity
pub use lib_identity::{ZhtpIdentity, types::NodeId};
pub use crate::handshake::{
    NodeIdentity, HandshakeCapabilities, NegotiatedCapabilities,
    HandshakeMessage, HandshakePayload, ClientHello, ServerHello, ClientFinish,
    ProvisionalHello, ChallengeResponse, ChallengeProof,
    HandshakeResult, HandshakeError, HandshakeErrorMessage,
    UHP_VERSION, UHP_VERSION_STRING, MIN_SUPPORTED_VERSION,
};

// Unified protocol encryption module (always available)
pub use crate::encryption::{
    ProtocolEncryption, ChaCha20Poly1305Encryption,
    EncryptionStats, create_encryption,
};

// Consensus message encryption (always available)
pub use crate::consensus_encryption::{
    ConsensusAead, RoleDirection,
};

// Consensus message broadcaster for validator communication (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::message_broadcaster::{
    MessageBroadcaster, MeshMessageBroadcaster, MockMessageBroadcaster,
    BroadcastResult,
};

// Consensus receiver (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::consensus_receiver::{
    ConsensusReceiver, ReceivedConsensusMessage,
};

// Validator discovery gossip transport (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::validator_discovery_transport::MeshValidatorDiscoveryTransport;

// Network utilities
pub mod network_utils;
pub use crate::network_utils::{get_local_ip, get_local_ip_with_config, LocalIpConfig};


// Core modules (always available)
pub mod types;
pub mod identity; // Unified peer identity system
pub mod peer_registry; // Unified peer registry (single source of truth)
pub mod peer_reputation; // Peer reputation system for Byzantine fault handling (Gap 6)
pub mod handshake; // Unified Handshake Protocol (UHP)
pub mod encryption; // Unified protocol encryption
pub mod consensus_encryption; // Consensus message encryption (Gap 1.3)
pub mod constants; // Protocol constants

// Modules that require transport features (quic, mdns, lorawan)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod mesh;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod messaging;
pub mod identity_store_forward;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod discovery;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod relays;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod routing;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use crate::routing::message_routing::MeshRoutingEvent;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod protocols;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod bootstrap;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod client; // Authenticated QUIC client for control-plane operations
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod message_broadcaster; // Consensus message broadcaster trait
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod consensus_receiver; // Consensus receiver (Gap 4: ingress boundary)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod validator_discovery_transport; // Mesh-based validator discovery gossip transport
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod monitoring;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod zk_integration;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod testing;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod platform;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod socket_utils;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod transport;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod dht_stub;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod dht;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod web4;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod fragmentation_v2; // Protocol-grade message fragmentation (session-scoped, versioned)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
mod blockchain_sync_stub;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod storage_stub;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub mod network_output;
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub use network_output::{NetworkOutput, OutputQueue, global_output_queue};

#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
#[cfg(not(feature = "chain-integration"))]
pub mod blockchain_sync {
    pub use crate::blockchain_sync_stub::*;
}
#[cfg(feature = "chain-integration")]
compile_error!("chain-integration is disabled in lib-network while storage/blockchain relocation is pending (Phase 4). Use stub or move integration to zhtp.");
// Storage/chain-dependent modules removed from lib-network

// Re-export protocol constants for convenience
pub use constants::*;

// Mobile FFI bindings removed - see archive/mobile-ffi-stubs branch when needed

// External dependencies for economics and API
pub use lib_economy as economics;
pub use lib_protocols as api;
pub use lib_identity;

/// Get active peer count from the mesh network (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub async fn get_active_peer_count() -> Result<usize> {
    // Get peer count from mesh statistics
    let stats = crate::mesh::statistics::get_mesh_statistics().await?;
    Ok(stats.active_peers as usize)
}

/// Get network statistics from the mesh (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub async fn get_network_statistics() -> Result<NetworkStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;

    Ok(NetworkStatistics {
        bytes_sent: mesh_stats.bytes_sent,
        bytes_received: mesh_stats.bytes_received,
        packets_sent: mesh_stats.packets_sent,
        packets_received: mesh_stats.packets_received,
        peer_count: mesh_stats.active_peers as usize,
        connection_count: mesh_stats.active_connections as usize,
    })
}

/// Get mesh status information (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub async fn get_mesh_status() -> Result<MeshStatus> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    let discovery_stats = crate::discovery::get_discovery_statistics().await?;

    Ok(MeshStatus {
        internet_connected: mesh_stats.internet_connectivity,
        mesh_connected: mesh_stats.mesh_connectivity,
        connectivity_percentage: mesh_stats.connectivity_percentage,
        relay_connectivity: mesh_stats.relay_connectivity,
        active_peers: mesh_stats.active_peers,
        local_peers: discovery_stats.local_peers,
        regional_peers: discovery_stats.regional_peers,
        global_peers: discovery_stats.global_peers,
        relay_peers: discovery_stats.relay_peers,
        churn_rate: mesh_stats.churn_rate,
        coverage: mesh_stats.coverage,
        redundancy: mesh_stats.redundancy,
        stability: mesh_stats.stability,
        protocol_health: mesh_stats.protocol_health,
    })
}

/// Get bandwidth statistics from the mesh (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub async fn get_bandwidth_statistics() -> Result<BandwidthStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;

    Ok(BandwidthStatistics {
        upload_utilization: mesh_stats.upload_utilization,
        download_utilization: mesh_stats.download_utilization,
        efficiency: mesh_stats.bandwidth_efficiency,
        congestion_level: mesh_stats.congestion_level,
    })
}

/// Get latency statistics from the mesh (transport-dependent)
#[cfg(any(feature = "quic", feature = "mdns", feature = "lorawan", feature = "full"))]
pub async fn get_latency_statistics() -> Result<LatencyStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;

    Ok(LatencyStatistics {
        average_latency: mesh_stats.average_latency,
        variance: mesh_stats.latency_variance,
        timeout_rate: mesh_stats.timeout_rate,
        jitter: mesh_stats.jitter,
    })
}

// Constants
pub const ZHTP_DEFAULT_PORT: u16 = 9333;
pub const ZHTP_PROTOCOL_VERSION: &str = "1.0";
pub const ZHTP_MAX_PACKET_SIZE: usize = 8192;
pub const ZHTP_MESH_DISCOVERY_TIMEOUT_MS: u64 = 10000;
pub const ZHTP_BOOTSTRAP_TIMEOUT_MS: u64 = 5000;

// Error types
pub use anyhow::{Result, Error};

// External dependencies re-exports
pub use serde::{Deserialize, Serialize};
pub use tokio;
pub use uuid::Uuid;
