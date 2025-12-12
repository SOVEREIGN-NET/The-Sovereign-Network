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

// Re-exports for external use
// Force rebuild
pub use crate::mesh::server::ZhtpMeshServer;
pub use crate::mesh::connection::MeshConnection;
pub use crate::mesh::statistics::MeshProtocolStats;
pub use crate::types::*;
pub use crate::discovery::*;
pub use crate::relays::*;
pub use crate::blockchain_sync::{BlockchainSyncManager, EdgeNodeSyncManager};

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

// Unified Handshake Protocol exports
// NOTE: NodeIdentity is a lightweight version containing only public fields from ZhtpIdentity
pub use lib_identity::{ZhtpIdentity, types::NodeId};
pub use crate::handshake::{
    NodeIdentity, HandshakeCapabilities, NegotiatedCapabilities,
    HandshakeMessage, HandshakePayload, ClientHello, ServerHello, ClientFinish,
    ProvisionalHello, ChallengeResponse, ChallengeProof,
    HandshakeResult, HandshakeError, HandshakeErrorMessage,
    UHP_VERSION, UHP_VERSION_STRING, MIN_SUPPORTED_VERSION,
};


// Native binary DHT protocol with lib-storage backend
// DHT client layer is deprecated; kept temporarily for compatibility
pub use crate::dht::{initialize_dht_client, ZkDHTIntegration, DHTNetworkStatus, DHTClient};

// Network utilities
pub mod network_utils;

// Web4 domain registry and content publishing
pub use crate::web4::{Web4Manager, DomainRegistry, ContentPublisher, initialize_web4_system, initialize_web4_system_with_storage};

// Core modules
pub mod types;
pub mod mesh;
pub mod messaging;
pub mod discovery;
pub mod relays;

pub mod routing;
pub mod protocols;
pub mod bootstrap;
pub mod identity; // Unified peer identity system
pub mod peer_registry; // Unified peer registry (single source of truth)
pub mod handshake; // Unified Handshake Protocol (UHP)
pub mod constants; // Protocol constants
pub mod monitoring;
pub mod zk_integration;
pub mod testing;
pub mod platform;
pub mod dht; // Native binary DHT protocol with lib-storage backend
pub mod web4; // Web4 domain registry and content publishing
pub mod blockchain_sync; // Blockchain synchronization over mesh protocols

// Re-export protocol constants for convenience
pub use constants::*;

// Mobile FFI bindings for Android (JNI) and iOS (C FFI)
// Available for all platforms to allow compilation, but only functional on mobile
pub mod mobile;

// External dependencies for economics, API, and storage
pub use lib_economy as economics;
pub use lib_protocols as api;
pub use lib_storage; // Direct access to storage backend
pub use lib_identity;
use crate::dht::serve_web4_page;

// Public API convenience functions
pub use crate::testing::test_utils::create_test_mesh_server;

/// Get active peer count from the mesh network
pub async fn get_active_peer_count() -> Result<usize> {
    // Get peer count from mesh statistics
    let stats = crate::mesh::statistics::get_mesh_statistics().await?;
    Ok(stats.active_peers as usize)
}

/// Get network statistics from the mesh
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

/// Get mesh status information
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

/// Get bandwidth statistics from the mesh
pub async fn get_bandwidth_statistics() -> Result<BandwidthStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    
    Ok(BandwidthStatistics {
        upload_utilization: mesh_stats.upload_utilization,
        download_utilization: mesh_stats.download_utilization,
        efficiency: mesh_stats.bandwidth_efficiency,
        congestion_level: mesh_stats.congestion_level,
    })
}

/// Get latency statistics from the mesh
pub async fn get_latency_statistics() -> Result<LatencyStatistics> {
    let mesh_stats = crate::mesh::statistics::get_mesh_statistics().await?;
    
    Ok(LatencyStatistics {
        average_latency: mesh_stats.average_latency,
        variance: mesh_stats.latency_variance,
        timeout_rate: mesh_stats.timeout_rate,
        jitter: mesh_stats.jitter,
    })
}

/// Initialize complete mesh network with DHT client integration
pub async fn initialize_mesh_with_dht(identity: lib_identity::ZhtpIdentity) -> Result<(ZhtpMeshServer, ())> {
    info!("Initializing complete mesh network with DHT integration...");
    
    // Initialize mesh server
    let mesh_server = crate::testing::test_utils::create_test_mesh_server().await?;
    
    // Initialize DHT client with lib-storage backend
    let _ = initialize_dht_client(identity).await?;
    
    info!("Mesh network with DHT client integration ready");
    Ok((mesh_server, ()))
}

/// Serve a Web4 page through the integrated mesh network and DHT
pub async fn serve_web4_page_through_mesh(
    url: &str
) -> Result<String> {
    info!("Serving Web4 page through integrated mesh+DHT: {}", url);
    
    // Parse URL to get domain and path
    let parts: Vec<&str> = url.split('/').collect();
    let domain = parts.get(0).unwrap_or(&"");
    let path = if parts.len() > 1 { parts[1..].join("/") } else { String::new() };
    
    // Use the DHT client to serve the page through lib-storage backend
    serve_web4_page(domain, &path).await
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

use tracing::info;
