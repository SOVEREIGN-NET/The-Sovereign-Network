//! DHT Enhanced Bootstrap Extensions  
//! 
//! Extends existing lib-network bootstrap with DHT-specific enhancements:
//! - mDNS local network discovery
//! - Peer exchange protocols
//! - DHT-optimized peer scoring
//!
//! **MIGRATION (Ticket #150):** Now uses unified peer_registry instead of
//! maintaining separate discovered_peers Vec. Peers are immediately visible
//! to DHT and mesh components.

use anyhow::Result;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tracing::{info, debug};
use rand::RngCore;

// Import DHT protocol types

// Re-export existing bootstrap functionality
pub use crate::bootstrap::{discover_bootstrap_peers, PeerInfo};

// Import peer registry (Ticket #150)
use crate::peer_registry::SharedPeerRegistry;
use crate::peer_registry::SharedPeerRegistry;

/// ZHTP service information from mDNS discovery
#[derive(Debug, Clone)]
struct ZhtpServiceInfo {
    name: String,
    host: String,
    port: u16,
    txt_properties: std::collections::HashMap<String, String>,
}

impl ZhtpServiceInfo {
    /// Check if this service is a router (Group Owner)
    fn is_router(&self) -> bool {
        self.txt_properties.get("device_type")
            .map(|t| t == "router")
            .unwrap_or_else(|| {
                // Fallback: check group_owner flag
                self.txt_properties.get("group_owner")
                    .and_then(|v| v.parse::<bool>().ok())
                    .unwrap_or(false)
            })
    }
    
    /// Check if this service is a client
    fn is_client(&self) -> bool {
        !self.is_router()
    }
    
    /// Get node ID if available
    fn node_id(&self) -> Option<String> {
        self.txt_properties.get("node_id").cloned()
    }
}

/// DHT-specific bootstrap enhancements configuration
#[derive(Debug, Clone)]
pub struct DHTBootstrapEnhancements {
    /// Enable mDNS local discovery
    pub enable_mdns: bool,
    /// Enable peer exchange protocol
    pub enable_peer_exchange: bool,
    /// mDNS discovery timeout
    pub mdns_timeout: Duration,
    /// Max peers from mDNS
    pub max_mdns_peers: usize,
}

impl Default for DHTBootstrapEnhancements {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_peer_exchange: true,
            mdns_timeout: Duration::from_secs(5),
            max_mdns_peers: 10,
        }
    }
}

/// Enhanced bootstrap manager that extends existing functionality
/// 
/// **MIGRATION (Ticket #150):** Removed discovered_peers Vec, now uses unified peer_registry
pub struct DHTBootstrap {
    enhancements: DHTBootstrapEnhancements,
    last_discovery: SystemTime,
    local_identity: lib_identity::ZhtpIdentity,
}

impl DHTBootstrap {
    pub fn new(enhancements: DHTBootstrapEnhancements, local_identity: lib_identity::ZhtpIdentity) -> Self {
        Self {
            enhancements,
            last_discovery: SystemTime::UNIX_EPOCH,
            local_identity,
        }
    }

    /// Enhance existing bootstrap with DHT-specific features
    /// 
    /// **MIGRATION (Ticket #150):** Now accepts peer_registry parameter and returns peer count
    /// instead of Vec<String>. Discovered peers are directly added to registry.
    pub async fn enhance_bootstrap(
        &mut self,
        bootstrap_nodes: &[String],
        peer_registry: SharedPeerRegistry,
    ) -> Result<usize> {
        info!(" Enhancing bootstrap with DHT features...");
        
        let mut total_discovered = 0;
        
        // 1. Use existing bootstrap system first (peers added directly to registry)
        let bootstrap_count = discover_bootstrap_peers(bootstrap_nodes, &self.local_identity, peer_registry.clone()).await?;
        total_discovered += bootstrap_count;
        info!(" Discovered {} peers via bootstrap", bootstrap_count);
        
        // 2. DHT Enhancement: Local network discovery via mDNS
        if self.enhancements.enable_mdns {
            let mdns_count = self.discover_local_peers(peer_registry.clone()).await?;
            total_discovered += mdns_count;
            info!(" Discovered {} peers via mDNS", mdns_count);
        }
        
        // 3. DHT Enhancement: Peer exchange
        if self.enhancements.enable_peer_exchange && total_discovered > 0 {
            let exchange_count = self.exchange_peers(peer_registry.clone()).await?;
            total_discovered += exchange_count;
            info!(" Discovered {} peers via peer exchange", exchange_count);
        }
        
        self.last_discovery = SystemTime::now();
        
        info!(" Enhanced bootstrap completed, found {} total peers", total_discovered);
        Ok(total_discovered)
    }

    /// DHT Enhancement: Discover local network peers via mDNS
    /// 
    /// **MIGRATION (Ticket #150):** Now accepts peer_registry and returns count
    async fn discover_local_peers(&self, peer_registry: SharedPeerRegistry) -> Result<usize> {
        info!("mDNS: Discovering local ZHTP peers...");
        
        let mut discovered_count = 0;
        
        // Enhanced peer discovery: mDNS + targeted port scanning
        let timeout = tokio::time::timeout(self.enhancements.mdns_timeout, async {
            info!("Starting comprehensive ZHTP peer discovery...");
            
            let mut count = 0;
            
            // Phase 1: mDNS service discovery for _zhtp._tcp.local
            if let Ok(mdns_peers) = self.discover_mdns_services().await {
                for peer_address in mdns_peers {
                    if let Ok(true) = self.ping_peer(&peer_address).await {
                        info!(" mDNS + Protocol validated peer: {}", peer_address);
                        
                        // Note: mDNS discovery is DHT enhancement layer
                        // To add to registry, needs full handshake via connect_to_bootstrap_peer()
                        // which creates complete PeerInfo with DID, NodeId, capabilities
                        // Current mDNS just validates peer exists - full connection happens later
                        count += 1;
                        
                        if count >= self.enhancements.max_mdns_peers {
                            return Ok::<usize, anyhow::Error>(count);
                        }
                    }
                }
            }
            
            // No localhost fallback scanning - use only peer discovery via mDNS
            debug!(" peer discovery complete - no localhost simulation used");
            
            // ZHTP protocol discovery complete
            // Future enhancement: Add multicast DNS for:
            // - Service registration (_zhtp._tcp.local)
            // - Network-wide peer announcements
            // - Automatic peer discovery across subnets
            
            Ok::<usize, anyhow::Error>(count)
        });
        
        match timeout.await {
            Ok(Ok(count)) => {
                discovered_count = count;
                info!("mDNS discovery found {} local peers", count);
                Ok(count)
            }
            Ok(Err(e)) => {
                debug!("mDNS discovery error: {}", e);
                Ok(0)
            }
            Err(_) => {
                debug!("mDNS discovery timeout");
                Ok(0)
            }
        }
    }

    /// DHT Enhancement: Peer exchange protocol
    /// 
    /// **MIGRATION (Ticket #150):** Now accepts peer_registry and returns count
    /// 
    /// Note: Peer exchange is a future DHT feature that will:
    /// - Send FIND_NODE requests to known peers
    /// - Request peer lists from connected nodes  
    /// - Share our peer list with requesting nodes
    /// - Implement proper Kademlia peer discovery
    /// - Add discovered peers via full handshake -> registry
    async fn exchange_peers(&self, _peer_registry: SharedPeerRegistry) -> Result<usize> {
        info!(" DHT peer exchange...");
        
        // Peer exchange not yet implemented - requires DHT protocol extensions
        debug!("Peer exchange protocol not yet implemented");
        Ok(0)
    }

    /// Enhanced peer ping with proper ZHTP protocol validation
    async fn ping_peer(&self, peer: &str) -> Result<bool> {
        let address_part = peer.strip_prefix("zhtp://")
            .ok_or_else(|| anyhow::anyhow!("Invalid peer format"))?;
        
        let socket_addr: std::net::SocketAddr = address_part.parse()?;
        
        // Create proper ZHTP protocol ping packet
        match self.send_zhtp_ping(socket_addr).await {
            Ok(response) => {
                // Validate ZHTP protocol response
                self.validate_zhtp_response(response).await
            },
            Err(_) => Ok(false),
        }
    }

    /// Send ZHTP protocol ping and wait for response
    async fn send_zhtp_ping(&self, target: std::net::SocketAddr) -> Result<Vec<u8>> {
        use crate::dht::protocol::*;
        
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        
        // Generate random packet ID for ping
        let mut packet_id = [0u8; 16];
        let mut sender_id = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut packet_id);
        rand::rngs::OsRng.fill_bytes(&mut sender_id);
        
        // Create ZHTP DHT ping packet
        let header = DhtPacketHeader {
            version: DHT_PROTOCOL_VERSION,
            operation: DhtOperation::Ping,
            packet_id,
            sender_id,
            target_id: [0; 32], // Broadcast ping
            payload_length: 0,
            timestamp: SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            reserved: [0; 32],
        };
        
        // Serialize packet
        let packet_data = bincode::serialize(&header)
            .map_err(|e| anyhow::anyhow!("Failed to serialize ping: {}", e))?;
        
        // Send ping with timeout
        let send_result = tokio::time::timeout(
            Duration::from_millis(200),
            socket.send_to(&packet_data, target)
        ).await;
        
        match send_result {
            Ok(Ok(_)) => {
                // Wait for pong response
                let mut response_buffer = [0u8; MAX_DHT_PACKET_SIZE];
                let response_result = tokio::time::timeout(
                    Duration::from_millis(500),
                    socket.recv_from(&mut response_buffer)
                ).await;
                
                match response_result {
                    Ok(Ok((size, _addr))) => {
                        Ok(response_buffer[..size].to_vec())
                    },
                    _ => Err(anyhow::anyhow!("No pong response received"))
                }
            },
            _ => Err(anyhow::anyhow!("Failed to send ping"))
        }
    }
    
    /// Validate ZHTP protocol response
    async fn validate_zhtp_response(&self, response_data: Vec<u8>) -> Result<bool> {
        use crate::dht::protocol::*;
        
        // Try to deserialize as ZHTP DHT packet
        match bincode::deserialize::<DhtPacketHeader>(&response_data) {
            Ok(header) => {
                // Validate it's a proper PONG response
                if header.version == DHT_PROTOCOL_VERSION && 
                   header.operation == DhtOperation::Pong {
                    debug!(" Valid ZHTP pong received from peer");
                    Ok(true)
                } else {
                    debug!(" Invalid ZHTP response: wrong operation or version");
                    Ok(false)
                }
            },
            Err(_) => {
                debug!(" Invalid ZHTP response: malformed packet");
                Ok(false)
            }
        }
    }

    /// Discover ZHTP services via multicast DNS
    async fn discover_mdns_services(&self) -> Result<Vec<String>> {
        info!("mDNS: Browsing for _zhtp._tcp.local services...");
        
        let mut discovered_peers = Vec::new();
        
        // Use mdns-sd crate for proper multicast DNS discovery
        match mdns_sd::ServiceDaemon::new() {
            Ok(mdns) => {
                // Browse for ZHTP services with timeout
                let browse_result = tokio::time::timeout(
                    Duration::from_millis(5000), // 5 second mDNS timeout (increased for cross-subnet discovery)
                    self.browse_zhtp_services(&mdns)
                ).await;
                
                match browse_result {
                    Ok(Ok(services)) => {
                        for service in services {
                            let peer_url = format!("zhtp://{}:{}", service.host, service.port);
                            discovered_peers.push(peer_url);
                            info!(" mDNS discovered ZHTP service: {}", service.name);
                        }
                    },
                    Ok(Err(e)) => {
                        debug!("mDNS browse error: {}", e);
                    },
                    Err(_) => {
                        debug!("mDNS browse timeout - no services found");
                    }
                }
            },
            Err(e) => {
                debug!("Failed to create mDNS daemon: {}", e);
            }
        }
        
        Ok(discovered_peers)
    }

    /// Browse for ZHTP services using mDNS
    async fn browse_zhtp_services(&self, mdns: &mdns_sd::ServiceDaemon) -> Result<Vec<ZhtpServiceInfo>> {
        use std::collections::HashMap;
        
        let mut services = Vec::new();
        
        // Create a receiver for discovered services
        let browser = mdns.browse("_zhtp._tcp.local.")?;
        
        // Collect services for a short period
        let mut service_map = HashMap::new();
        
        while let Ok(event) = tokio::time::timeout(Duration::from_millis(4000), browser.recv_async()).await {
            match event {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    let service_info = ZhtpServiceInfo {
                        name: info.get_fullname().to_string(),
                        host: info.get_hostname().to_string(),
                        port: info.get_port(),
                        txt_properties: info.get_properties().iter()
                            .map(|prop| (prop.key().to_string(), prop.val_str().to_string()))
                            .collect(),
                    };
                    
                    service_map.insert(info.get_fullname().to_string(), service_info);
                },
                _ => {} // Ignore other events
            }
        }
        
        // Stop browsing explicitly before daemon cleanup
        drop(browser);
        
        // Give mdns-sd time to clean up browser's internal channels
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        services.extend(service_map.into_values());
        
        // Log discovered routers and clients separately
        let routers: Vec<_> = services.iter().filter(|s| s.is_router()).collect();
        let clients: Vec<_> = services.iter().filter(|s| s.is_client()).collect();
        
        if !routers.is_empty() {
            info!(" Found {} ZHTP routers:", routers.len());
            for router in &routers {
                info!("   🔀 Router: {} ({}:{})", 
                    router.node_id().unwrap_or_else(|| router.name.clone()),
                    router.host, router.port);
            }
        }
        
        if !clients.is_empty() {
            info!("📱 Found {} ZHTP clients:", clients.len());
            for client in &clients {
                info!("   📲 Client: {} ({}:{})",
                    client.node_id().unwrap_or_else(|| client.name.clone()),
                    client.host, client.port);
            }
        }
        
        Ok(services)
    }
    
    /// Get only router peers (Group Owners) for mesh backbone routing
    pub async fn discover_routers_only(&self) -> Result<Vec<String>> {
        let mdns = mdns_sd::ServiceDaemon::new()?;
        let services = self.browse_zhtp_services(&mdns).await?;
        
        let routers: Vec<String> = services.iter()
            .filter(|s| s.is_router())
            .map(|s| format!("{}:{}", s.host, s.port))
            .collect();
        
        info!("🔀 Discovered {} router nodes for mesh backbone", routers.len());
        Ok(routers)
    }
    
    /// Get only client peers for leaf node connections
    pub async fn discover_clients_only(&self) -> Result<Vec<String>> {
        let mdns = mdns_sd::ServiceDaemon::new()?;
        let services = self.browse_zhtp_services(&mdns).await?;
        
        let clients: Vec<String> = services.iter()
            .filter(|s| s.is_client())
            .map(|s| format!("{}:{}", s.host, s.port))
            .collect();
        
        info!("📱 Discovered {} client nodes", clients.len());
        Ok(clients)
    }

    /// Check if enhanced discovery needs refresh
    pub fn needs_refresh(&self) -> bool {
        self.last_discovery.elapsed()
            .unwrap_or(Duration::MAX) > Duration::from_secs(300) // 5 minutes
    }
}