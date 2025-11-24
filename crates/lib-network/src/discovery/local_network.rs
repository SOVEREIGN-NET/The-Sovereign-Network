//! Local Network Discovery via Multicast
//! 
//! Automatically discovers ZHTP nodes on the same local network without needing bootstrap peers

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, interval};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn, error, debug};
use uuid::Uuid;

/// Multicast address for ZHTP local discovery (224.0.0.251 is mDNS standard)
const ZHTP_MULTICAST_ADDR: &str = "224.0.1.75"; // Custom ZHTP multicast address
const ZHTP_MULTICAST_PORT: u16 = 37775; // Custom port for ZHTP discovery

/// Local ZHTP node announcement (sent via multicast UDP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    pub node_id: Uuid,
    pub mesh_port: u16,
    pub local_ip: IpAddr,
    pub protocols: Vec<String>,
    pub announced_at: u64,
}

/// Mesh handshake sent over TCP after discovery (compact binary format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHandshake {
    pub version: u8,
    pub node_id: Uuid,
    pub public_key: lib_crypto::PublicKey, // Actual cryptographic public key for peer identification
    pub mesh_port: u16,
    pub protocols: Vec<String>,
    pub discovered_via: u8, // 0=multicast, 1=bluetooth, 2=wifi_direct, 3=manual
    #[serde(default)]
    pub capabilities: HandshakeCapabilities,
}

/// Protocol capabilities for hybrid negotiation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HandshakeCapabilities {
    pub supports_bluetooth_classic: bool,  // Can upgrade to RFCOMM
    pub supports_bluetooth_le: bool,       // BLE GATT available
    pub supports_wifi_direct: bool,        // WiFi Direct capable
    pub max_throughput: u32,               // Maximum bandwidth (bytes/sec)
    pub prefers_high_throughput: bool,     // Prefer Classic over BLE
}

/// Start local network discovery service
/// Optional peer_discovered_callback will be called when a peer is found (for coordinator integration)
pub async fn start_local_discovery(
    node_id: Uuid, 
    mesh_port: u16, 
    public_key: lib_crypto::PublicKey,
    peer_discovered_callback: Option<std::sync::Arc<dyn Fn(String, lib_crypto::PublicKey) + Send + Sync>>,
) -> Result<()> {
    info!(" Starting UDP Multicast discovery...");
    info!("   Multicast address: {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Node ID: {}", node_id);
    info!("   Mesh port: {}", mesh_port);
    
    // Send an immediate announcement BEFORE spawning background task
    // This ensures other nodes can discover us right away
    if let Err(e) = send_immediate_announcement(node_id, mesh_port).await {
        warn!("Failed to send immediate announcement: {}", e);
    }
    
    // Start announcement broadcaster (background task)
    let announce_node_id = node_id;
    tokio::spawn(async move {
        if let Err(e) = broadcast_announcements(announce_node_id, mesh_port).await {
            error!(" Local announcement broadcaster failed: {}", e);
        }
    });
    
    // Start discovery listener (background task)
    let listen_node_id = node_id;
    let listen_public_key = public_key.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_for_announcements(listen_node_id, listen_public_key, peer_discovered_callback).await {
            error!(" Local discovery listener failed: {}", e);
        }
    });
    
    info!(" UDP Multicast discovery active on {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Broadcasting announcements every 30 seconds");
    info!("   Listening for peer announcements");
    Ok(())
}

/// Send a single immediate announcement (synchronous, before background task starts)
async fn send_immediate_announcement(node_id: Uuid, mesh_port: u16) -> Result<()> {
    use socket2::{Socket, Domain, Type, Protocol};
    
    // Create ephemeral socket for immediate announcement
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    let local_ip = get_local_ip().await.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    
    let announcement = NodeAnnouncement {
        node_id,
        mesh_port,
        local_ip,
        protocols: vec!["tcp".to_string(), "bluetooth".to_string(), "wifi_direct".to_string()],
        announced_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let announcement_json = serde_json::to_string(&announcement)?;
    socket.send_to(announcement_json.as_bytes(), multicast_addr).await?;
    info!(" Sent immediate announcement to {}", multicast_addr);
    
    Ok(())
}

/// Broadcast this node's presence on local network
async fn broadcast_announcements(node_id: Uuid, mesh_port: u16) -> Result<()> {
    // Bind to the multicast port with SO_REUSEADDR to allow multiple processes
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    // Bind to the multicast port (not ephemeral) for proper multicast routing
    socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    
    // Configure multicast socket options
    let multicast_ipv4: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.set_multicast_ttl_v4(2)?; // TTL=2 allows crossing one router (subnet-local)
    socket.set_multicast_loop_v4(true)?; // Enable loopback for testing on same machine
    socket.join_multicast_v4(multicast_ipv4, Ipv4Addr::UNSPECIFIED)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    
    // Get local IP address
    let local_ip = get_local_ip().await.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    
    info!(" Broadcasting from local IP: {}", local_ip);
    
    let mut interval = interval(Duration::from_secs(30)); // Announce every 30 seconds
    
    let mut announcement_count = 0;
    loop {
        // Send announcement immediately on first iteration, then wait 30s between
        if announcement_count > 0 {
            interval.tick().await;
        }
        
        let announcement = NodeAnnouncement {
            node_id,
            mesh_port,
            local_ip,
            protocols: vec!["tcp".to_string(), "bluetooth".to_string(), "wifi_direct".to_string()],
            announced_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        match serde_json::to_string(&announcement) {
            Ok(announcement_json) => {
                announcement_count += 1;
                if announcement_count == 1 || announcement_count % 10 == 0 {
                    info!(" Broadcasting announcement #{} to {}", announcement_count, multicast_addr);
                } else {
                    debug!("Broadcasting ZHTP node announcement to {}", multicast_addr);
                }
                
                if let Err(e) = socket.send_to(announcement_json.as_bytes(), multicast_addr).await {
                    warn!("Failed to send multicast announcement: {}", e);
                }
            },
            Err(e) => {
                warn!("Failed to serialize announcement: {}", e);
            }
        }
        
        // Wait 30 seconds before next announcement
        interval.tick().await;
    }
}

/// Listen for other ZHTP nodes on local network
async fn listen_for_announcements(
    our_node_id: Uuid, 
    our_public_key: lib_crypto::PublicKey,
    peer_discovered_callback: Option<std::sync::Arc<dyn Fn(String, lib_crypto::PublicKey) + Send + Sync>>,
) -> Result<()> {
    // Use SO_REUSEADDR to allow multiple listeners on the same port
    // This lets both the persistent listener and temporary discovery scans coexist
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&format!("0.0.0.0:{}", ZHTP_MULTICAST_PORT).parse::<std::net::SocketAddr>()?.into())?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(socket)?;
    
    // Configure multicast socket options
    let multicast_addr: Ipv4Addr = ZHTP_MULTICAST_ADDR.parse()?;
    socket.set_multicast_loop_v4(true)?; // Enable loopback for testing on same machine
    socket.join_multicast_v4(multicast_addr, Ipv4Addr::UNSPECIFIED)?;
    
    info!(" Listening for ZHTP node announcements on multicast {}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT);
    info!("   Joined multicast group successfully");
    
    let mut buf = [0; 1024];
    let mut discovery_count = 0;
    let mut packet_count = 0;
    
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                packet_count += 1;
                
                // Log every packet received for debugging
                if packet_count == 1 || packet_count % 10 == 0 {
                    debug!(" Received multicast packet #{} from {} ({} bytes)", packet_count, addr, len);
                }
                
                let announcement_str = String::from_utf8_lossy(&buf[..len]);
                debug!("Packet content: {}", announcement_str);
                
                match serde_json::from_str::<NodeAnnouncement>(&announcement_str) {
                    Ok(announcement) => {
                        // Ignore our own announcements (check node_id)
                        if announcement.node_id == our_node_id {
                            debug!("Ignoring our own multicast announcement (node_id={})", our_node_id);
                            continue;
                        }
                        
                        discovery_count += 1;
                        info!(" PEER DISCOVERED #{}: Node {} at {}:{}", 
                            discovery_count,
                            announcement.node_id, 
                            announcement.local_ip, 
                            announcement.mesh_port
                        );
                        info!("   Protocols: {:?}", announcement.protocols);
                        info!("   Attempting connection...");
                        
                        // Notify coordinator if callback provided (Phase 3 integration)
                        if let Some(ref callback) = peer_discovered_callback {
                            let peer_addr = format!("{}:{}", announcement.local_ip, announcement.mesh_port);
                            callback(peer_addr, our_public_key.clone());
                            debug!("   ✓ Notified discovery coordinator");
                        }
                        
                        // TODO: Add this peer to our connections
                        attempt_connect_to_discovered_peer(&announcement, &our_public_key).await;
                    },
                    Err(e) => {
                        debug!("Invalid announcement format from {}: {}", addr, e);
                    }
                }
            },
            Err(e) => {
                warn!("Error receiving multicast announcement: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Attempt to connect to a newly discovered peer
async fn attempt_connect_to_discovered_peer(announcement: &NodeAnnouncement, our_public_key: &lib_crypto::PublicKey) {
    let peer_addr = format!("{}:{}", announcement.local_ip, announcement.mesh_port);
    info!(" Connecting to discovered ZHTP peer at {}", peer_addr);
    
    // Connect via TCP to the peer's mesh port
    match tokio::net::TcpStream::connect(&peer_addr).await {
        Ok(mut stream) => {
            info!(" TCP connection established to peer {}", peer_addr);
            
            // Create compact binary handshake (faster and smaller than JSON)
            let handshake = MeshHandshake {
                version: 1,
                node_id: announcement.node_id,
                public_key: our_public_key.clone(),
                mesh_port: announcement.mesh_port,
                protocols: announcement.protocols.clone(),
                discovered_via: 0, // 0 = local multicast discovery
                capabilities: HandshakeCapabilities::default(), // Default capabilities
            };
            
            // Serialize with bincode (10x faster, 60% smaller than JSON)
            match bincode::serialize(&handshake) {
                Ok(handshake_bytes) => {
                    match stream.write_all(&handshake_bytes).await {
                        Ok(_) => {
                            info!(" Binary mesh handshake sent to {} ({} bytes)", 
                                peer_addr, handshake_bytes.len());
                            
                            // Wait for acknowledgment from server
                            use tokio::io::AsyncReadExt;
                            let mut ack_buf = vec![0u8; 8];
                            
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                stream.read(&mut ack_buf)
                            ).await {
                                Ok(Ok(n)) if n > 0 => {
                                    info!(" Received acknowledgment from peer ({} bytes)", n);
                                    info!(" Initial handshake complete - peer will initiate full auth on their end");
                                }
                                Ok(Ok(_)) => {
                                    warn!(" Peer closed connection immediately after handshake");
                                }
                                Ok(Err(e)) => {
                                    warn!(" Error reading ack from peer: {}", e);
                                }
                                Err(_) => {
                                    warn!(" Timeout waiting for ack from peer");
                                }
                            }
                            
                            // Close the initial handshake connection
                            // The server will now initiate a proper authenticated connection back to us
                            // or we'll reconnect when we actually need to send data
                            debug!(" Closing initial discovery handshake connection");
                        },
                        Err(e) => {
                            warn!("Failed to send handshake to {}: {}", peer_addr, e);
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to serialize handshake: {}", e);
                }
            }
        },
        Err(e) => {
            debug!("Could not connect to peer {} (may not be ready yet): {}", peer_addr, e);
        }
    }
}

/// Get the local IP address of this machine
async fn get_local_ip() -> Result<IpAddr> {
    // Try to connect to a remote address to determine our local IP
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            if let Ok(_) = socket.connect("8.8.8.8:80").await {
                if let Ok(local_addr) = socket.local_addr() {
                    return Ok(local_addr.ip());
                }
            }
        },
        Err(_) => {}
    }
    
    // Fallback to localhost
    Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

/// Discover ZHTP nodes on local network immediately
pub async fn discover_local_peers() -> Result<Vec<NodeAnnouncement>> {
    info!("Scanning for ZHTP peers on local network...");
    
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    
    let multicast_addr: SocketAddr = format!("{}:{}", ZHTP_MULTICAST_ADDR, ZHTP_MULTICAST_PORT).parse()?;
    
    // Send discovery request
    let discovery_request = serde_json::json!({
        "type": "discovery_request",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    
    socket.send_to(discovery_request.to_string().as_bytes(), multicast_addr).await?;
    
    // Listen for responses (simplified - in implementation would be more sophisticated)
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // TODO: Collect actual responses
    Ok(vec![])
}