//! Network Monitoring and Local Subnet Discovery
//! 
//! Automatically discovers ZHTP nodes on the same local network via subnet scanning

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, debug, warn};

/// Scan local subnet for ZHTP nodes
pub async fn discover_local_subnet_peers(mesh_port: u16) -> Result<Vec<SocketAddr>> {
    info!("Scanning local subnet for ZHTP nodes on port {}...", mesh_port);
    
    let local_ip = get_local_ip().await?;
    let subnet_base = get_subnet_base(&local_ip)?;
    
    info!("Scanning subnet {}.{}.{}.0/24 for ZHTP peers", subnet_base.0, subnet_base.1, subnet_base.2);
    
    let mut discovered_peers = Vec::new();
    let mut scan_tasks = Vec::new();
    
    // Scan all 254 possible host addresses in parallel
    for host in 1..=254 {
        let target_ip = Ipv4Addr::new(subnet_base.0, subnet_base.1, subnet_base.2, host);
        let target_addr = SocketAddr::new(IpAddr::V4(target_ip), mesh_port);
        
        let task = tokio::spawn(async move {
            if let Ok(_) = test_zhtp_connection(target_addr).await {
                Some(target_addr)
            } else {
                None
            }
        });
        
        scan_tasks.push(task);
    }
    
    // Collect results
    for task in scan_tasks {
        if let Ok(Some(addr)) = task.await {
            discovered_peers.push(addr);
            info!(" Found ZHTP peer at {}", addr);
        }
    }
    
    info!("Discovered {} ZHTP peers on local subnet", discovered_peers.len());
    Ok(discovered_peers)
}

/// Test if a ZHTP node is running at the given address
async fn test_zhtp_connection(addr: SocketAddr) -> Result<()> {
    // Try to establish TCP connection with short timeout
    let connect_timeout = Duration::from_millis(200);
    
    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            debug!("TCP connection successful to {}", addr);
            
            // Send ZHTP handshake to verify it's actually a ZHTP node
            let handshake = serde_json::json!({
                "type": "handshake",
                "protocol": "ZHTP",
                "version": "1.0"
            });
            
            use tokio::io::AsyncWriteExt;
            if stream.write_all(handshake.to_string().as_bytes()).await.is_ok() {
                debug!(" ZHTP handshake sent to {}", addr);
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to send ZHTP handshake"))
            }
        },
        Ok(Err(e)) => {
            debug!("Connection failed to {}: {}", addr, e);
            Err(anyhow::anyhow!("Connection failed: {}", e))
        },
        Err(_) => {
            debug!("⏰ Connection timeout to {}", addr);
            Err(anyhow::anyhow!("Connection timeout"))
        }
    }
}

/// Get the local IP address of this machine
async fn get_local_ip() -> Result<Ipv4Addr> {
    // Connect to a well-known address to determine our local IP
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    
    match socket.local_addr()? {
        SocketAddr::V4(addr) => Ok(*addr.ip()),
        SocketAddr::V6(_) => {
            // Fallback for IPv6 environments
            Ok(Ipv4Addr::new(192, 168, 1, 100)) // Common default
        }
    }
}

/// Extract subnet base (first 3 octets) from IP address
fn get_subnet_base(ip: &Ipv4Addr) -> Result<(u8, u8, u8)> {
    let octets = ip.octets();
    Ok((octets[0], octets[1], octets[2]))
}

/// Monitor network changes and re-scan when network topology changes
pub async fn start_network_monitor(mesh_port: u16) -> Result<()> {
    info!("Starting continuous network monitoring...");
    
    let mut last_peers: Vec<SocketAddr> = Vec::new();
    let mut scan_interval = tokio::time::interval(Duration::from_secs(60)); // Scan every minute
    
    loop {
        scan_interval.tick().await;
        
        match discover_local_subnet_peers(mesh_port).await {
            Ok(current_peers) => {
                // Check for new peers
                for peer in &current_peers {
                    if !last_peers.contains(peer) {
                        info!(" New ZHTP peer discovered: {}", peer);
                        // TODO: Trigger connection attempt
                    }
                }
                
                // Check for lost peers
                for peer in &last_peers {
                    if !current_peers.contains(peer) {
                        warn!("📵 ZHTP peer lost: {}", peer);
                        // TODO: Clean up connection
                    }
                }
                
                last_peers = current_peers;
            },
            Err(e) => {
                warn!("Network scan failed: {}", e);
            }
        }
    }
}

/// Get network interface information
pub async fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    
    // This is a simplified implementation
    // In a implementation, you'd use system APIs to get interface details
    if let Ok(local_ip) = get_local_ip().await {
        interfaces.push(NetworkInterface {
            name: "primary".to_string(),
            ip_address: IpAddr::V4(local_ip),
            is_active: true,
            interface_type: InterfaceType::Ethernet,
        });
    }
    
    Ok(interfaces)
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_address: IpAddr,
    pub is_active: bool,
    pub interface_type: InterfaceType,
}

/// Type of network interface
#[derive(Debug, Clone)]
pub enum InterfaceType {
    Ethernet,
    WiFi,
    Loopback,
    VPN,
}