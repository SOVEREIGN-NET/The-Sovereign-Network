//! Network Scanner for ZHTP Nodes
//!
//! Actively scans local network for ZHTP nodes on common ports
//! Complements passive multicast discovery with active probing

use anyhow::{Result, Context};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{info, debug, warn};
use std::net::{IpAddr, Ipv4Addr};
use crate::discovery::local_network::HandshakeCapabilities;

/// Common ZHTP ports to scan
const ZHTP_COMMON_PORTS: &[u16] = &[
    9333,  // Default ZHTP unified port
    9334,  // Common alternative
    9335,  // Common alternative
    8080,  // HTTP alternative
    3000,  // Development port
];

/// Scan timeout per port
const SCAN_TIMEOUT: Duration = Duration::from_millis(500);

/// Network scanner result
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub is_zhtp_node: bool,
    pub node_id: Option<String>,
    pub response_time_ms: u64,
}

/// Start background network scanner
pub async fn start_network_scanner(_mesh_port: u16, local_node_id: uuid::Uuid, local_public_key: lib_crypto::PublicKey) -> Result<()> {
    info!(" Starting automatic network scanner for ZHTP nodes...");
    info!(" Local node ID: {}", local_node_id);
    
    // Get local IP address to avoid self-connections
    let local_ip = local_ip_address::local_ip().ok();
    if let Some(ip) = local_ip {
        info!(" Local IP: {} (will skip self-connections)", ip);
    }
    
    // Get local network range
    let local_ranges = get_local_network_ranges().await?;
    
    info!(" Scanning {} local network ranges for ZHTP nodes", local_ranges.len());
    
    // Spawn background scanner task
    tokio::spawn(async move {
        loop {
            for range in &local_ranges {
                info!(" Scanning network range: {}", range);
                
                match scan_network_range(range, ZHTP_COMMON_PORTS).await {
                    Ok(results) => {
                        let zhtp_nodes: Vec<_> = results.iter()
                            .filter(|r| {
                                // Filter out non-ZHTP nodes and self-connections
                                if !r.is_zhtp_node {
                                    return false;
                                }
                                
                                // Skip if this is our own IP
                                if let Some(local) = local_ip {
                                    if r.ip == local {
                                        debug!(" Skipping self-connection to {}", r.ip);
                                        return false;
                                    }
                                }
                                
                                true
                            })
                            .collect();
                        
                        if !zhtp_nodes.is_empty() {
                            info!(" Found {} ZHTP nodes in range {} (excluding self)", zhtp_nodes.len(), range);
                            
                            // Attempt to connect to discovered nodes
                            for node in zhtp_nodes {
                                info!("🤝 Discovered ZHTP node at {}:{} ({}ms response)", 
                                    node.ip, node.port, node.response_time_ms);
                                
                                // Attempt automatic connection with our persistent node ID
                                if let Err(e) = attempt_auto_connect(node, local_node_id, &local_public_key).await {
                                    debug!("Auto-connect failed for {}:{}: {}", node.ip, node.port, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Network scan failed for {}: {}", range, e);
                    }
                }
            }
            
            // Scan every 30 seconds
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    
    info!(" Network scanner started - will scan every 30 seconds");
    Ok(())
}

/// Get local network ranges to scan (automatically detects ALL local subnets)
async fn get_local_network_ranges() -> Result<Vec<String>> {
    let mut ranges = Vec::new();
    
    // Get ALL network interfaces and their IP addresses
    match local_ip_address::list_afinet_netifas() {
        Ok(network_interfaces) => {
            info!(" Detected {} network interfaces", network_interfaces.len());
            
            for (name, ip) in network_interfaces {
                match ip {
                    IpAddr::V4(ipv4) => {
                        // Skip loopback interface
                        if ipv4.is_loopback() {
                            debug!("   Skipping loopback interface: {} ({})", name, ipv4);
                            continue;
                        }
                        
                        // Create /24 subnet (e.g., 192.168.1.0/24)
                        let octets = ipv4.octets();
                        let subnet = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
                        
                        // Only add if not already present
                        if !ranges.contains(&subnet) {
                            info!("   {} {} → scanning {}.0/24", name, ipv4, subnet);
                            ranges.push(subnet);
                        }
                    }
                    IpAddr::V6(_ipv6) => {
                        // IPv6 not yet supported for scanning
                        debug!("   Skipping IPv6 interface: {} (IPv6 not yet supported)", name);
                    }
                }
            }
            
            if ranges.is_empty() {
                warn!(" No valid network interfaces found for scanning!");
                warn!(" Falling back to default 192.168.1.0/24");
                ranges.push("192.168.1".to_string());
            } else {
                info!(" Will scan {} subnet(s) for ZHTP nodes", ranges.len());
            }
        }
        Err(e) => {
            warn!("Failed to detect network interfaces: {}", e);
            warn!(" Falling back to common private network ranges");
            
            // Fallback: try to get at least the primary local IP
            if let Ok(local_ip) = local_ip_address::local_ip() {
                if let IpAddr::V4(ipv4) = local_ip {
                    let octets = ipv4.octets();
                    let subnet = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
                    info!(" Detected primary subnet: {}.0/24", &subnet);
                    ranges.push(subnet);
                }
            }
            
            // Add common ranges as last resort
            if ranges.is_empty() {
                ranges.push("192.168.1".to_string());
            }
        }
    }
    
    Ok(ranges)
}

/// Scan a network range for ZHTP nodes
async fn scan_network_range(subnet: &str, ports: &[u16]) -> Result<Vec<ScanResult>> {
    let mut results = Vec::new();
    let mut all_scans = Vec::new();
    
    // Collect all scan configurations
    for host in 1..=254 {
        let ip_str = format!("{}.{}", subnet, host);
        
        // Parse IP
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            // Scan all ports for this IP
            for &port in ports {
                all_scans.push((IpAddr::V4(ip), port));
            }
        }
    }
    
    // Execute scans in parallel (batches of 50 to avoid overwhelming network)
    for chunk in all_scans.chunks(50) {
        let scan_futures: Vec<_> = chunk.iter()
            .map(|(ip, port)| scan_port(*ip, *port))
            .collect();
        
        let chunk_results = futures::future::join_all(scan_futures).await;
        
        for result in chunk_results {
            if let Ok(Some(scan_result)) = result {
                results.push(scan_result);
            }
        }
    }
    
    Ok(results)
}

/// Scan a single IP:port combination
async fn scan_port(ip: IpAddr, port: u16) -> Result<Option<ScanResult>> {
    let addr = format!("{}:{}", ip, port);
    let start = std::time::Instant::now();
    
    // Attempt TCP connection with timeout
    match timeout(SCAN_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let response_time_ms = start.elapsed().as_millis() as u64;
            
            // Connection successful - check if it's a ZHTP node
            match probe_zhtp_node(&mut stream).await {
                Ok(Some(node_id)) => {
                    debug!(" ZHTP node found at {}:{} - ID: {}", ip, port, node_id);
                    Ok(Some(ScanResult {
                        ip,
                        port,
                        is_zhtp_node: true,
                        node_id: Some(node_id),
                        response_time_ms,
                    }))
                }
                Ok(None) => {
                    // Port open but not ZHTP
                    debug!(" Port {}:{} open but not ZHTP", ip, port);
                    Ok(Some(ScanResult {
                        ip,
                        port,
                        is_zhtp_node: false,
                        node_id: None,
                        response_time_ms,
                    }))
                }
                Err(_) => {
                    // Connection open but probe failed
                    Ok(None)
                }
            }
        }
        Ok(Err(_)) => {
            // Connection refused - port closed
            Ok(None)
        }
        Err(_) => {
            // Timeout - host unreachable or port filtered
            Ok(None)
        }
    }
}

/// Probe if a connected socket is a ZHTP node
async fn probe_zhtp_node(stream: &mut TcpStream) -> Result<Option<String>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Send ZHTP probe request
    let probe = b"ZHTP-PROBE\r\n";
    
    match timeout(Duration::from_millis(200), stream.write_all(probe)).await {
        Ok(Ok(_)) => {
            // Read response
            let mut buffer = vec![0u8; 1024];
            
            match timeout(Duration::from_millis(200), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    
                    // Check if response contains ZHTP identifiers
                    if response.contains("ZHTP") || response.contains("zhtp") {
                        // Try to extract node ID
                        if let Some(node_id) = extract_node_id(&response) {
                            return Ok(Some(node_id));
                        }
                        
                        // ZHTP node but couldn't extract ID
                        return Ok(Some("unknown".to_string()));
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    
    Ok(None)
}

/// Extract node ID from ZHTP response
fn extract_node_id(response: &str) -> Option<String> {
    // Look for node ID patterns
    for line in response.lines() {
        if line.contains("node-id:") || line.contains("Node-ID:") {
            if let Some(id) = line.split(':').nth(1) {
                return Some(id.trim().to_string());
            }
        }
        if line.contains("X-Node-ID:") {
            if let Some(id) = line.split(':').nth(1) {
                return Some(id.trim().to_string());
            }
        }
    }
    
    None
}

/// Attempt automatic connection to discovered node
async fn attempt_auto_connect(node: &ScanResult, local_node_id: uuid::Uuid, local_public_key: &lib_crypto::PublicKey) -> Result<()> {
    use crate::discovery::local_network::MeshHandshake;
    use tokio::io::AsyncWriteExt;
    
    let addr = format!("{}:{}", node.ip, node.port);
    
    info!(" Auto-connecting to discovered ZHTP node at {}", addr);
    
    // Connect to node
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(&addr)
    ).await
        .context("Connection timeout")?
        .context("Failed to connect")?;
    
    // Send MeshHandshake with our persistent node ID
    let handshake = MeshHandshake {
        node_id: local_node_id,  //  Using persistent node ID from server
        version: 1,
        public_key: local_public_key.clone(),
        mesh_port: 9333,
        protocols: vec!["zhtp".to_string(), "dht".to_string()],
        discovered_via: 4, // 4 = network scan
        capabilities: HandshakeCapabilities::default(), // Default capabilities
    };
    
    let handshake_bytes = bincode::serialize(&handshake)?;
    stream.write_all(&handshake_bytes).await?;
    
    info!(" Sent handshake to {} with node ID: {}", addr, local_node_id);
    
    // Note: Full authentication will be handled by the server's
    // authenticate_and_register_peer() function
    
    Ok(())
}

/// Quick scan for ZHTP nodes (used during startup)
pub async fn quick_scan_local_network() -> Result<Vec<ScanResult>> {
    info!(" Running quick network scan for ZHTP nodes...");
    
    let ranges = get_local_network_ranges().await?;
    let mut all_results = Vec::new();
    
    for range in ranges {
        match scan_network_range(&range, &[9333]).await {
            Ok(results) => {
                let zhtp_nodes: Vec<_> = results.into_iter()
                    .filter(|r| r.is_zhtp_node)
                    .collect();
                
                if !zhtp_nodes.is_empty() {
                    info!(" Quick scan found {} ZHTP nodes in {}.0/24", 
                        zhtp_nodes.len(), range);
                    all_results.extend(zhtp_nodes);
                }
            }
            Err(e) => {
                warn!("Quick scan failed for {}: {}", range, e);
            }
        }
    }
    
    info!(" Quick scan complete - found {} ZHTP nodes total", all_results.len());
    Ok(all_results)
}
