//! Smart Routing and Peer Selection
//! 
//! Intelligently selects optimal peers based on proximity, performance, and network conditions

use anyhow::Result;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use tracing::{info, debug};
use crate::network_utils::get_local_ip;

/// Peer quality metrics for routing decisions
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    pub latency_ms: f64,
    pub bandwidth_mbps: f64,
    pub reliability: f64,  // 0.0 to 1.0
    pub hop_count: u32,
    pub last_seen: u64,
    pub peer_type: PeerType,
}

/// Type of peer for routing prioritization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerType {
    LocalSubnet,     // Same network - highest priority
    WiFiDirect,      // Direct WiFi connection
    BluetoothLE,     // Bluetooth mesh
    LoRaWAN,         // Long-range low-power
    Internet,        // Traditional internet routing
    Satellite,       // Satellite uplink
}

/// Smart peer selection for optimal routing
pub async fn select_optimal_peers(
    available_peers: &[SocketAddr],
    peer_metrics: &HashMap<SocketAddr, PeerMetrics>,
    max_peers: usize
) -> Result<Vec<SocketAddr>> {
    info!("🧠 Selecting {} optimal peers from {} candidates", max_peers, available_peers.len());
    
    let mut scored_peers: Vec<(SocketAddr, f64)> = Vec::new();
    
    for peer in available_peers {
        if let Some(metrics) = peer_metrics.get(peer) {
            let score = calculate_peer_score(metrics);
            scored_peers.push((*peer, score));
            debug!("Peer {} scored {:.2}", peer, score);
        }
    }
    
    // Sort by score (highest first)
    scored_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    
    // Take the top peers
    let selected: Vec<SocketAddr> = scored_peers
        .into_iter()
        .take(max_peers)
        .map(|(addr, _score)| addr)
        .collect();
    
    info!(" Selected {} optimal peers", selected.len());
    Ok(selected)
}

/// Calculate routing score for a peer (higher is better)
fn calculate_peer_score(metrics: &PeerMetrics) -> f64 {
    let mut score = 0.0;
    
    // Peer type priority (local is best)
    let type_weight = match metrics.peer_type {
        PeerType::LocalSubnet => 100.0,
        PeerType::WiFiDirect => 80.0,
        PeerType::BluetoothLE => 60.0,
        PeerType::LoRaWAN => 40.0,
        PeerType::Internet => 20.0,
        PeerType::Satellite => 10.0,
    };
    score += type_weight;
    
    // Latency (lower is better, invert for scoring)
    let latency_score = if metrics.latency_ms > 0.0 {
        1000.0 / metrics.latency_ms // Max 1000ms becomes score 1.0
    } else {
        0.0
    };
    score += latency_score * 10.0;
    
    // Bandwidth (higher is better)
    score += metrics.bandwidth_mbps * 2.0;
    
    // Reliability (0.0 to 1.0, higher is better)
    score += metrics.reliability * 50.0;
    
    // Hop count (fewer hops is better)
    let hop_score = if metrics.hop_count > 0 {
        10.0 / metrics.hop_count as f64
    } else {
        10.0
    };
    score += hop_score;
    
    // Freshness (recently seen peers are better)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age_seconds = now.saturating_sub(metrics.last_seen);
    let freshness_score = if age_seconds < 300 { // 5 minutes
        20.0 - (age_seconds as f64 / 15.0) // Decay over time
    } else {
        0.0
    };
    score += freshness_score;
    
    score.max(0.0) // Ensure non-negative
}

/// Automatically categorize peers by network topology
pub async fn categorize_peers_by_topology(
    peers: &[SocketAddr]
) -> Result<HashMap<PeerType, Vec<SocketAddr>>> {
    let mut categorized: HashMap<PeerType, Vec<SocketAddr>> = HashMap::new();
    
    let local_ip = get_local_ip().await?;
    let local_ipv4 = match local_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::new(127, 0, 0, 1),
    };
    let local_subnet = get_subnet_base(&local_ipv4);
    
    for peer in peers {
        let peer_type = match peer {
            SocketAddr::V4(v4_addr) => {
                let peer_subnet = get_subnet_base(v4_addr.ip());
                
                if peer_subnet == local_subnet {
                    PeerType::LocalSubnet
                } else if is_private_ip(v4_addr.ip()) {
                    PeerType::WiFiDirect // Assume WiFi Direct for other private IPs
                } else {
                    PeerType::Internet
                }
            },
            SocketAddr::V6(_) => PeerType::Internet, // IPv6 treated as internet
        };
        
        categorized.entry(peer_type).or_insert_with(Vec::new).push(*peer);
    }
    
    info!("Categorized peers by topology:");
    for (peer_type, addrs) in &categorized {
        info!("  {:?}: {} peers", peer_type, addrs.len());
    }
    
    Ok(categorized)
}

/// Check if IP address is in private ranges
fn is_private_ip(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }
    
    false
}

/// Get subnet base (first 3 octets) from IP
fn get_subnet_base(ip: &std::net::Ipv4Addr) -> (u8, u8, u8) {
    let octets = ip.octets();
    (octets[0], octets[1], octets[2])
}

/// Measure peer performance metrics
pub async fn measure_peer_performance(peer: SocketAddr) -> Result<PeerMetrics> {
    let start_time = std::time::Instant::now();
    
    // Simple latency test
    match tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        tokio::net::TcpStream::connect(peer)
    ).await {
        Ok(Ok(_stream)) => {
            let latency = start_time.elapsed().as_millis() as f64;
            
            Ok(PeerMetrics {
                latency_ms: latency,
                bandwidth_mbps: 0.0, // TODO: Implement bandwidth test
                reliability: 1.0,    // TODO: Track over time
                hop_count: 1,        // TODO: Implement traceroute-like functionality
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                peer_type: PeerType::Internet, // Will be updated by categorization
            })
        },
        _ => {
            Err(anyhow::anyhow!("Failed to connect to peer {}", peer))
        }
    }
}