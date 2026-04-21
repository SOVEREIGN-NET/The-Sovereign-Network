//! Global peer endpoint registry for ZDNS discovery.
//!
//! Simple DID → SocketAddr map populated during UHP handshakes.
//! The ZDNS endpoint provider reads this to return non-validator node IPs
//! alongside validator IPs in `network.sov` responses.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;

static PEER_ENDPOINTS: once_cell::sync::Lazy<RwLock<HashMap<String, PeerEndpointInfo>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Clone, Debug)]
pub struct PeerEndpointInfo {
    pub did: String,
    pub addr: SocketAddr,
    pub last_seen: u64,
}

/// Register or update a peer's endpoint after successful UHP handshake.
pub async fn register_peer_endpoint(did: String, addr: SocketAddr) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(mut map) = PEER_ENDPOINTS.write() {
        map.insert(did.clone(), PeerEndpointInfo { did, addr, last_seen: now });
    }
}

/// Called when receiving a PeerEndpointAnnounce gossip from another node.
pub fn handle_peer_announce(did: String, addr_str: &str) {
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Ok(mut map) = PEER_ENDPOINTS.write() {
        map.insert(did.clone(), PeerEndpointInfo { did, addr, last_seen: now });
    }
}

/// Get all peer endpoints seen within the last `max_age_secs` seconds.
/// Returns IPv4 addresses only (for DNS A records).
/// Sync-safe: uses std::sync::RwLock, callable from sync closures.
pub fn get_active_peer_ips_sync(max_age_secs: u64) -> Vec<std::net::Ipv4Addr> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let map = match PEER_ENDPOINTS.read() {
        Ok(m) => m,
        Err(_) => return vec![],
    };
    map.values()
        .filter(|p| now.saturating_sub(p.last_seen) < max_age_secs)
        .filter_map(|p| match p.addr.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_private() && !v4.is_unspecified() => Some(v4),
            _ => None,
        })
        .collect()
}

/// Get all active peer endpoints with metadata (for directory API).
pub fn get_active_peers_sync(max_age_secs: u64) -> Vec<PeerEndpointInfo> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let map = match PEER_ENDPOINTS.read() {
        Ok(m) => m,
        Err(_) => return vec![],
    };
    map.values()
        .filter(|p| now.saturating_sub(p.last_seen) < max_age_secs)
        .cloned()
        .collect()
}
