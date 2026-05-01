//! Validator IP self-registration via STUN discovery.
//!
//! On startup, each node discovers its public IP using STUN and updates a
//! local IP overlay cache. ZDNS and API handlers read from this overlay to
//! serve resolved IPs instead of hostnames, without mutating blockchain state.
//!
//! A background task re-checks the public IP periodically (default: 5 minutes)
//! to handle IP changes on nodes with dynamic addresses.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::RwLock;
use tracing::{info, warn};

/// Local IP resolution overlay. Maps DID → resolved network_address.
/// This does NOT mutate blockchain state — it's a local convenience layer
/// for serving resolved IPs in DNS and API responses.
static IP_OVERLAY: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);

/// Get the resolved network address for a validator DID, if available.
/// Returns None if no override exists (caller should fall back to blockchain data).
pub fn get_resolved_address(did: &str) -> Option<String> {
    let overlay = IP_OVERLAY.read().ok()?;
    overlay.as_ref()?.get(did).cloned()
}

/// Get all resolved addresses from the overlay.
pub fn get_all_resolved_addresses() -> HashMap<String, String> {
    IP_OVERLAY
        .read()
        .ok()
        .and_then(|o| o.clone())
        .unwrap_or_default()
}

/// Discover this node's public IPv4 address via STUN.
pub async fn discover_public_ip() -> Option<Ipv4Addr> {
    let stun = lib_network::nat::stun::StunClient::new();
    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    match stun.discover_public_endpoint(bind).await {
        Ok(endpoint) => {
            if let std::net::IpAddr::V4(ip) = endpoint.ip() {
                info!("STUN discovered public IP: {}", ip);
                Some(ip)
            } else {
                warn!("STUN returned IPv6 address {}, skipping", endpoint.ip());
                None
            }
        }
        Err(e) => {
            tracing::debug!(
                "STUN discovery skipped: {} (not needed if endpoints are configured)",
                e
            );
            None
        }
    }
}

/// Resolve validator IPs and store them in the local overlay cache.
/// Reads blockchain state under a read lock only. Never mutates blockchain.
pub async fn update_validator_ips(own_did: Option<&str>, stun_ip: Option<Ipv4Addr>) {
    let blockchain_arc = match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(bc) => bc,
        Err(_) => return,
    };

    let mut updates: HashMap<String, String> = HashMap::new();

    // Read current validator addresses under read lock
    let entries_to_resolve: Vec<(String, String)> = {
        let blockchain = blockchain_arc.read().await;

        // 1. Own entry with STUN-discovered IP
        if let (Some(did), Some(ip)) = (own_did, stun_ip) {
            if let Some(validator) = blockchain.validator_registry.get(did) {
                let port = validator
                    .network_address
                    .split(':')
                    .last()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(9334);
                let new_addr = format!("{}:{}", ip, port);
                if validator.network_address != new_addr {
                    info!(
                        "Updated own validator IP in overlay: {} -> {}",
                        validator.network_address, new_addr
                    );
                    updates.insert(did.to_string(), new_addr);
                }
            }
        }

        // 2. Collect hostname-based entries that need resolution
        blockchain
            .validator_registry
            .iter()
            .filter(|(did, _)| own_did.map_or(true, |own| *did != own))
            .filter(|(_, v)| {
                let addr = &v.network_address;
                if addr.starts_with('[') {
                    return false;
                }
                let host = addr.split(':').next().unwrap_or("");
                host.parse::<Ipv4Addr>().is_err()
                    && host.parse::<std::net::Ipv6Addr>().is_err()
                    && !host.is_empty()
            })
            .map(|(did, v)| (did.clone(), v.network_address.clone()))
            .collect()
    };
    // Read lock dropped here

    // 3. Resolve hostnames (no lock held)
    if !entries_to_resolve.is_empty() {
        let resolved = resolve_hostnames(entries_to_resolve).await;
        for (did, new_addr) in resolved {
            updates.insert(did, new_addr);
        }
    }

    // 4. Merge into overlay
    if !updates.is_empty() {
        if let Ok(mut overlay) = IP_OVERLAY.write() {
            let map = overlay.get_or_insert_with(HashMap::new);
            for (did, addr) in &updates {
                map.insert(did.clone(), addr.clone());
            }
        }
        info!("Updated {} validator addresses in IP overlay", updates.len());
    }
}

/// Resolve hostname:port entries to ip:port using system DNS.
async fn resolve_hostnames(entries: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut resolved = Vec::new();
    for (did, addr) in entries {
        let parts: Vec<&str> = addr.splitn(2, ':').collect();
        let (host, port) = match parts.as_slice() {
            [h, p] => (*h, *p),
            [h] => (*h, "9334"),
            _ => continue,
        };

        match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                    resolved.push((did, format!("{}:{}", addr.ip(), port)));
                }
            }
            Err(e) => {
                warn!("DNS resolution failed for {}: {}", host, e);
            }
        }
    }
    resolved
}

/// Spawn a background task that periodically re-discovers the public IP
/// and updates the IP overlay.
pub fn spawn_periodic_ip_update(own_did: Option<String>, interval_secs: u64) {
    tokio::spawn(async move {
        let stun_ip = discover_public_ip().await;
        update_validator_ips(own_did.as_deref(), stun_ip).await;

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
        interval.tick().await;
        loop {
            interval.tick().await;
            let stun_ip = discover_public_ip().await;
            update_validator_ips(own_did.as_deref(), stun_ip).await;
        }
    });
}
