//! Validator IP self-registration via STUN discovery.
//!
//! On startup, each node discovers its public IP using STUN and updates the
//! `network_address` field in the local validator registry. This ensures ZDNS
//! returns real IPs instead of relying on hardcoded config values.
//!
//! A background task re-checks the public IP periodically (default: 5 minutes)
//! to handle IP changes on nodes with dynamic addresses.

use std::net::{Ipv4Addr, SocketAddr};
use tracing::{info, warn};

/// Discover this node's public IPv4 address via STUN.
pub async fn discover_public_ip() -> Option<Ipv4Addr> {
    let stun = lib_network::nat::stun::StunClient::new();
    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    match stun.discover_public_endpoint(bind).await {
        Ok(endpoint) => {
            if let std::net::IpAddr::V4(ip) = endpoint.ip() {
                info!("🌐 STUN discovered public IP: {}", ip);
                Some(ip)
            } else {
                warn!("STUN returned IPv6 address {}, skipping", endpoint.ip());
                None
            }
        }
        Err(e) => {
            tracing::debug!("STUN discovery skipped: {} (not needed if endpoints are configured)", e);
            None
        }
    }
}

/// Update all validator registry entries that have hostname-based `network_address`
/// by resolving them to IPs. Also update this node's own entry with STUN-discovered IP.
///
/// Called once after startup completes and periodically thereafter.
pub async fn update_validator_ips(own_did: Option<&str>, stun_ip: Option<Ipv4Addr>) {
    let blockchain_arc = match crate::runtime::blockchain_provider::get_global_blockchain().await {
        Ok(bc) => bc,
        Err(_) => return,
    };

    let mut blockchain = blockchain_arc.write().await;
    let mut updated = 0;

    // 1. Update own entry with STUN-discovered IP
    if let (Some(did), Some(ip)) = (own_did, stun_ip) {
        if let Some(validator) = blockchain.validator_registry.get_mut(did) {
            let port = validator
                .network_address
                .split(':')
                .last()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(9334);
            let new_addr = format!("{}:{}", ip, port);
            if validator.network_address != new_addr {
                info!(
                    "🌐 Updated own validator IP: {} → {}",
                    validator.network_address, new_addr
                );
                validator.network_address = new_addr;
                updated += 1;
            }
        }
    }

    // 2. Resolve hostname-based entries for other validators.
    //    This runs in a blocking task since DNS resolution is sync.
    let entries_to_resolve: Vec<(String, String)> = blockchain
        .validator_registry
        .iter()
        .filter(|(did, _)| own_did.map_or(true, |own| *did != own))
        .filter(|(_, v)| {
            // Only resolve entries that aren't already raw IPs
            let host = v.network_address.split(':').next().unwrap_or("");
            host.parse::<Ipv4Addr>().is_err() && !host.is_empty()
        })
        .map(|(did, v)| (did.clone(), v.network_address.clone()))
        .collect();

    // Drop blockchain lock before doing DNS resolution
    drop(blockchain);

    if !entries_to_resolve.is_empty() {
        let resolved = resolve_hostnames(entries_to_resolve).await;

        if !resolved.is_empty() {
            let mut blockchain = blockchain_arc.write().await;
            for (did, new_addr) in &resolved {
                if let Some(validator) = blockchain.validator_registry.get_mut(did) {
                    info!(
                        "🌐 Resolved validator IP: {} → {}",
                        validator.network_address, new_addr
                    );
                    validator.network_address = new_addr.clone();
                    updated += 1;
                }
            }
        }
    }

    if updated > 0 {
        info!("🌐 Updated {} validator network addresses", updated);
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

        // Use tokio's async DNS resolution
        match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(mut addrs) => {
                // Prefer IPv4
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
/// and updates the validator registry.
pub fn spawn_periodic_ip_update(own_did: Option<String>, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
        // Skip the first tick (we already ran once at startup)
        interval.tick().await;

        loop {
            interval.tick().await;
            let stun_ip = discover_public_ip().await;
            update_validator_ips(own_did.as_deref(), stun_ip).await;
        }
    });
}
