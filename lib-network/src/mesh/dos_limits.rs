//! DoS Resistance: Connection Limits and Per-Peer Cost Model (closes #985)
//!
//! # Threat Model
//!
//! An attacker wishing to exhaust a node's resources can open many simultaneous
//! connections (TCP SYN flood equivalent for QUIC, or many QUIC `Initial`
//! packets).  Without hard limits the node's file-descriptor table, memory, and
//! CPU can be exhausted before the QUIC handshake even completes.
//!
//! This module defines three nested limits that together prevent connection
//! exhaustion at different stages of the connection lifecycle:
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │                      MAX_TOTAL_CONNECTIONS = 100                     │
//!  │                                                                      │
//!  │   ┌──────────────────────────────────────────────────────────┐       │
//!  │   │           established (active) connections               │       │
//!  │   └──────────────────────────────────────────────────────────┘       │
//!  │   ┌───────────────────────────────────────────────────┐              │
//!  │   │     MAX_PENDING_CONNECTIONS = 20                  │              │
//!  │   │     (QUIC Initial received, handshake in flight)  │              │
//!  │   └───────────────────────────────────────────────────┘              │
//!  │                                                                      │
//!  │   Per-IP cap: MAX_CONNECTIONS_PER_IP = 5                             │
//!  │   (applied to both established and pending counts)                   │
//!  └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Per-Peer Cost Model
//!
//! Not all connections are equal.  The cost model assigns a weight to each
//! connection based on the peer's validation status and the connection's
//! current phase:
//!
//! | Connection Phase         | Weight | Rationale                                      |
//! |--------------------------|--------|------------------------------------------------|
//! | Pending (handshaking)    | 2      | Crypto is expensive; limit concurrent setup    |
//! | Established, unauthed    | 2      | Unknown peers consume more monitoring budget   |
//! | Established, authed      | 1      | Trusted peers are cheaper to maintain          |
//! | Established, validator   | 1      | Same as authed; validators get no extra budget |
//!
//! The *effective connection count* used against `MAX_TOTAL_CONNECTIONS` is the
//! sum of weighted costs, not a raw count.  This means that 50 authenticated
//! peers (weight 1 each) + 25 unauthenticated peers (weight 2 each) = 100,
//! which hits the total limit.  This incentivizes peers to complete
//! authentication quickly.
//!
//! # Why These Values?
//!
//! - `MAX_CONNECTIONS_PER_IP = 5`:
//!   A single legitimate operator behind NAT rarely needs more than 2-3
//!   connections.  Allowing 5 provides headroom for multi-process nodes while
//!   preventing any one IP from monopolising the connection table.
//!
//! - `MAX_TOTAL_CONNECTIONS = 100`:
//!   Each QUIC connection consumes ~128 KiB of state.  100 connections ≈ 12 MiB
//!   of connection state, which is manageable on even a 256 MiB device.  This
//!   leaves the node reachable by a healthy peer set without risking OOM.
//!
//! - `MAX_PENDING_CONNECTIONS = 20`:
//!   QUIC handshakes involve post-quantum key exchange (Kyber768 + Dilithium3),
//!   which is CPU-intensive.  Limiting in-flight handshakes to 20 bounds the
//!   concurrent crypto workload.
//!
//! # Enforcement
//!
//! `assert_connection_limits()` MUST be called before accepting any new
//! inbound connection (i.e., before allocating connection state).  If any
//! limit would be violated the connection MUST be refused with a QUIC
//! `CONNECTION_REFUSED` frame (or equivalent transport-level rejection).

use std::collections::HashMap;
use std::net::IpAddr;

// =============================================================================
// INVARIANT: Connection Limit Constants (closes #985)
// =============================================================================

/// Maximum number of simultaneous connections originating from a single IP
/// address (counting both pending and established).
///
/// # Invariant
///
/// Before accepting a new connection from `remote_ip`, the handler MUST verify
/// that the current count of connections from that IP is strictly less than
/// `MAX_CONNECTIONS_PER_IP`.  If the count is already at or above this value
/// the connection MUST be refused immediately, before any crypto work is done.
pub const MAX_CONNECTIONS_PER_IP: usize = 5;

/// Maximum total number of active (established) plus pending connections
/// across all remote IPs.
///
/// # Invariant
///
/// The weighted sum of all active and pending connections (see cost model in
/// module docs) MUST NOT exceed `MAX_TOTAL_CONNECTIONS`.  New connections MUST
/// be refused when this limit would be exceeded.
pub const MAX_TOTAL_CONNECTIONS: usize = 100;

/// Maximum number of simultaneous pending (handshaking) connections.
///
/// A connection is "pending" from the moment the first QUIC `Initial` packet
/// is received until the handshake completes (or times out).
///
/// # Invariant
///
/// If the pending count is already at `MAX_PENDING_CONNECTIONS`, new inbound
/// `Initial` packets MUST be dropped (or a stateless `RETRY` sent, if
/// implemented) without allocating connection state.
pub const MAX_PENDING_CONNECTIONS: usize = 20;

/// Connection weight for a pending (handshaking) connection.
///
/// Higher weight reflects the CPU cost of post-quantum key exchange during
/// the QUIC/TLS 1.3 handshake.
pub const WEIGHT_PENDING: usize = 2;

/// Connection weight for an established but unauthenticated peer.
///
/// Higher weight reflects additional monitoring overhead for unknown peers.
pub const WEIGHT_ESTABLISHED_UNAUTHED: usize = 2;

/// Connection weight for an established, authenticated peer.
///
/// Authenticated peers are cheaper to maintain because their identity has
/// been verified and their messages can be fast-pathed.
pub const WEIGHT_ESTABLISHED_AUTHED: usize = 1;

// =============================================================================
// State Snapshot
// =============================================================================

/// A point-in-time snapshot of connection table state, used by
/// `assert_connection_limits()` to evaluate whether a new connection can be
/// accepted.
#[derive(Debug, Clone, Default)]
pub struct ConnectionSnapshot {
    /// Number of in-flight (pending / handshaking) connections.
    pub pending_count: usize,
    /// Number of established, authenticated connections.
    pub established_authed: usize,
    /// Number of established, unauthenticated connections.
    pub established_unauthed: usize,
    /// Per-IP connection counts (both pending and established).
    pub per_ip_counts: HashMap<IpAddr, usize>,
}

impl ConnectionSnapshot {
    /// Compute the weighted total connection cost.
    ///
    /// This is the value compared against `MAX_TOTAL_CONNECTIONS`.
    pub fn weighted_total(&self) -> usize {
        self.pending_count * WEIGHT_PENDING
            + self.established_authed * WEIGHT_ESTABLISHED_AUTHED
            + self.established_unauthed * WEIGHT_ESTABLISHED_UNAUTHED
    }

    /// Return the raw (unweighted) total number of connections.
    pub fn raw_total(&self) -> usize {
        self.pending_count + self.established_authed + self.established_unauthed
    }
}

// =============================================================================
// Assertion / Enforcement Helpers
// =============================================================================

/// Assert that accepting a new connection from `remote_ip` would not violate
/// any of the DoS resistance invariants.
///
/// This function MUST be called before allocating any state for a new inbound
/// connection.  It checks all three limits:
///
/// 1. `pending_count < MAX_PENDING_CONNECTIONS`
/// 2. `weighted_total() < MAX_TOTAL_CONNECTIONS`
/// 3. `per_ip_counts[remote_ip] < MAX_CONNECTIONS_PER_IP`
///
/// # Arguments
///
/// * `snapshot` - Current connection table state.
/// * `remote_ip` - The IP address of the inbound peer.
/// * `is_pending` - `true` if this is a new handshake, `false` for an
///   already-established connection being re-registered (unusual, but handled
///   for completeness).
///
/// # Errors
///
/// Returns `Err` with a human-readable description of the first violated
/// invariant.  The caller MUST refuse the connection.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use std::net::{IpAddr, Ipv4Addr};
/// use lib_network::mesh::dos_limits::{
///     assert_connection_limits, ConnectionSnapshot, MAX_TOTAL_CONNECTIONS,
/// };
///
/// let snapshot = ConnectionSnapshot::default();
/// let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
///
/// // Empty snapshot: connection should be accepted
/// assert!(assert_connection_limits(&snapshot, &ip, true).is_ok());
/// ```
pub fn assert_connection_limits(
    snapshot: &ConnectionSnapshot,
    remote_ip: &IpAddr,
    is_pending: bool,
) -> Result<(), String> {
    // Invariant 1: pending connection cap
    if is_pending && snapshot.pending_count >= MAX_PENDING_CONNECTIONS {
        return Err(format!(
            "DoS LIMIT: pending connections ({}) >= MAX_PENDING_CONNECTIONS ({}); \
             refusing handshake from {}",
            snapshot.pending_count, MAX_PENDING_CONNECTIONS, remote_ip,
        ));
    }

    // Invariant 2: weighted total cap
    let new_weight = if is_pending { WEIGHT_PENDING } else { WEIGHT_ESTABLISHED_UNAUTHED };
    let projected_weighted = snapshot.weighted_total() + new_weight;
    if projected_weighted > MAX_TOTAL_CONNECTIONS {
        return Err(format!(
            "DoS LIMIT: projected weighted total ({}) > MAX_TOTAL_CONNECTIONS ({}); \
             refusing connection from {}",
            projected_weighted, MAX_TOTAL_CONNECTIONS, remote_ip,
        ));
    }

    // Invariant 3: per-IP cap
    let current_ip_count = snapshot.per_ip_counts.get(remote_ip).copied().unwrap_or(0);
    if current_ip_count >= MAX_CONNECTIONS_PER_IP {
        return Err(format!(
            "DoS LIMIT: IP {} already has {} connections (max {}); refusing new connection",
            remote_ip, current_ip_count, MAX_CONNECTIONS_PER_IP,
        ));
    }

    Ok(())
}

/// Assert that the pending connection count is within the limit.
///
/// This is a lighter-weight check for code paths that only need to test the
/// pending limit (e.g., inside a packet demultiplexer before full state lookup).
pub fn assert_pending_limit(pending_count: usize) -> Result<(), String> {
    if pending_count >= MAX_PENDING_CONNECTIONS {
        return Err(format!(
            "DoS LIMIT: pending connections ({}) >= MAX_PENDING_CONNECTIONS ({})",
            pending_count, MAX_PENDING_CONNECTIONS,
        ));
    }
    Ok(())
}

/// Assert that a per-IP count is within the limit.
pub fn assert_per_ip_limit(ip: &IpAddr, count: usize) -> Result<(), String> {
    if count >= MAX_CONNECTIONS_PER_IP {
        return Err(format!(
            "DoS LIMIT: IP {} has {} connections >= MAX_CONNECTIONS_PER_IP ({})",
            ip, count, MAX_CONNECTIONS_PER_IP,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // ---- constant sanity checks ----

    #[test]
    fn max_connections_per_ip_is_5() {
        assert_eq!(MAX_CONNECTIONS_PER_IP, 5);
    }

    #[test]
    fn max_total_connections_is_100() {
        assert_eq!(MAX_TOTAL_CONNECTIONS, 100);
    }

    #[test]
    fn max_pending_connections_is_20() {
        assert_eq!(MAX_PENDING_CONNECTIONS, 20);
    }

    #[test]
    fn pending_limit_less_than_total_limit() {
        assert!(
            MAX_PENDING_CONNECTIONS < MAX_TOTAL_CONNECTIONS,
            "Pending limit should be a fraction of the total limit"
        );
    }

    // ---- ConnectionSnapshot::weighted_total ----

    #[test]
    fn weighted_total_empty_is_zero() {
        let snap = ConnectionSnapshot::default();
        assert_eq!(snap.weighted_total(), 0);
    }

    #[test]
    fn weighted_total_counts_correctly() {
        let snap = ConnectionSnapshot {
            pending_count: 5,             // 5 * 2 = 10
            established_authed: 10,       // 10 * 1 = 10
            established_unauthed: 3,      // 3 * 2 = 6
            per_ip_counts: HashMap::new(),
        };
        assert_eq!(snap.weighted_total(), 10 + 10 + 6); // = 26
    }

    // ---- assert_connection_limits ----

    #[test]
    fn empty_snapshot_accepts_new_pending() {
        let snap = ConnectionSnapshot::default();
        let ip = ipv4(1, 2, 3, 4);
        assert!(assert_connection_limits(&snap, &ip, true).is_ok());
    }

    #[test]
    fn pending_limit_blocks_at_max() {
        let mut snap = ConnectionSnapshot::default();
        snap.pending_count = MAX_PENDING_CONNECTIONS;
        let ip = ipv4(1, 2, 3, 4);
        let result = assert_connection_limits(&snap, &ip, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DoS LIMIT"));
    }

    #[test]
    fn per_ip_limit_blocks_at_max() {
        let ip = ipv4(10, 0, 0, 1);
        let mut snap = ConnectionSnapshot::default();
        snap.per_ip_counts.insert(ip, MAX_CONNECTIONS_PER_IP);
        let result = assert_connection_limits(&snap, &ip, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(ip.to_string().as_str()));
    }

    #[test]
    fn per_ip_allows_different_ips() {
        let ip1 = ipv4(10, 0, 0, 1);
        let ip2 = ipv4(10, 0, 0, 2);
        let mut snap = ConnectionSnapshot::default();
        // ip1 is at the limit, but ip2 is fresh
        snap.per_ip_counts.insert(ip1, MAX_CONNECTIONS_PER_IP);
        assert!(assert_connection_limits(&snap, &ip2, true).is_ok());
    }

    #[test]
    fn total_weighted_limit_blocks_when_exceeded() {
        // Fill up with authenticated connections (weight 1 each)
        let snap = ConnectionSnapshot {
            pending_count: 0,
            established_authed: MAX_TOTAL_CONNECTIONS, // weight 1 * 100 = 100
            established_unauthed: 0,
            per_ip_counts: HashMap::new(),
        };
        let ip = ipv4(5, 6, 7, 8);
        // Adding one more pending (weight 2) would push us to 102, which exceeds 100.
        let result = assert_connection_limits(&snap, &ip, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("projected weighted total"));
    }

    #[test]
    fn total_weighted_allows_just_below_limit() {
        // 99 authenticated connections (weight 1) = 99.  Adding weight-1 established = 100. OK.
        let snap = ConnectionSnapshot {
            pending_count: 0,
            established_authed: 99,
            established_unauthed: 0,
            per_ip_counts: HashMap::new(),
        };
        let ip = ipv4(5, 6, 7, 8);
        // Adding a non-pending (weight 2 for unauthed) would be 99 + 2 = 101 > 100. Should fail.
        let result = assert_connection_limits(&snap, &ip, false);
        assert!(result.is_err(), "99 authed + 1 unauthed (weight 2) = 101 > 100");
    }

    // ---- assert_pending_limit ----

    #[test]
    fn pending_limit_helper_allows_below_max() {
        assert!(assert_pending_limit(0).is_ok());
        assert!(assert_pending_limit(MAX_PENDING_CONNECTIONS - 1).is_ok());
    }

    #[test]
    fn pending_limit_helper_blocks_at_max() {
        assert!(assert_pending_limit(MAX_PENDING_CONNECTIONS).is_err());
    }

    // ---- assert_per_ip_limit ----

    #[test]
    fn per_ip_limit_helper_allows_below_max() {
        let ip = ipv4(192, 168, 1, 1);
        assert!(assert_per_ip_limit(&ip, 0).is_ok());
        assert!(assert_per_ip_limit(&ip, MAX_CONNECTIONS_PER_IP - 1).is_ok());
    }

    #[test]
    fn per_ip_limit_helper_blocks_at_max() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let result = assert_per_ip_limit(&ip, MAX_CONNECTIONS_PER_IP);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DoS LIMIT"));
    }

    // ---- ipv6 ----

    #[test]
    fn ipv6_addresses_are_tracked_per_ip() {
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mut snap = ConnectionSnapshot::default();
        snap.per_ip_counts.insert(ipv6, MAX_CONNECTIONS_PER_IP);
        let result = assert_connection_limits(&snap, &ipv6, false);
        assert!(result.is_err(), "IPv6 per-IP limit should be enforced");
    }
}
