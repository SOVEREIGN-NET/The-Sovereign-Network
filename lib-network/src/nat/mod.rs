//! NAT Traversal and Endpoint Reachability (#2200)
//!
//! Provides NAT type detection, public endpoint discovery via STUN,
//! and reachability evaluation for routing decisions.

pub mod stun;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Classification of NAT behavior for a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    /// Direct public IP — no NAT.
    Public,
    /// Full-cone NAT: any external host can send packets to mapped address.
    FullCone,
    /// Restricted-cone NAT: only hosts the peer has sent to can send back.
    RestrictedCone,
    /// Port-restricted cone NAT: only hosts+ports the peer has sent to can send back.
    PortRestrictedCone,
    /// Symmetric NAT: each destination gets a different mapped address.
    Symmetric,
    /// NAT type not yet determined.
    Unknown,
}

/// Reachability state of a peer from the perspective of the public internet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReachabilityState {
    /// Peer is directly reachable on its advertised public endpoint.
    Direct,
    /// Peer is reachable via NAT traversal (e.g., hole punching).
    NatTraversable,
    /// Peer requires a relay (TURN or long-range relay).
    RelayRequired,
    /// Reachability has not been determined.
    Unknown,
    /// Peer is unreachable (all probes failed).
    Unreachable,
}

/// NAT and reachability metadata for a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatState {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Public endpoint observed by a STUN server (if available).
    pub public_endpoint: Option<SocketAddr>,
    /// Endpoint of a relay that can reach this peer (if applicable).
    pub relay_endpoint: Option<SocketAddr>,
    /// Last time reachability was verified (Unix timestamp).
    pub last_verified_at: Option<u64>,
    /// Reachability classification.
    pub reachability: ReachabilityState,
    /// Reason for the current reachability state.
    pub reason: String,
}

impl Default for NatState {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            public_endpoint: None,
            relay_endpoint: None,
            last_verified_at: None,
            reachability: ReachabilityState::Unknown,
            reason: "Not yet evaluated".to_string(),
        }
    }
}

impl NatState {
    /// Create a new `NatState` for a publicly reachable peer.
    pub fn public(endpoint: SocketAddr, now: u64) -> Self {
        Self {
            nat_type: NatType::Public,
            public_endpoint: Some(endpoint),
            relay_endpoint: None,
            last_verified_at: Some(now),
            reachability: ReachabilityState::Direct,
            reason: "Public endpoint confirmed".to_string(),
        }
    }

    /// Create a new `NatState` for a NAT'd but traversable peer.
    pub fn nat_traversable(nat_type: NatType, public_endpoint: SocketAddr, now: u64) -> Self {
        let reason = format!("NAT type: {:?}", nat_type);
        Self {
            nat_type,
            public_endpoint: Some(public_endpoint),
            relay_endpoint: None,
            last_verified_at: Some(now),
            reachability: ReachabilityState::NatTraversable,
            reason,
        }
    }

    /// Create a new `NatState` for a peer that requires a relay.
    pub fn relay_required(relay_endpoint: SocketAddr, now: u64) -> Self {
        Self {
            nat_type: NatType::Symmetric,
            public_endpoint: None,
            relay_endpoint: Some(relay_endpoint),
            last_verified_at: Some(now),
            reachability: ReachabilityState::RelayRequired,
            reason: "Symmetric NAT — relay required".to_string(),
        }
    }

    /// Returns true if the reachability information is fresh (within TTL).
    pub fn is_fresh(&self, now: u64, ttl_secs: u64) -> bool {
        self.last_verified_at
            .map(|t| now.saturating_sub(t) <= ttl_secs)
            .unwrap_or(false)
    }
}

/// Evaluate whether a peer is reachable for routing purposes.
///
/// A peer is considered reachable if:
/// - It has a fresh reachability evaluation, AND
/// - Its reachability state is Direct or NatTraversable, OR
/// - It has a relay endpoint available for RelayRequired.
pub fn is_reachable(nat_state: Option<&NatState>, now: u64, ttl_secs: u64) -> bool {
    let Some(state) = nat_state else {
        // Without NAT state, fall back to assuming reachable if we have an endpoint
        return true;
    };

    // If stale, consider unreachable until re-evaluated
    if !state.is_fresh(now, ttl_secs) {
        return false;
    }

    match state.reachability {
        ReachabilityState::Direct | ReachabilityState::NatTraversable => true,
        ReachabilityState::RelayRequired => state.relay_endpoint.is_some(),
        ReachabilityState::Unknown => true, // Conservative: allow until proven otherwise
        ReachabilityState::Unreachable => false,
    }
}

/// Summarize reachability across a collection of peers.
#[derive(Debug, Clone, Default)]
pub struct ReachabilitySummary {
    pub direct: usize,
    pub nat_traversable: usize,
    pub relay_required: usize,
    pub unknown: usize,
    pub unreachable: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_state_freshness() {
        let state = NatState::public("1.2.3.4:5678".parse().unwrap(), 1000);
        assert!(state.is_fresh(1000, 300));
        assert!(state.is_fresh(1299, 300));
        assert!(!state.is_fresh(1301, 300));
    }

    #[test]
    fn test_is_reachable_direct() {
        let state = NatState::public("1.2.3.4:5678".parse().unwrap(), 1000);
        assert!(is_reachable(Some(&state), 1000, 300));
    }

    #[test]
    fn test_is_reachable_stale() {
        let state = NatState::public("1.2.3.4:5678".parse().unwrap(), 1000);
        assert!(!is_reachable(Some(&state), 2000, 300));
    }

    #[test]
    fn test_is_reachable_unreachable() {
        let state = NatState {
            nat_type: NatType::Symmetric,
            public_endpoint: None,
            relay_endpoint: None,
            last_verified_at: Some(1000),
            reachability: ReachabilityState::Unreachable,
            reason: "All probes failed".to_string(),
        };
        assert!(!is_reachable(Some(&state), 1000, 300));
    }

    #[test]
    fn test_is_reachable_relay_required_with_endpoint() {
        let state = NatState::relay_required("5.6.7.8:9012".parse().unwrap(), 1000);
        assert!(is_reachable(Some(&state), 1000, 300));
    }

    #[test]
    fn test_is_reachable_none_fallback() {
        // No NAT state -> conservative fallback to reachable
        assert!(is_reachable(None, 1000, 300));
    }
}
