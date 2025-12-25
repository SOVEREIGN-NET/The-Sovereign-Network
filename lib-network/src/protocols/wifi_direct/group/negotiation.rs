//! P2P Group Owner Negotiation
//!
//! Handles GO negotiation logic including device capability scoring and tie-breaker resolution

use anyhow::Result;
use tracing::{debug, info, warn};
use crate::protocols::wifi_direct::wifi_direct::{
    P2PGoNegotiation, DeviceCapability, GroupCapability,
};

pub struct GoNegotiator {
    node_id: [u8; 32],
}

impl GoNegotiator {
    pub fn new(node_id: [u8; 32]) -> Result<Self> {
        debug!("Initializing GO Negotiator");
        Ok(Self { node_id })
    }

    /// Perform GO negotiation with a peer
    pub async fn perform_negotiation(
        &self,
        peer_address: &str,
        peer_negotiation: &P2PGoNegotiation,
    ) -> Result<bool> {
        debug!(peer = peer_address, "Performing GO negotiation");

        // Get our negotiation parameters
        let our_negotiation = self.get_default_negotiation();

        // Determine who should be GO based on intent and tie-breaker
        let we_should_be_go = self.determine_group_owner(&our_negotiation, peer_negotiation)?;

        if we_should_be_go {
            info!(peer = peer_address, "We will be Group Owner");
        } else {
            info!(peer = peer_address, "Peer will be Group Owner");
        }

        Ok(we_should_be_go)
    }

    /// Determine if we should be Group Owner
    fn determine_group_owner(
        &self,
        our_negotiation: &P2PGoNegotiation,
        peer_negotiation: &P2PGoNegotiation,
    ) -> Result<bool> {
        // Compare GO intent values
        if our_negotiation.go_intent > peer_negotiation.go_intent {
            debug!("We have higher GO intent - we should be GO");
            return Ok(true);
        }

        if peer_negotiation.go_intent > our_negotiation.go_intent {
            debug!("Peer has higher GO intent - peer should be GO");
            return Ok(false);
        }

        // Intent is equal - use tie-breaker
        if our_negotiation.tie_breaker != peer_negotiation.tie_breaker {
            let we_are_go = our_negotiation.tie_breaker;
            debug!(
                tie_breaker = we_are_go,
                "Using tie-breaker bit for GO determination"
            );
            return Ok(we_are_go);
        }

        // Both intent and tie-breaker are equal - compare device capabilities
        let our_score = self.calculate_capability_score(&our_negotiation);
        let peer_score = self.calculate_capability_score(peer_negotiation);

        debug!(
            our_score = our_score,
            peer_score = peer_score,
            "Using capability score for GO determination"
        );

        Ok(our_score >= peer_score)
    }

    /// Calculate device capability score
    fn calculate_capability_score(&self, negotiation: &P2PGoNegotiation) -> f64 {
        let mut score = 0.0;

        // Service discovery capability
        if negotiation.device_capability.service_discovery {
            score += 0.1;
        }

        // P2P client discoverability
        if negotiation.device_capability.p2p_client_discoverability {
            score += 0.1;
        }

        // Concurrent operation
        if negotiation.device_capability.concurrent_operation {
            score += 0.2;
        }

        // Infrastructure managed
        if negotiation.device_capability.p2p_infrastructure_managed {
            score += 0.15;
        }

        // Device limit
        if negotiation.device_capability.p2p_device_limit {
            score += 0.1;
        }

        // Invitation procedure
        if negotiation.device_capability.p2p_invitation_procedure {
            score += 0.1;
        }

        // Group owner capability
        if negotiation.group_capability.p2p_group_owner {
            score += 0.15;
        }

        // Persistent group
        if negotiation.group_capability.persistent_p2p_group {
            score += 0.1;
        }

        // Intra-BSS distribution
        if negotiation.group_capability.intra_bss_distribution {
            score += 0.05;
        }

        score
    }

    /// Get default GO negotiation parameters
    pub fn get_default_negotiation(&self) -> P2PGoNegotiation {
        P2PGoNegotiation {
            go_intent: 7, // Moderate intent (0-15)
            tie_breaker: rand::random(),
            device_capability: DeviceCapability {
                service_discovery: true,
                p2p_client_discoverability: true,
                concurrent_operation: true,
                p2p_infrastructure_managed: false,
                p2p_device_limit: false,
                p2p_invitation_procedure: true,
            },
            group_capability: GroupCapability {
                p2p_group_owner: false,
                persistent_p2p_group: true,
                group_limit: false,
                intra_bss_distribution: true,
                cross_connection: true,
                persistent_reconnect: true,
                group_formation: true,
                ip_address_allocation: true,
            },
            channel_list: vec![1, 6, 11], // Common 2.4GHz channels
            config_timeout: 100,           // 100ms negotiation timeout
        }
    }

    /// Derive P2P BSSID from network name
    pub fn derive_p2p_bssid(&self, network_name: &str) -> String {
        // Simple deterministic derivation from network name
        let mut seed = 0u32;
        for byte in network_name.as_bytes() {
            seed = seed.wrapping_mul(31).wrapping_add(*byte as u32);
        }

        // Create BSSID with deterministic last 2 octets
        let last_byte = ((seed & 0xFF) as u8);
        let second_last = (((seed >> 8) & 0xFF) as u8);
        format!(
            "02:1A:11:FF:{:02X}:{:02X}",
            second_last, last_byte
        )
    }

    /// Generate P2P Group ID
    pub fn generate_group_id(&self) -> String {
        format!(
            "DIRECT-{:02X}{:02X}",
            self.node_id[0], self.node_id[1]
        )
    }
}
