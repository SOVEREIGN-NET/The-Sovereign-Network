//! Event types for Bluetooth mesh protocol (functional core inputs).

use crate::protocols::zhtp_auth::ZhtpAuthVerification;

#[derive(Debug, Clone)]
pub enum AuthEvent {
    VerificationComplete {
        peer_address: String,
        verification: ZhtpAuthVerification,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::zhtp_auth::NodeCapabilities;

    #[test]
    fn test_auth_event_construction() {
        let verification = ZhtpAuthVerification {
            authenticated: true,
            peer_pubkey: vec![1, 2, 3],
            capabilities: NodeCapabilities {
                has_dht: false,
                can_relay: false,
                max_bandwidth: 0,
                protocols: vec!["ble".to_string()],
                reputation: 0,
                quantum_secure: false,
            },
            trust_score: 1.0,
        };

        let event = AuthEvent::VerificationComplete {
            peer_address: "peer-x".to_string(),
            verification,
        };

        match event {
            AuthEvent::VerificationComplete { peer_address, .. } => {
                assert_eq!(peer_address, "peer-x");
            }
        }
    }
}
