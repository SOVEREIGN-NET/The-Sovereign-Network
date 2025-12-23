//! Command types for Bluetooth mesh protocol (functional core outputs).

use crate::protocols::zhtp_auth::ZhtpAuthVerification;

#[derive(Debug, Clone, Copy)]
pub enum AuthLogLevel {
    Info,
    Warn,
}

#[derive(Debug, Clone)]
pub enum AuthCommand {
    Log {
        level: AuthLogLevel,
        message: String,
    },
    StoreVerifiedPeer {
        peer_address: String,
        verification: ZhtpAuthVerification,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::zhtp_auth::NodeCapabilities;

    #[test]
    fn test_auth_command_log() {
        let cmd = AuthCommand::Log {
            level: AuthLogLevel::Info,
            message: "ok".to_string(),
        };

        match cmd {
            AuthCommand::Log { message, .. } => {
                assert_eq!(message, "ok");
            }
            _ => panic!("Expected log command"),
        }
    }

    #[test]
    fn test_auth_command_store() {
        let verification = ZhtpAuthVerification {
            authenticated: true,
            peer_pubkey: vec![1],
            capabilities: NodeCapabilities {
                has_dht: false,
                can_relay: false,
                max_bandwidth: 0,
                protocols: vec!["ble".to_string()],
                reputation: 0,
                quantum_secure: false,
            },
            trust_score: 0.5,
        };

        let cmd = AuthCommand::StoreVerifiedPeer {
            peer_address: "peer-y".to_string(),
            verification,
        };

        match cmd {
            AuthCommand::StoreVerifiedPeer { peer_address, .. } => {
                assert_eq!(peer_address, "peer-y");
            }
            _ => panic!("Expected store command"),
        }
    }
}
