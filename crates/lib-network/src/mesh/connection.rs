use serde::{Deserialize, Serialize};
use lib_crypto::PublicKey;
use crate::protocols::NetworkProtocol;

/// Individual mesh connection between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConnection {
    /// Connected peer identity
    pub peer_id: PublicKey,
    /// Connection protocol (Bluetooth, WiFi Direct, LoRaWAN, etc.)
    pub protocol: NetworkProtocol,
    /// Peer's socket address for sending relay queries (IP:port or Bluetooth address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<String>,
    /// Connection strength/quality (0.0 to 1.0)
    pub signal_strength: f64,
    /// Bandwidth capacity in bytes/second
    pub bandwidth_capacity: u64,
    /// Connection latency in milliseconds
    pub latency_ms: u32,
    /// When connection was established (Unix timestamp)
    pub connected_at: u64,
    /// Total data transferred
    pub data_transferred: u64,
    /// Tokens earned from this connection
    pub tokens_earned: u64,
    /// Connection stability score
    pub stability_score: f64,
    /// ZHTP authentication status
    #[serde(default)]
    pub zhtp_authenticated: bool,
    /// Post-quantum encryption enabled
    #[serde(default = "default_true")]
    pub quantum_secure: bool,
    /// Peer's Dilithium public key (for signature verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_dilithium_pubkey: Option<Vec<u8>>,
    /// Kyber shared secret (for encryption) - NOT serialized for security
    #[serde(skip)]
    pub kyber_shared_secret: Option<Vec<u8>>,
    /// Peer trust score (0.0 - 1.0)
    #[serde(default)]
    pub trust_score: f64,
    /// Bootstrap mode: connection is unauthenticated and can only request blockchain data
    /// Used by new nodes downloading blockchain before creating identity
    #[serde(default)]
    pub bootstrap_mode: bool,
}

fn default_true() -> bool {
    true
}
