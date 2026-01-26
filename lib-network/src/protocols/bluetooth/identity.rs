//! Identity and privacy helpers for Bluetooth mesh protocol.

use sha2::{Digest, Sha256};

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Generate secure node identifier from node_id and MAC (never expose raw MAC)
    #[allow(dead_code)]
    pub(crate) fn generate_secure_node_id(&self, mac: &[u8; 6]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.node_id);
        hasher.update(b"ZHTP_SECURE_NODE_ID");
        hasher.update(mac);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Generate encrypted MAC hash (one-way, cannot recover original MAC)
    #[allow(dead_code)]
    pub(crate) fn generate_encrypted_mac_hash(&self, mac: &[u8; 6]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.node_id);
        hasher.update(b"ZHTP_MAC_PRIVACY");
        hasher.update(mac);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        hasher.update(&(timestamp / 3600).to_le_bytes());
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}
