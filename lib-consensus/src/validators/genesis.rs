//! Genesis Validator Registration
//!
//! This module handles validator registration during genesis block creation.
//! It provides types and utilities for multi-node network initialization.

use anyhow::Result;
use lib_crypto::{Hash, PublicKey};
use lib_identity::IdentityId;

/// Genesis validator configuration for multi-node network initialization
///
/// This struct represents a validator that should be registered during
/// genesis block creation. It contains all necessary information to
/// bootstrap a validator into the consensus system.
#[derive(Debug, Clone)]
pub struct GenesisValidator {
    /// Validator identity ID (DID hash) - should be USER identity, not node identity
    pub identity_id: Hash,
    /// Initial stake amount (in micro-SOV)
    pub stake: u64,
    /// Storage capacity provided (in bytes)
    pub storage_provided: u64,
    /// Commission rate (basis points, 0-10000)
    pub commission_rate: u16,
    /// Network endpoints for peer communication
    pub endpoints: Vec<String>,
    /// Consensus public key (post-quantum)
    pub consensus_key: Option<PublicKey>,
    /// Physical node device ID that runs validator operations (optional)
    /// Allows tracking which node device performs operations for this USER identity validator
    pub node_device_id: Option<IdentityId>,
}

impl GenesisValidator {
    /// Create a new genesis validator
    pub fn new(
        identity_id: Hash,
        stake: u64,
        storage_provided: u64,
        commission_rate: u16,
        endpoints: Vec<String>,
        consensus_key: Option<PublicKey>,
    ) -> Self {
        Self {
            identity_id,
            stake,
            storage_provided,
            commission_rate,
            endpoints,
            consensus_key,
            node_device_id: None,
        }
    }

    /// Parse identity from DID or hex string
    ///
    /// Accepts:
    /// - DID format: "did:zhtp:hexstring"
    /// - Hex format: "hexstring"
    /// - Raw string (will be hashed)
    pub fn parse_identity(identity_str: &str) -> Hash {
        if identity_str.starts_with("did:") {
            // Extract hash from DID
            let did_parts: Vec<&str> = identity_str.split(':').collect();
            if did_parts.len() >= 3 {
                // Convert hex string to Hash
                if let Ok(bytes) = hex::decode(did_parts[2]) {
                    if bytes.len() == 32 {
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(&bytes);
                        return Hash(hash_bytes);
                    }
                }
            }
        } else {
            // Try to parse as hex hash string
            if let Ok(bytes) = hex::decode(identity_str) {
                if bytes.len() == 32 {
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes.copy_from_slice(&bytes);
                    return Hash(hash_bytes);
                }
            }
        }

        // Fallback: hash the string
        Hash(lib_crypto::hashing::hash_blake3(identity_str.as_bytes()))
    }

    /// Parse consensus key from hex string
    pub fn parse_consensus_key(key_str: &str, identity_id: &Hash) -> Option<PublicKey> {
        if key_str.is_empty() {
            return None;
        }

        // Try to parse as hex
        if let Ok(bytes) = hex::decode(key_str) {
            Some(PublicKey {
                dilithium_pk: bytes,
                kyber_pk: Vec::new(),
                key_id: identity_id.0,
            })
        } else {
            None
        }
    }

    /// Get identity as IdentityId for lib-consensus
    pub fn as_identity_id(&self) -> IdentityId {
        // Convert lib_crypto::Hash to lib_identity::IdentityId
        IdentityId::from_bytes(&self.identity_id.0)
    }

    /// Get consensus key bytes
    pub fn consensus_key_bytes(&self) -> Vec<u8> {
        self.consensus_key
            .as_ref()
            .map(|k| k.dilithium_pk.clone())
            .unwrap_or_default()
    }
}

/// Builder for GenesisValidator to make construction easier
pub struct GenesisValidatorBuilder {
    identity_id: Option<Hash>,
    stake: u64,
    storage_provided: u64,
    commission_rate: u16,
    endpoints: Vec<String>,
    consensus_key: Option<PublicKey>,
    node_device_id: Option<IdentityId>,
}

impl GenesisValidatorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            identity_id: None,
            stake: 0,
            storage_provided: 0,
            commission_rate: 0,
            endpoints: Vec::new(),
            consensus_key: None,
            node_device_id: None,
        }
    }

    /// Set identity from string (DID or hex)
    pub fn identity(mut self, identity_str: &str) -> Self {
        self.identity_id = Some(GenesisValidator::parse_identity(identity_str));
        self
    }

    /// Set identity from Hash directly
    pub fn identity_hash(mut self, identity_id: Hash) -> Self {
        self.identity_id = Some(identity_id);
        self
    }

    /// Set stake amount
    pub fn stake(mut self, stake: u64) -> Self {
        self.stake = stake;
        self
    }

    /// Set storage capacity
    pub fn storage(mut self, storage_provided: u64) -> Self {
        self.storage_provided = storage_provided;
        self
    }

    /// Set commission rate (basis points)
    pub fn commission(mut self, commission_rate: u16) -> Self {
        self.commission_rate = commission_rate;
        self
    }

    /// Add an endpoint
    pub fn endpoint(mut self, endpoint: String) -> Self {
        self.endpoints.push(endpoint);
        self
    }

    /// Set endpoints
    pub fn endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Set consensus key from hex string
    pub fn consensus_key_hex(mut self, key_str: &str) -> Self {
        if let Some(identity_id) = &self.identity_id {
            self.consensus_key = GenesisValidator::parse_consensus_key(key_str, identity_id);
        }
        self
    }

    /// Set consensus key directly
    pub fn consensus_key(mut self, key: PublicKey) -> Self {
        self.consensus_key = Some(key);
        self
    }

    /// Set node device ID
    pub fn node_device(mut self, device_id: IdentityId) -> Self {
        self.node_device_id = Some(device_id);
        self
    }

    /// Build the GenesisValidator
    pub fn build(self) -> Result<GenesisValidator> {
        let identity_id = self
            .identity_id
            .ok_or_else(|| anyhow::anyhow!("Identity ID is required"))?;

        Ok(GenesisValidator {
            identity_id,
            stake: self.stake,
            storage_provided: self.storage_provided,
            commission_rate: self.commission_rate,
            endpoints: self.endpoints,
            consensus_key: self.consensus_key,
            node_device_id: self.node_device_id,
        })
    }
}

impl Default for GenesisValidatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identity_did() {
        let did = "did:zhtp:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let identity = GenesisValidator::parse_identity(did);

        // Should successfully parse DID
        assert_eq!(identity.0[0], 0x01);
        assert_eq!(identity.0[1], 0x23);
    }

    #[test]
    fn test_parse_identity_hex() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let identity = GenesisValidator::parse_identity(hex);

        // Should successfully parse hex
        assert_eq!(identity.0[0], 0x01);
        assert_eq!(identity.0[1], 0x23);
    }

    #[test]
    fn test_parse_identity_fallback() {
        let text = "test_validator";
        let identity = GenesisValidator::parse_identity(text);

        // Should hash the string
        assert_eq!(identity.0.len(), 32);
    }

    #[test]
    fn test_builder() {
        let validator = GenesisValidatorBuilder::new()
            .identity("did:zhtp:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .stake(100_000_000)
            .storage(1_000_000_000)
            .commission(500) // 5%
            .endpoint("tcp://127.0.0.1:9333".to_string())
            .build()
            .unwrap();

        assert_eq!(validator.stake, 100_000_000);
        assert_eq!(validator.storage_provided, 1_000_000_000);
        assert_eq!(validator.commission_rate, 500);
        assert_eq!(validator.endpoints.len(), 1);
    }
}
