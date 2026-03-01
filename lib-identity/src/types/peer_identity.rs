use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::NodeId;

/// Unified peer identity used across storage and networking layers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DhtPeerIdentity {
    /// Canonical node identifier from lib-identity.
    pub node_id: NodeId,
    /// Cryptographic public key for signature verification.
    pub public_key: lib_crypto::PublicKey,
    /// Decentralized Identifier (DID) in "did:zhtp:<hash>" form.
    pub did: String,
    /// Device identifier (e.g., "laptop", "phone").
    pub device_id: String,
}

impl DhtPeerIdentity {
    /// Create from full ZhtpIdentity with all cryptographic material.
    pub fn from_zhtp_identity_full(identity: &crate::ZhtpIdentity) -> Self {
        Self {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key.clone(),
            did: identity.did.clone(),
            device_id: identity.primary_device.clone(),
        }
    }

    /// Get NodeId reference (for Kademlia routing).
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get PublicKey reference (for signature verification).
    pub fn public_key(&self) -> &lib_crypto::PublicKey {
        &self.public_key
    }

    /// Get DID reference (for identity validation).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get device ID reference.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}
