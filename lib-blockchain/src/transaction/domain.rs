//! Domain registration and update transaction payloads.
//!
//! Domain records are authoritative on-chain. The sled/DHT DomainRegistry is a
//! read-through cache populated from chain state at startup.
//!
//! ## Memo encoding
//!
//! Payloads are encoded into `Transaction::memo` as:
//!   `DOMAIN_REGISTRATION_PREFIX || bincode(DomainRegistrationPayload)`
//!   `DOMAIN_UPDATE_PREFIX       || bincode(DomainUpdatePayload)`

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const DOMAIN_REGISTRATION_PREFIX: &[u8] = b"DOMREG1:";
pub const DOMAIN_UPDATE_PREFIX: &[u8] = b"DOMUPD1:";

/// Canonical on-chain domain record — stored in `Blockchain::domain_registry`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainDomainRecord {
    /// Domain name (e.g. "mysite.sov")
    pub domain: String,
    /// Owner DID (did:zhtp:hex)
    pub owner_did: String,
    /// Current Web4Manifest CID
    pub manifest_cid: String,
    /// BLAKE3 hash of the build output
    pub build_hash: String,
    /// Human-readable title
    pub title: String,
    /// Human-readable description
    pub description: String,
    /// Category tag
    pub category: String,
    /// Discovery tags
    pub tags: Vec<String>,
    /// Block timestamp at registration
    pub registered_at: u64,
    /// Expiration (registered_at + duration_days * 86400)
    pub expires_at: u64,
    /// Monotonically increasing deployment version (starts at 1)
    pub version: u64,
    /// Block timestamp of last update
    pub updated_at: u64,
    /// Hash of the SOV fee payment transaction
    pub fee_tx_hash: String,
}

/// Payload embedded in a `DomainRegistration` transaction memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistrationPayload {
    pub domain: String,
    pub owner_did: String,
    pub manifest_cid: String,
    pub build_hash: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub duration_days: u64,
    pub fee_tx_hash: String,
}

/// Payload embedded in a `DomainUpdate` transaction memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUpdatePayload {
    pub domain: String,
    pub owner_did: String,
    pub new_manifest_cid: String,
    pub expected_previous_manifest_cid: String,
    pub build_hash: String,
    pub message: Option<String>,
    pub fee_tx_hash: String,
}

impl DomainRegistrationPayload {
    pub fn encode_memo(&self) -> Result<Vec<u8>> {
        let payload = bincode::serialize(self)
            .map_err(|e| anyhow!("Failed to encode DomainRegistrationPayload: {}", e))?;
        let mut memo = Vec::with_capacity(DOMAIN_REGISTRATION_PREFIX.len() + payload.len());
        memo.extend_from_slice(DOMAIN_REGISTRATION_PREFIX);
        memo.extend_from_slice(&payload);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self> {
        let memo = memo
            .strip_prefix(DOMAIN_REGISTRATION_PREFIX)
            .ok_or_else(|| anyhow!("Missing DOMAIN_REGISTRATION_PREFIX"))?;
        bincode::deserialize(memo)
            .map_err(|e| anyhow!("Failed to decode DomainRegistrationPayload: {}", e))
    }
}

impl DomainUpdatePayload {
    pub fn encode_memo(&self) -> Result<Vec<u8>> {
        let payload = bincode::serialize(self)
            .map_err(|e| anyhow!("Failed to encode DomainUpdatePayload: {}", e))?;
        let mut memo = Vec::with_capacity(DOMAIN_UPDATE_PREFIX.len() + payload.len());
        memo.extend_from_slice(DOMAIN_UPDATE_PREFIX);
        memo.extend_from_slice(&payload);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self> {
        let memo = memo
            .strip_prefix(DOMAIN_UPDATE_PREFIX)
            .ok_or_else(|| anyhow!("Missing DOMAIN_UPDATE_PREFIX"))?;
        bincode::deserialize(memo)
            .map_err(|e| anyhow!("Failed to decode DomainUpdatePayload: {}", e))
    }
}
