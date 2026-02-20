//! PoUW Type Definitions
//!
//! These types mirror the protobuf schema from pouw-protocol-spec.md
//! but are implemented as native Rust types with serde for JSON and
//! prost-compatible serialization.

use serde::{Deserialize, Serialize};

/// Protocol version (locked at 1)
pub const POUW_VERSION: u32 = 1;

/// Default challenge token lifetime (1 hour)
pub const DEFAULT_CHALLENGE_TTL_SECS: u64 = 3600;

/// Default maximum receipts per batch
pub const DEFAULT_MAX_RECEIPTS: u32 = 20;

/// Default maximum bytes total (10MB)
pub const DEFAULT_MAX_BYTES_TOTAL: u64 = 10 * 1024 * 1024;

/// Default minimum bytes per receipt (1KB)
pub const DEFAULT_MIN_BYTES_PER_RECEIPT: u64 = 1024;

/// Proof types that can be requested/provided
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Hash = 0,
    Merkle = 1,
    Signature = 2,
    /// Mobile node routed a Web4 manifest request through the mesh
    Web4ManifestRoute = 3,
    /// Mobile node served/validated Web4 content from local cache
    Web4ContentServed = 4,
}

impl ProofType {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hash" => Some(ProofType::Hash),
            "merkle" => Some(ProofType::Merkle),
            "signature" | "sig" => Some(ProofType::Signature),
            "web4manifestroute" | "web4_manifest_route" => Some(ProofType::Web4ManifestRoute),
            "web4contentserved" | "web4_content_served" => Some(ProofType::Web4ContentServed),
            _ => None,
        }
    }

    /// Reward multiplier for this proof type
    pub fn multiplier(&self) -> u32 {
        match self {
            ProofType::Hash => 1,
            ProofType::Merkle => 2,
            ProofType::Signature => 3,
            ProofType::Web4ManifestRoute => 2,
            ProofType::Web4ContentServed => 3,
        }
    }
}

/// Policy constraints for a challenge token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Maximum number of receipts in a batch
    pub max_receipts: u32,
    /// Maximum total bytes across all receipts
    pub max_bytes_total: u64,
    /// Minimum bytes per individual receipt
    pub min_bytes_per_receipt: u64,
    /// Allowed proof types
    pub allowed_proof_types: Vec<ProofType>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_bytes_total: DEFAULT_MAX_BYTES_TOTAL,
            min_bytes_per_receipt: DEFAULT_MIN_BYTES_PER_RECEIPT,
            allowed_proof_types: vec![ProofType::Hash],
        }
    }
}

/// Challenge token issued by a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeToken {
    /// Protocol version (= 1)
    pub version: u32,
    /// Node's public key (32 bytes)
    #[serde(with = "hex_bytes")]
    pub node_id: Vec<u8>,
    /// Unique task identifier (16-32 bytes)
    #[serde(with = "hex_bytes")]
    pub task_id: Vec<u8>,
    /// Random challenge nonce (16-32 bytes)
    #[serde(with = "hex_bytes")]
    pub challenge_nonce: Vec<u8>,
    /// Issuance timestamp (unix seconds)
    pub issued_at: u64,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
    /// Policy constraints
    pub policy: Policy,
    /// Node's signature over the canonical token (excluding this field)
    #[serde(with = "hex_bytes")]
    pub node_signature: Vec<u8>,
}

impl ChallengeToken {
    /// Check if this token has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if a proof type is allowed by this token's policy
    pub fn allows_proof_type(&self, proof_type: ProofType) -> bool {
        self.policy.allowed_proof_types.contains(&proof_type)
    }
}

/// API response for GET /pouw/challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Base64-encoded ChallengeToken (protobuf serialized)
    pub token: String,
    /// Expiration timestamp (unix seconds)
    pub expires_at: u64,
}

/// Database record for issued challenges (for later validation)
#[derive(Debug, Clone)]
pub struct ChallengeIssue {
    /// Node ID that issued this challenge
    pub node_id: Vec<u8>,
    /// The challenge nonce (primary lookup key)
    pub challenge_nonce: Vec<u8>,
    /// Task ID
    pub task_id: Vec<u8>,
    /// Issuance timestamp
    pub issued_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Policy (serialized)
    pub policy: Policy,
    /// Node signature
    pub node_signature: Vec<u8>,
    /// Client IP (optional, for rate limiting)
    pub client_ip: Option<String>,
    /// Whether this challenge has been used/consumed
    pub consumed: bool,
    /// Soft delete flag (for audit trail)
    pub deleted: bool,
}

/// Receipt submitted by a client after completing work
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Protocol version (= 1)
    pub version: u32,
    /// Task ID from the challenge
    #[serde(with = "hex_bytes")]
    pub task_id: Vec<u8>,
    /// Client's DID (decentralized identifier)
    pub client_did: String,
    /// Client's node ID (public key)
    #[serde(with = "hex_bytes")]
    pub client_node_id: Vec<u8>,
    /// Optional provider ID
    #[serde(with = "hex_bytes")]
    pub provider_id: Vec<u8>,
    /// Content ID that was verified
    #[serde(with = "hex_bytes")]
    pub content_id: Vec<u8>,
    /// Type of proof performed
    pub proof_type: ProofType,
    /// Number of bytes verified
    pub bytes_verified: u64,
    /// Whether the verification succeeded
    pub result_ok: bool,
    /// Unix timestamp when work started
    pub started_at: u64,
    /// Unix timestamp when work finished
    pub finished_at: u64,
    /// Unique receipt nonce (16-32 bytes)
    #[serde(with = "hex_bytes")]
    pub receipt_nonce: Vec<u8>,
    /// Challenge nonce from the issued token
    #[serde(with = "hex_bytes")]
    pub challenge_nonce: Vec<u8>,
    /// Optional auxiliary data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aux: Option<String>,
}

/// A receipt with client's signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The receipt data
    pub receipt: Receipt,
    /// Signature scheme used ("ed25519" or "dilithium5")
    pub sig_scheme: String,
    /// Client's signature over the receipt
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Batch of receipts for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptBatch {
    /// Protocol version
    pub version: u32,
    /// Client's DID (must match all receipts)
    pub client_did: String,
    /// List of signed receipts
    pub receipts: Vec<SignedReceipt>,
}

/// Helper module for hex serialization of byte arrays
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_type_from_str() {
        assert_eq!(ProofType::from_str("hash"), Some(ProofType::Hash));
        assert_eq!(ProofType::from_str("HASH"), Some(ProofType::Hash));
        assert_eq!(ProofType::from_str("merkle"), Some(ProofType::Merkle));
        assert_eq!(ProofType::from_str("signature"), Some(ProofType::Signature));
        assert_eq!(ProofType::from_str("sig"), Some(ProofType::Signature));
        assert_eq!(ProofType::from_str("invalid"), None);
    }

    #[test]
    fn test_proof_type_multiplier() {
        assert_eq!(ProofType::Hash.multiplier(), 1);
        assert_eq!(ProofType::Merkle.multiplier(), 2);
        assert_eq!(ProofType::Signature.multiplier(), 3);
    }

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert_eq!(policy.max_receipts, DEFAULT_MAX_RECEIPTS);
        assert_eq!(policy.max_bytes_total, DEFAULT_MAX_BYTES_TOTAL);
        assert_eq!(policy.min_bytes_per_receipt, DEFAULT_MIN_BYTES_PER_RECEIPT);
        assert!(policy.allowed_proof_types.contains(&ProofType::Hash));
    }
}
