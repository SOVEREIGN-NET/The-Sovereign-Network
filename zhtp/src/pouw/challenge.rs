//! Challenge Token Generation (Phase 1)
//!
//! Implements GET /pouw/challenge endpoint logic:
//! - Generate cryptographically random nonce and task_id
//! - Create policy from client capabilities
//! - Sign token with node's private key
//! - Persist for later validation

use anyhow::{Context, Result};
use rand::RngCore;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::types::{
    ChallengeIssue,
    ChallengeResponse,
    ChallengeToken,
    Policy,
    ProofType,
    DEFAULT_CHALLENGE_TTL_SECS,
    DEFAULT_MAX_BYTES_TOTAL,
    DEFAULT_MAX_RECEIPTS,
    DEFAULT_MIN_BYTES_PER_RECEIPT,
    POUW_VERSION,
};

/// Challenge token generator
pub struct ChallengeGenerator {
    /// Node's private key for signing (32 bytes for Ed25519)
    node_private_key: [u8; 32],
    /// Node's public key / ID (32 bytes)
    node_id: [u8; 32],
    /// Challenge token TTL in seconds
    challenge_ttl_secs: u64,
    /// In-memory challenge store (for validation)
    /// In production, this should be backed by a database
    challenges: Arc<RwLock<std::collections::HashMap<Vec<u8>, ChallengeIssue>>>,
}

impl ChallengeGenerator {
    /// Create a new challenge generator with the given node keys
    pub fn new(node_private_key: [u8; 32], node_id: [u8; 32]) -> Self {
        Self {
            node_private_key,
            node_id,
            challenge_ttl_secs: DEFAULT_CHALLENGE_TTL_SECS,
            challenges: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.challenge_ttl_secs = ttl_secs;
        self
    }

    /// Generate a random nonce (16-32 bytes)
    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Generate a random task ID (16-32 bytes)
    fn generate_task_id(&self) -> Vec<u8> {
        let mut task_id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut task_id);
        task_id
    }

    /// Get current timestamp in unix seconds
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Parse capability string into allowed proof types
    /// e.g., "hash,merkle" -> [ProofType::Hash, ProofType::Merkle]
    pub fn parse_capabilities(&self, cap: &str) -> Vec<ProofType> {
        cap.split(',')
            .filter_map(|s| ProofType::from_str(s.trim()))
            .collect()
    }

    /// Sign the canonical token bytes with node's private key
    fn sign_token(&self, token_bytes: &[u8]) -> Result<Vec<u8>> {
        lib_crypto::classical::ed25519::ed25519_sign(token_bytes, &self.node_private_key)
    }

    /// Serialize token for signing (excludes node_signature field)
    fn serialize_for_signing(&self, token: &ChallengeToken) -> Result<Vec<u8>> {
        // Create a token copy without signature for canonical serialization
        let signable = ChallengeTokenSignable {
            version: token.version,
            node_id: token.node_id.clone(),
            task_id: token.task_id.clone(),
            challenge_nonce: token.challenge_nonce.clone(),
            issued_at: token.issued_at,
            expires_at: token.expires_at,
            policy: token.policy.clone(),
        };
        
        // Use deterministic bincode serialization
        bincode::serialize(&signable).context("Failed to serialize token for signing")
    }

    /// Generate a new challenge token
    ///
    /// # Arguments
    /// * `cap` - Comma-separated list of proof types (e.g., "hash,merkle")
    /// * `max_bytes` - Optional client budget hint
    /// * `max_receipts` - Optional max receipts in batch
    /// * `client_ip` - Optional client IP for rate limiting
    ///
    /// # Returns
    /// * `ChallengeResponse` with base64-encoded token and expiry
    pub async fn generate_challenge(
        &self,
        cap: Option<&str>,
        max_bytes: Option<u64>,
        max_receipts: Option<u32>,
        client_ip: Option<String>,
    ) -> Result<ChallengeResponse> {
        // Parse capabilities
        let allowed_proof_types = cap
            .map(|c| self.parse_capabilities(c))
            .unwrap_or_else(|| vec![ProofType::Hash]);

        // Validate at least hash is supported
        if allowed_proof_types.is_empty() {
            anyhow::bail!("At least one valid proof type must be specified");
        }

        // Generate random values
        let challenge_nonce = self.generate_nonce();
        let task_id = self.generate_task_id();
        let now = self.now_secs();
        let expires_at = now + self.challenge_ttl_secs;

        // Build policy
        let policy = Policy {
            max_receipts: max_receipts.unwrap_or(DEFAULT_MAX_RECEIPTS),
            max_bytes_total: max_bytes.unwrap_or(DEFAULT_MAX_BYTES_TOTAL),
            min_bytes_per_receipt: DEFAULT_MIN_BYTES_PER_RECEIPT,
            allowed_proof_types,
        };

        // Create unsigned token
        let mut token = ChallengeToken {
            version: POUW_VERSION,
            node_id: self.node_id.to_vec(),
            task_id: task_id.clone(),
            challenge_nonce: challenge_nonce.clone(),
            issued_at: now,
            expires_at,
            policy: policy.clone(),
            node_signature: vec![],
        };

        // Sign the token
        let signable_bytes = self.serialize_for_signing(&token)?;
        let signature = self.sign_token(&signable_bytes)?;
        token.node_signature = signature.clone();

        // Persist for later validation
        let challenge_issue = ChallengeIssue {
            node_id: self.node_id.to_vec(),
            challenge_nonce: challenge_nonce.clone(),
            task_id,
            issued_at: now,
            expires_at,
            policy,
            node_signature: signature,
            client_ip,
            consumed: false,
            deleted: false,
        };

        {
            let mut challenges = self.challenges.write().await;
            challenges.insert(challenge_nonce.clone(), challenge_issue);
        }

        // Serialize full token to JSON then base64
        let token_json = serde_json::to_vec(&token)
            .context("Failed to serialize token to JSON")?;
        let token_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &token_json,
        );

        info!(
            nonce = hex::encode(&challenge_nonce[..8]),
            expires_at = expires_at,
            proof_types = ?token.policy.allowed_proof_types,
            "Challenge token generated"
        );

        Ok(ChallengeResponse {
            token: token_b64,
            expires_at,
        })
    }

    /// Look up a challenge by nonce (for validation in Phase 2)
    pub async fn get_challenge(&self, nonce: &[u8]) -> Option<ChallengeIssue> {
        let challenges = self.challenges.read().await;
        challenges.get(nonce).cloned()
    }

    /// Mark a challenge as consumed (after successful receipt validation)
    pub async fn consume_challenge(&self, nonce: &[u8]) -> bool {
        let mut challenges = self.challenges.write().await;
        if let Some(challenge) = challenges.get_mut(nonce) {
            if !challenge.consumed && !challenge.deleted {
                challenge.consumed = true;
                return true;
            }
        }
        false
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired(&self) -> usize {
        let now = self.now_secs();
        let mut challenges = self.challenges.write().await;
        let before = challenges.len();
        challenges.retain(|_, c| c.expires_at > now);
        let removed = before - challenges.len();
        if removed > 0 {
            debug!(removed = removed, "Cleaned up expired challenges");
        }
        removed
    }

    /// Get node ID
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }
}

/// Signable portion of ChallengeToken (excludes node_signature)
#[derive(serde::Serialize)]
struct ChallengeTokenSignable {
    version: u32,
    node_id: Vec<u8>,
    task_id: Vec<u8>,
    challenge_nonce: Vec<u8>,
    issued_at: u64,
    expires_at: u64,
    policy: Policy,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        let (public_key, private_key) = lib_crypto::classical::ed25519::ed25519_keypair();
        
        let mut priv_arr = [0u8; 32];
        let mut pub_arr = [0u8; 32];
        priv_arr.copy_from_slice(&private_key[..32]);
        pub_arr.copy_from_slice(&public_key);
        (priv_arr, pub_arr)
    }

    #[tokio::test]
    async fn test_generate_challenge() {
        let (private_key, public_key) = test_keys();
        let generator = ChallengeGenerator::new(private_key, public_key);

        let response = generator
            .generate_challenge(Some("hash,merkle"), None, None, None)
            .await
            .unwrap();

        assert!(!response.token.is_empty());
        assert!(response.expires_at > 0);
    }

    #[tokio::test]
    async fn test_challenge_nonce_uniqueness() {
        let (private_key, public_key) = test_keys();
        let generator = ChallengeGenerator::new(private_key, public_key);

        let r1 = generator.generate_challenge(None, None, None, None).await.unwrap();
        let r2 = generator.generate_challenge(None, None, None, None).await.unwrap();

        // Tokens should be different (different nonces)
        assert_ne!(r1.token, r2.token);
    }

    #[tokio::test]
    async fn test_challenge_lookup() {
        let (private_key, public_key) = test_keys();
        let generator = ChallengeGenerator::new(private_key, public_key);

        let _ = generator.generate_challenge(None, None, None, None).await.unwrap();

        // Get all challenges and verify one exists
        let challenges = generator.challenges.read().await;
        assert_eq!(challenges.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_capabilities() {
        let (private_key, public_key) = test_keys();
        let generator = ChallengeGenerator::new(private_key, public_key);

        let caps = generator.parse_capabilities("hash,merkle,signature");
        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&ProofType::Hash));
        assert!(caps.contains(&ProofType::Merkle));
        assert!(caps.contains(&ProofType::Signature));
    }

    #[tokio::test]
    async fn test_challenge_expiry() {
        let (private_key, public_key) = test_keys();
        let generator = ChallengeGenerator::new(private_key, public_key)
            .with_ttl(1); // 1 second TTL

        let _ = generator.generate_challenge(None, None, None, None).await.unwrap();

        // Wait for expiry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let removed = generator.cleanup_expired().await;
        assert_eq!(removed, 1);
    }
}
