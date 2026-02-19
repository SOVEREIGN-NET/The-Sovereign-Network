//! Receipt Validation Pipeline (Phase 2)
//!
//! Implements POST /pouw/submit endpoint logic:
//! - Signature verification (Ed25519, Dilithium5)
//! - Challenge binding verification
//! - Policy enforcement
//! - Replay detection
//! - Dispute logging

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::challenge::ChallengeGenerator;
use super::types::{
    ChallengeIssue, ChallengeToken, Policy, ProofType, Receipt, ReceiptBatch, SignedReceipt,
    POUW_VERSION,
};

/// Rejection reason codes (Spec 8.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// Signature verification failed
    BadSig,
    /// Challenge expired or unknown
    Expired,
    /// Receipt already processed (replay attempt)
    Replay,
    /// Policy limits exceeded
    Policy,
    /// Proof validation failed or malformed
    BadProof,
    /// Client DID invalid or unknown
    ClientInvalid,
}

impl RejectionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectionReason::BadSig => "BAD_SIG",
            RejectionReason::Expired => "EXPIRED",
            RejectionReason::Replay => "REPLAY",
            RejectionReason::Policy => "POLICY",
            RejectionReason::BadProof => "BAD_PROOF",
            RejectionReason::ClientInvalid => "CLIENT_INVALID",
        }
    }
}

/// Result of validating a single receipt
#[derive(Debug, Clone)]
pub struct ReceiptValidationResult {
    /// Receipt nonce (hex encoded)
    pub receipt_nonce: String,
    /// Whether the receipt was accepted
    pub accepted: bool,
    /// Rejection reason if not accepted
    pub rejection_reason: Option<RejectionReason>,
}

/// Batch submission response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitResponse {
    /// Nonces of accepted receipts
    pub accepted: Vec<String>,
    /// Rejected receipts with reasons
    pub rejected: Vec<RejectedReceipt>,
    /// Server timestamp
    pub server_time: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RejectedReceipt {
    pub receipt_nonce: String,
    pub reason: String,
}

/// Receipt validation pipeline
pub struct ReceiptValidator {
    /// Challenge generator for binding verification
    challenge_generator: Arc<ChallengeGenerator>,
    /// Seen receipt nonces (for replay detection)
    seen_nonces: Arc<RwLock<HashSet<Vec<u8>>>>,
    /// Validated receipts storage
    validated_receipts: Arc<RwLock<Vec<ValidatedReceipt>>>,
    /// Dispute log for rejected receipts
    dispute_log: Arc<RwLock<Vec<DisputeLogEntry>>>,
}

/// A validated and accepted receipt
#[derive(Debug, Clone)]
pub struct ValidatedReceipt {
    pub receipt_nonce: Vec<u8>,
    pub client_did: String,
    pub task_id: Vec<u8>,
    pub proof_type: ProofType,
    pub bytes_verified: u64,
    pub validated_at: u64,
    pub challenge_nonce: Vec<u8>,
}

/// Dispute log entry for rejected receipts
#[derive(Debug, Clone)]
pub struct DisputeLogEntry {
    pub timestamp: u64,
    pub client_did: String,
    pub receipt_nonce: Option<Vec<u8>>,
    pub reason: RejectionReason,
    pub details: String,
}

impl ReceiptValidator {
    /// Create a new receipt validator
    pub fn new(challenge_generator: Arc<ChallengeGenerator>) -> Self {
        Self {
            challenge_generator,
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            validated_receipts: Arc::new(RwLock::new(Vec::new())),
            dispute_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get current timestamp
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Validate a batch of receipts
    pub async fn validate_batch(
        &self,
        batch: &ReceiptBatch,
    ) -> Result<SubmitResponse> {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        // Validate batch version
        if batch.version != POUW_VERSION {
            return Ok(SubmitResponse {
                accepted: vec![],
                rejected: vec![RejectedReceipt {
                    receipt_nonce: "batch".to_string(),
                    reason: RejectionReason::BadProof.as_str().to_string(),
                }],
                server_time: self.now_secs(),
            });
        }

        // Process each receipt
        for signed_receipt in &batch.receipts {
            let result = self.validate_receipt(signed_receipt, &batch.client_did).await;

            if result.accepted {
                accepted.push(result.receipt_nonce);
            } else {
                rejected.push(RejectedReceipt {
                    receipt_nonce: result.receipt_nonce,
                    reason: result.rejection_reason
                        .map(|r| r.as_str().to_string())
                        .unwrap_or_else(|| "UNKNOWN".to_string()),
                });
            }
        }

        Ok(SubmitResponse {
            accepted,
            rejected,
            server_time: self.now_secs(),
        })
    }

    /// Validate a single signed receipt
    async fn validate_receipt(
        &self,
        signed_receipt: &SignedReceipt,
        batch_client_did: &str,
    ) -> ReceiptValidationResult {
        let receipt = &signed_receipt.receipt;
        let nonce_hex = hex::encode(&receipt.receipt_nonce);

        // Step 1: Format validation
        if let Err(reason) = self.validate_format(receipt) {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Format validation failed").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
            };
        }

        // Step 2: Client DID validation
        if receipt.client_did != batch_client_did {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), RejectionReason::ClientInvalid, 
                "Client DID mismatch with batch").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(RejectionReason::ClientInvalid),
            };
        }

        // Step 3: Signature verification
        if let Err(reason) = self.verify_signature(signed_receipt).await {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Signature verification failed").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
            };
        }

        // Step 4: Replay detection
        if let Err(reason) = self.check_replay(&receipt.receipt_nonce).await {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Replay detected").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
            };
        }

        // Step 5: Challenge binding
        let challenge = match self.verify_challenge_binding(receipt).await {
            Ok(c) => c,
            Err(reason) => {
                self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Challenge binding failed").await;
                return ReceiptValidationResult {
                    receipt_nonce: nonce_hex,
                    accepted: false,
                    rejection_reason: Some(reason),
                };
            }
        };

        // Step 6: Policy enforcement
        if let Err(reason) = self.enforce_policy(receipt, &challenge.policy) {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Policy violation").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
            };
        }

        // All checks passed - accept the receipt
        self.accept_receipt(receipt).await;

        info!(
            nonce = %nonce_hex,
            client = %batch_client_did,
            bytes = receipt.bytes_verified,
            proof_type = ?receipt.proof_type,
            "Receipt accepted"
        );

        ReceiptValidationResult {
            receipt_nonce: nonce_hex,
            accepted: true,
            rejection_reason: None,
        }
    }

    /// Step 1: Validate receipt format
    fn validate_format(&self, receipt: &Receipt) -> Result<(), RejectionReason> {
        // Version check
        if receipt.version != POUW_VERSION {
            return Err(RejectionReason::BadProof);
        }

        // Nonce length checks (16-32 bytes)
        if receipt.receipt_nonce.len() < 16 || receipt.receipt_nonce.len() > 32 {
            return Err(RejectionReason::BadProof);
        }
        if receipt.challenge_nonce.len() < 16 || receipt.challenge_nonce.len() > 32 {
            return Err(RejectionReason::BadProof);
        }
        if receipt.task_id.len() < 16 || receipt.task_id.len() > 32 {
            return Err(RejectionReason::BadProof);
        }

        // Client DID not empty
        if receipt.client_did.is_empty() {
            return Err(RejectionReason::ClientInvalid);
        }

        // Content ID present
        if receipt.content_id.is_empty() {
            return Err(RejectionReason::BadProof);
        }

        // Timestamp sanity
        if receipt.started_at > receipt.finished_at {
            return Err(RejectionReason::BadProof);
        }

        Ok(())
    }

    /// Step 2: Verify signature
    async fn verify_signature(&self, signed_receipt: &SignedReceipt) -> Result<(), RejectionReason> {
        let receipt_bytes = self.serialize_receipt(&signed_receipt.receipt)
            .map_err(|_| RejectionReason::BadProof)?;

        match signed_receipt.sig_scheme.to_lowercase().as_str() {
            "ed25519" => {
                // Extract public key from client_did
                let pubkey = self.get_client_pubkey(&signed_receipt.receipt.client_did).await
                    .map_err(|_| RejectionReason::ClientInvalid)?;

                // Verify Ed25519 signature
                let valid = lib_crypto::classical::ed25519::ed25519_verify(
                    &receipt_bytes,
                    &signed_receipt.signature,
                    &pubkey,
                ).map_err(|_| RejectionReason::BadSig)?;

                if !valid {
                    return Err(RejectionReason::BadSig);
                }
            }
            "dilithium5" => {
                // Extract public key from client_did
                let pubkey = self.get_client_pubkey_dilithium(&signed_receipt.receipt.client_did).await
                    .map_err(|_| RejectionReason::ClientInvalid)?;

                // Verify Dilithium signature
                let valid = lib_crypto::post_quantum::dilithium::dilithium_verify(
                    &receipt_bytes,
                    &signed_receipt.signature,
                    &pubkey,
                ).map_err(|_| RejectionReason::BadSig)?;

                if !valid {
                    return Err(RejectionReason::BadSig);
                }
            }
            _ => {
                return Err(RejectionReason::BadSig);
            }
        }

        Ok(())
    }

    /// Step 3: Check for replay attacks
    async fn check_replay(&self, nonce: &[u8]) -> Result<(), RejectionReason> {
        let mut seen = self.seen_nonces.write().await;
        if seen.contains(nonce) {
            return Err(RejectionReason::Replay);
        }
        seen.insert(nonce.to_vec());
        Ok(())
    }

    /// Step 4: Verify challenge binding
    async fn verify_challenge_binding(&self, receipt: &Receipt) -> Result<ChallengeIssue, RejectionReason> {
        // Look up challenge by nonce
        let challenge = self.challenge_generator
            .get_challenge(&receipt.challenge_nonce)
            .await
            .ok_or(RejectionReason::Expired)?;

        // Check expiry
        if self.now_secs() > challenge.expires_at {
            return Err(RejectionReason::Expired);
        }

        // Verify task_id matches
        if receipt.task_id != challenge.task_id {
            return Err(RejectionReason::BadProof);
        }

        Ok(challenge)
    }

    /// Step 5: Enforce policy limits
    fn enforce_policy(&self, receipt: &Receipt, policy: &Policy) -> Result<(), RejectionReason> {
        // Check proof type is allowed
        if !policy.allowed_proof_types.contains(&receipt.proof_type) {
            return Err(RejectionReason::Policy);
        }

        // Check minimum bytes per receipt
        if receipt.bytes_verified < policy.min_bytes_per_receipt {
            return Err(RejectionReason::Policy);
        }

        Ok(())
    }

    /// Serialize receipt for signature verification
    fn serialize_receipt(&self, receipt: &Receipt) -> Result<Vec<u8>> {
        bincode::serialize(receipt).context("Failed to serialize receipt")
    }

    /// Get client's Ed25519 public key from DID
    async fn get_client_pubkey(&self, _client_did: &str) -> Result<Vec<u8>> {
        // TODO: Implement DID resolution to get public key
        // For now, return placeholder
        Err(anyhow::anyhow!("DID resolution not implemented"))
    }

    /// Get client's Dilithium public key from DID
    async fn get_client_pubkey_dilithium(&self, _client_did: &str) -> Result<Vec<u8>> {
        // TODO: Implement DID resolution to get Dilithium public key
        Err(anyhow::anyhow!("Dilithium DID resolution not implemented"))
    }

    /// Accept a validated receipt
    async fn accept_receipt(&self, receipt: &Receipt) {
        let validated = ValidatedReceipt {
            receipt_nonce: receipt.receipt_nonce.clone(),
            client_did: receipt.client_did.clone(),
            task_id: receipt.task_id.clone(),
            proof_type: receipt.proof_type,
            bytes_verified: receipt.bytes_verified,
            validated_at: self.now_secs(),
            challenge_nonce: receipt.challenge_nonce.clone(),
        };

        self.validated_receipts.write().await.push(validated);
    }

    /// Log a dispute for audit trail
    async fn log_dispute(&self, client_did: &str, nonce: Option<&[u8]>, reason: RejectionReason, details: &str) {
        let entry = DisputeLogEntry {
            timestamp: self.now_secs(),
            client_did: client_did.to_string(),
            receipt_nonce: nonce.map(|n| n.to_vec()),
            reason,
            details: details.to_string(),
        };

        warn!(
            client = %client_did,
            reason = ?reason,
            details = %details,
            "Receipt rejected"
        );

        self.dispute_log.write().await.push(entry);
    }

    /// Get all validated receipts (for reward calculation)
    pub async fn get_validated_receipts(&self) -> Vec<ValidatedReceipt> {
        self.validated_receipts.read().await.clone()
    }

    /// Get validated receipts matching a set of accepted nonce hex strings.
    pub async fn get_validated_receipts_for_nonces(
        &self,
        accepted_nonce_hex: &[String],
    ) -> Vec<ValidatedReceipt> {
        let accepted_set: HashSet<Vec<u8>> = accepted_nonce_hex
            .iter()
            .filter_map(|nonce| hex::decode(nonce).ok())
            .collect();
        if accepted_set.is_empty() {
            return Vec::new();
        }

        self.validated_receipts
            .read()
            .await
            .iter()
            .filter(|receipt| accepted_set.contains(&receipt.receipt_nonce))
            .cloned()
            .collect()
    }

    /// Get dispute log entries
    pub async fn get_disputes(&self) -> Vec<DisputeLogEntry> {
        self.dispute_log.read().await.clone()
    }
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
    async fn test_format_validation() {
        let (priv_key, pub_key) = test_keys();
        let generator = Arc::new(ChallengeGenerator::new(priv_key, pub_key));
        let validator = ReceiptValidator::new(generator);

        // Test invalid version
        let receipt = Receipt {
            version: 99, // Invalid
            task_id: vec![0u8; 16],
            client_did: "did:zhtp:test".to_string(),
            client_node_id: vec![0u8; 32],
            provider_id: vec![],
            content_id: vec![1, 2, 3],
            proof_type: ProofType::Hash,
            bytes_verified: 1024,
            result_ok: true,
            started_at: 1000,
            finished_at: 2000,
            receipt_nonce: vec![0u8; 32],
            challenge_nonce: vec![0u8; 32],
            aux: None,
        };

        assert!(validator.validate_format(&receipt).is_err());
    }

    #[tokio::test]
    async fn test_replay_detection() {
        let (priv_key, pub_key) = test_keys();
        let generator = Arc::new(ChallengeGenerator::new(priv_key, pub_key));
        let validator = ReceiptValidator::new(generator);

        let nonce = vec![1u8; 32];

        // First submission should succeed
        assert!(validator.check_replay(&nonce).await.is_ok());

        // Second submission of same nonce should fail
        assert_eq!(
            validator.check_replay(&nonce).await.err(),
            Some(RejectionReason::Replay)
        );
    }

    #[tokio::test]
    async fn test_challenge_binding() {
        let (priv_key, pub_key) = test_keys();
        let generator = Arc::new(ChallengeGenerator::new(priv_key, pub_key));
        let validator = ReceiptValidator::new(generator.clone());

        // Generate a challenge
        let challenge_response = generator.generate_challenge(Some("hash"), None, None, None).await.unwrap();

        // Decode the token to get nonce and task_id
        let token_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &challenge_response.token,
        ).unwrap();
        let token: ChallengeToken = serde_json::from_slice(&token_bytes).unwrap();

        // Create a receipt with matching binding
        let receipt = Receipt {
            version: 1,
            task_id: token.task_id.clone(),
            client_did: "did:zhtp:test".to_string(),
            client_node_id: vec![0u8; 32],
            provider_id: vec![],
            content_id: vec![1, 2, 3],
            proof_type: ProofType::Hash,
            bytes_verified: 1024,
            result_ok: true,
            started_at: 1000,
            finished_at: 2000,
            receipt_nonce: vec![0u8; 32],
            challenge_nonce: token.challenge_nonce.clone(),
            aux: None,
        };

        // Should succeed
        assert!(validator.verify_challenge_binding(&receipt).await.is_ok());
    }

    #[tokio::test]
    async fn test_policy_enforcement() {
        let (priv_key, pub_key) = test_keys();
        let generator = Arc::new(ChallengeGenerator::new(priv_key, pub_key));
        let validator = ReceiptValidator::new(generator);

        let policy = Policy {
            max_receipts: 20,
            max_bytes_total: 10 * 1024 * 1024,
            min_bytes_per_receipt: 1024,
            allowed_proof_types: vec![ProofType::Hash],
        };

        // Receipt with allowed proof type and sufficient bytes
        let receipt = Receipt {
            version: 1,
            task_id: vec![0u8; 16],
            client_did: "did:zhtp:test".to_string(),
            client_node_id: vec![0u8; 32],
            provider_id: vec![],
            content_id: vec![1, 2, 3],
            proof_type: ProofType::Hash,
            bytes_verified: 2048,
            result_ok: true,
            started_at: 1000,
            finished_at: 2000,
            receipt_nonce: vec![0u8; 32],
            challenge_nonce: vec![0u8; 32],
            aux: None,
        };

        assert!(validator.enforce_policy(&receipt, &policy).is_ok());

        // Receipt with disallowed proof type
        let mut bad_receipt = receipt.clone();
        bad_receipt.proof_type = ProofType::Merkle;
        assert_eq!(
            validator.enforce_policy(&bad_receipt, &policy).err(),
            Some(RejectionReason::Policy)
        );

        // Receipt with insufficient bytes
        let mut small_receipt = receipt.clone();
        small_receipt.bytes_verified = 100;
        assert_eq!(
            validator.enforce_policy(&small_receipt, &policy).err(),
            Some(RejectionReason::Policy)
        );
    }
}
