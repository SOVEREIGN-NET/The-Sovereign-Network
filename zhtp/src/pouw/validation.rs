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

use lib_identity::IdentityManager;
use super::session_log::SharedSessionLog;

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
    /// Identity manager for DID public key resolution
    identity_manager: Arc<RwLock<IdentityManager>>,
    /// Session log for proof-of-presence verification (Web4 proof types)
    session_log: Option<SharedSessionLog>,
    /// Minimum identity age in seconds for reward eligibility (None = disabled)
    min_identity_age_secs: Option<u64>,
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
    // Web4 context — None for non-Web4 proof types
    /// CID of the Web4 manifest that was routed or served
    pub manifest_cid: Option<String>,
    /// Domain associated with the manifest (e.g. "central.sov")
    pub domain: Option<String>,
    /// Number of mesh hops used to route the manifest (Web4ManifestRoute only)
    pub route_hops: Option<u8>,
    /// Whether the content was served from local cache (Web4ContentServed only)
    pub served_from_cache: Option<bool>,
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
    pub fn new(challenge_generator: Arc<ChallengeGenerator>, identity_manager: Arc<RwLock<IdentityManager>>) -> Self {
        Self {
            challenge_generator,
            seen_nonces: Arc::new(RwLock::new(HashSet::new())),
            validated_receipts: Arc::new(RwLock::new(Vec::new())),
            dispute_log: Arc::new(RwLock::new(Vec::new())),
            identity_manager,
            session_log: None,
            min_identity_age_secs: None,
        }
    }

    /// Attach a session log for proof-of-presence verification on Web4 receipts
    pub fn with_session_log(mut self, session_log: SharedSessionLog) -> Self {
        self.session_log = Some(session_log);
        self
    }

    /// Enforce a minimum identity age for reward eligibility.
    /// Receipts from identities newer than `min_age_secs` will be rejected with `ClientInvalid`.
    pub fn with_min_identity_age(mut self, min_age_secs: u64) -> Self {
        self.min_identity_age_secs = Some(min_age_secs);
        self
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

        // Step 2.1: Identity age enforcement (if configured)
        if let Err(reason) = self.validate_identity_age(batch_client_did).await {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Identity too new for reward eligibility").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
            };
        }

        // Step 2.5: Proof-of-presence — Web4 receipts must include a valid QUIC session ID
        if let Err(reason) = self.verify_session_presence(receipt).await {
            self.log_dispute(batch_client_did, Some(&receipt.receipt_nonce), reason, "Session presence check failed").await;
            return ReceiptValidationResult {
                receipt_nonce: nonce_hex,
                accepted: false,
                rejection_reason: Some(reason),
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

        // Web4 proof types require manifest_cid in the aux field
        match receipt.proof_type {
            ProofType::Web4ManifestRoute | ProofType::Web4ContentServed => {
                let aux_obj = receipt.aux.as_deref()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
                let manifest_cid = aux_obj.as_ref()
                    .and_then(|v| v.get("manifest_cid"))
                    .and_then(|v| v.as_str());
                if manifest_cid.is_none() || manifest_cid.unwrap_or("").is_empty() {
                    return Err(RejectionReason::BadProof);
                }
                // Web4ContentServed additionally requires served_from_cache
                if receipt.proof_type == ProofType::Web4ContentServed {
                    let has_cache_field = aux_obj.as_ref()
                        .and_then(|v| v.get("served_from_cache"))
                        .is_some();
                    if !has_cache_field {
                        return Err(RejectionReason::BadProof);
                    }
                }
            }
            _ => {}
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

    /// Step 2.5: Verify proof-of-presence for Web4 receipts via QUIC session ID
    ///
    /// For Web4ManifestRoute and Web4ContentServed receipts, the aux JSON must include a
    /// `quic_session_id` (hex, 8 bytes) that matches an active session for the client DID.
    /// If no session log is configured, this check is skipped (for backwards compatibility).
    async fn verify_session_presence(&self, receipt: &Receipt) -> Result<(), RejectionReason> {
        let is_web4 = matches!(
            receipt.proof_type,
            ProofType::Web4ManifestRoute | ProofType::Web4ContentServed
        );
        if !is_web4 {
            return Ok(());
        }

        let Some(session_log) = &self.session_log else {
            // No session log attached — skip check (permissive mode for dev/test)
            return Ok(());
        };

        // Extract quic_session_id from aux JSON
        let aux_obj = receipt.aux.as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let session_id_hex = aux_obj.as_ref()
            .and_then(|v| v.get("quic_session_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if session_id_hex.is_empty() {
            warn!(client = %receipt.client_did, "Web4 receipt missing quic_session_id in aux");
            return Err(RejectionReason::BadProof);
        }

        let session_id_bytes = hex::decode(session_id_hex)
            .map_err(|_| RejectionReason::BadProof)?;
        if session_id_bytes.len() != 8 {
            return Err(RejectionReason::BadProof);
        }
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&session_id_bytes);

        let log = session_log.read().await;
        if !log.verify(session_id, &receipt.client_did) {
            warn!(
                client = %receipt.client_did,
                session_id = %session_id_hex,
                "Web4 receipt session ID not found or expired in session log"
            );
            return Err(RejectionReason::BadProof);
        }

        Ok(())
    }

    /// Step 2.1: Verify the client identity is old enough for reward eligibility
    async fn validate_identity_age(&self, client_did: &str) -> Result<(), RejectionReason> {
        let Some(min_age) = self.min_identity_age_secs else {
            return Ok(()); // Age check disabled
        };

        let mgr = self.identity_manager.read().await;
        let identity = mgr.get_identity_by_did(client_did)
            .ok_or(RejectionReason::ClientInvalid)?;

        let now = self.now_secs();
        let age_secs = now.saturating_sub(identity.created_at);
        if age_secs < min_age {
            warn!(
                client = %client_did,
                age_secs = age_secs,
                min_age_secs = min_age,
                "Receipt rejected: identity too new for reward eligibility"
            );
            return Err(RejectionReason::ClientInvalid);
        }

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

    /// Get client's Ed25519-compatible public key from DID (key_id bytes)
    async fn get_client_pubkey(&self, client_did: &str) -> Result<Vec<u8>> {
        let mgr = self.identity_manager.read().await;
        let identity = mgr.get_identity_by_did(client_did)
            .ok_or_else(|| anyhow::anyhow!("DID not registered: {}", client_did))?;
        Ok(identity.public_key.key_id.to_vec())
    }

    /// Get client's Dilithium5 public key from DID
    async fn get_client_pubkey_dilithium(&self, client_did: &str) -> Result<Vec<u8>> {
        let mgr = self.identity_manager.read().await;
        let identity = mgr.get_identity_by_did(client_did)
            .ok_or_else(|| anyhow::anyhow!("DID not registered: {}", client_did))?;
        Ok(identity.public_key.dilithium_pk.clone())
    }

    /// Parse Web4 context fields from receipt aux JSON
    fn parse_web4_aux(receipt: &Receipt) -> (Option<String>, Option<String>, Option<u8>, Option<bool>) {
        let aux_obj = receipt.aux.as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
        let manifest_cid = aux_obj.as_ref()
            .and_then(|v| v.get("manifest_cid"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let domain = aux_obj.as_ref()
            .and_then(|v| v.get("domain"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let route_hops = aux_obj.as_ref()
            .and_then(|v| v.get("route_hops"))
            .and_then(|v| v.as_u64())
            .map(|n| n.min(255) as u8);
        let served_from_cache = aux_obj.as_ref()
            .and_then(|v| v.get("served_from_cache"))
            .and_then(|v| v.as_bool());
        (manifest_cid, domain, route_hops, served_from_cache)
    }

    /// Accept a validated receipt
    async fn accept_receipt(&self, receipt: &Receipt) {
        let (manifest_cid, domain, route_hops, served_from_cache) = match receipt.proof_type {
            ProofType::Web4ManifestRoute | ProofType::Web4ContentServed => {
                Self::parse_web4_aux(receipt)
            }
            _ => (None, None, None, None),
        };

        let validated = ValidatedReceipt {
            receipt_nonce: receipt.receipt_nonce.clone(),
            client_did: receipt.client_did.clone(),
            task_id: receipt.task_id.clone(),
            proof_type: receipt.proof_type,
            bytes_verified: receipt.bytes_verified,
            validated_at: self.now_secs(),
            challenge_nonce: receipt.challenge_nonce.clone(),
            manifest_cid,
            domain,
            route_hops,
            served_from_cache,
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

    /// Directly emit a pre-validated receipt (for server-side hooks, bypasses challenge-response)
    ///
    /// Used by Web4ContentService and MeshMessageRouter to credit server-observed work
    /// without requiring the full client challenge-response flow.
    pub async fn emit_direct(&self, receipt: ValidatedReceipt) {
        self.validated_receipts.write().await.push(receipt);
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

/// Spawn a background task that converts `MeshRoutingEvent`s into `Web4ManifestRoute` receipts.
///
/// Call this in `unified_server.rs` after creating the `ReceiptValidator` and
/// attaching a `pouw_routing_tx` to `MeshMessageRouter`.
pub fn spawn_mesh_routing_listener(
    validator: Arc<ReceiptValidator>,
    mut rx: tokio::sync::mpsc::Receiver<lib_network::MeshRoutingEvent>,
    node_did: String,
) {
    tokio::spawn(async move {
        tracing::info!(did = %node_did, "POUW mesh routing listener started");

        while let Some(event) = rx.recv().await {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut nonce = vec![0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

            let receipt = ValidatedReceipt {
                receipt_nonce: nonce,
                client_did: node_did.clone(),
                task_id: vec![0u8; 16],
                proof_type: ProofType::Web4ManifestRoute,
                bytes_verified: event.message_size,
                validated_at: now,
                challenge_nonce: vec![0u8; 16],
                manifest_cid: None,
                domain: None,
                route_hops: Some(event.hop_count),
                served_from_cache: None,
            };

            validator.emit_direct(receipt).await;
        }

        tracing::info!("POUW mesh routing listener stopped (channel closed)");
    });
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
        let validator = ReceiptValidator::new(generator, Arc::new(RwLock::new(IdentityManager::new())));

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
        let validator = ReceiptValidator::new(generator, Arc::new(RwLock::new(IdentityManager::new())));

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
        let validator = ReceiptValidator::new(generator.clone(), Arc::new(RwLock::new(IdentityManager::new())));

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
        let validator = ReceiptValidator::new(generator, Arc::new(RwLock::new(IdentityManager::new())));

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
