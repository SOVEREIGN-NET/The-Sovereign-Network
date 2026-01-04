//! Consensus-facing storage capacity attestations.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use lib_crypto::{Hash, PostQuantumSignature};
use lib_crypto::keypair::generation::KeyPair;
use lib_crypto::verification::verify_signature;

use crate::proofs::{StorageChallenge, StorageProof, VerificationResult};
use crate::types::ContentHash;

/// Summary of a verified proof for consensus consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofSummary {
    pub content_hash: ContentHash,
    pub challenge_id: String,
    pub verified_at: u64,
    pub result: VerificationResult,
}

/// Full challenge/proof/result bundle for attestation records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResult {
    pub challenge: StorageChallenge,
    pub proof: StorageProof,
    pub result: VerificationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageCapacityAttestationPayload {
    validator_id: Hash,
    storage_capacity: u64,
    utilization: u64,
    challenge_results: Vec<ChallengeResult>,
    timestamp: u64,
}

/// Consensus-facing storage capacity attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapacityAttestation {
    pub validator_id: Hash,
    pub storage_capacity: u64,
    pub utilization: u64,
    pub challenge_results: Vec<ChallengeResult>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

impl StorageCapacityAttestation {
    pub fn new(
        validator_id: Hash,
        storage_capacity: u64,
        utilization: u64,
        challenge_results: Vec<ChallengeResult>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            validator_id,
            storage_capacity,
            utilization,
            challenge_results,
            timestamp,
            signature: PostQuantumSignature::default(),
        }
    }

    pub fn sign(mut self, keypair: &KeyPair) -> Result<Self> {
        if self.utilization > 100 {
            return Err(anyhow!("Utilization must be between 0 and 100"));
        }

        let payload = self.payload_bytes()?;
        let signature = keypair.sign(&payload)?;
        self.signature = signature;
        Ok(self)
    }

    pub fn verify(&self) -> Result<bool> {
        if self.utilization > 100 {
            return Ok(false);
        }

        if self.challenge_results.is_empty() {
            return Ok(false);
        }

        if self
            .challenge_results
            .iter()
            .any(|result| !matches!(result.result, VerificationResult::Valid))
        {
            return Ok(false);
        }

        let payload = self.payload_bytes()?;
        verify_signature(
            &payload,
            &self.signature.signature,
            &self.signature.public_key.dilithium_pk,
        )
    }

    fn payload_bytes(&self) -> Result<Vec<u8>> {
        let payload = StorageCapacityAttestationPayload {
            validator_id: self.validator_id.clone(),
            storage_capacity: self.storage_capacity,
            utilization: self.utilization,
            challenge_results: self.challenge_results.clone(),
            timestamp: self.timestamp,
        };
        bincode::serialize(&payload)
            .map_err(|e| anyhow!("Attestation serialization failed: {e}"))
    }
}

/// Consensus interface for storage proof providers.
#[async_trait]
pub trait StorageProofProvider: Send + Sync {
    async fn active_challenges(&self, validator_id: &Hash) -> Result<Vec<StorageChallenge>>;
    async fn verified_proof_summaries(&self, validator_id: &Hash) -> Result<Vec<StorageProofSummary>>;
    async fn capacity_attestation(
        &self,
        validator_id: &Hash,
    ) -> Result<StorageCapacityAttestation>;
}
