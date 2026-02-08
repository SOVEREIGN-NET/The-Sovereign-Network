//! In-memory storage proof provider for consensus integration.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};

use lib_crypto::Hash;

use crate::proofs::{
    generate_storage_proof,
    ChallengeResult,
    ProofManager,
    StorageCapacityAttestation,
    StorageChallenge,
    StorageProofSummary,
    StorageProofProvider,
    VerificationResult,
};
use crate::types::ContentHash;

struct StoredContent {
    content_hash: ContentHash,
    blocks: Vec<Vec<u8>>,
}

struct ValidatorStorageState {
    storage_capacity: u64,
    utilization_override: Option<u64>,
    contents: Vec<StoredContent>,
}

/// In-memory proof provider backed by ProofManager and registered content.
pub struct InMemoryStorageProofProvider {
    proof_manager: Mutex<ProofManager>,
    validators: RwLock<HashMap<Hash, ValidatorStorageState>>,
    max_challenges_per_attestation: usize,
}

impl InMemoryStorageProofProvider {
    pub fn new(challenge_timeout: u64, sample_count: usize, max_proof_age: u64) -> Self {
        Self {
            proof_manager: Mutex::new(ProofManager::new(
                challenge_timeout,
                sample_count,
                max_proof_age,
            )),
            validators: RwLock::new(HashMap::new()),
            max_challenges_per_attestation: 3,
        }
    }

    pub fn with_max_challenges(mut self, max: usize) -> Self {
        self.max_challenges_per_attestation = max.max(1);
        self
    }

    pub async fn register_validator_capacity(
        &self,
        validator_id: Hash,
        storage_capacity: u64,
    ) -> Result<()> {
        let mut validators = self.validators.write().await;
        let entry = validators.entry(validator_id).or_insert(ValidatorStorageState {
            storage_capacity,
            utilization_override: None,
            contents: Vec::new(),
        });
        entry.storage_capacity = storage_capacity;
        Ok(())
    }

    pub async fn set_utilization_override(
        &self,
        validator_id: Hash,
        utilization: u64,
    ) -> Result<()> {
        if utilization > 100 {
            return Err(anyhow!("Utilization must be between 0 and 100"));
        }
        let mut validators = self.validators.write().await;
        let entry = validators.entry(validator_id).or_insert(ValidatorStorageState {
            storage_capacity: 0,
            utilization_override: Some(utilization),
            contents: Vec::new(),
        });
        entry.utilization_override = Some(utilization);
        Ok(())
    }

    pub async fn register_content(
        &self,
        validator_id: Hash,
        content_hash: ContentHash,
        blocks: Vec<Vec<u8>>,
    ) -> Result<()> {
        if blocks.is_empty() {
            return Err(anyhow!("Content blocks cannot be empty"));
        }

        let mut validators = self.validators.write().await;
        let entry = validators.entry(validator_id).or_insert(ValidatorStorageState {
            storage_capacity: 0,
            utilization_override: None,
            contents: Vec::new(),
        });
        entry.contents.push(StoredContent { content_hash, blocks });
        Ok(())
    }

    async fn compute_utilization(&self, state: &ValidatorStorageState) -> u64 {
        if let Some(utilization) = state.utilization_override {
            return utilization;
        }

        if state.storage_capacity == 0 {
            return 0;
        }

        let stored_bytes: u64 = state
            .contents
            .iter()
            .map(|content| content.blocks.iter().map(|b| b.len() as u64).sum::<u64>())
            .sum();

        ((stored_bytes.saturating_mul(100)) / state.storage_capacity).min(100)
    }
}

#[async_trait]
impl StorageProofProvider for InMemoryStorageProofProvider {
    async fn active_challenges(&self, validator_id: &Hash) -> Result<Vec<StorageChallenge>> {
        let validators = self.validators.read().await;
        let Some(state) = validators.get(validator_id) else {
            return Ok(Vec::new());
        };

        let manager = self.proof_manager.lock().await;
        let mut challenges = Vec::new();
        for content in &state.contents {
            challenges.extend(manager.get_active_challenges(&content.content_hash));
        }
        Ok(challenges)
    }

    async fn verified_proof_summaries(&self, validator_id: &Hash) -> Result<Vec<StorageProofSummary>> {
        let validators = self.validators.read().await;
        let Some(state) = validators.get(validator_id) else {
            return Ok(Vec::new());
        };

        let manager = self.proof_manager.lock().await;
        let mut summaries = Vec::new();

        for content in &state.contents {
            for (proof, result) in manager.get_storage_proof_history(&content.content_hash) {
                summaries.push(StorageProofSummary {
                    content_hash: content.content_hash.clone(),
                    challenge_id: format!("challenge-{}", proof.challenge_nonce),
                    verified_at: proof.timestamp,
                    result,
                });
            }
        }

        Ok(summaries)
    }

    async fn capacity_attestation(
        &self,
        validator_id: &Hash,
    ) -> Result<StorageCapacityAttestation> {
        let validators = self.validators.read().await;
        let Some(state) = validators.get(validator_id) else {
            return Err(anyhow!("Validator not registered"));
        };

        if state.storage_capacity == 0 {
            return Err(anyhow!("Storage capacity not set"));
        }

        if state.contents.is_empty() {
            return Err(anyhow!("No content registered for validator"));
        }

        let utilization = self.compute_utilization(state).await;
        let mut manager = self.proof_manager.lock().await;
        let mut challenge_results = Vec::new();

        for content in state.contents.iter().take(self.max_challenges_per_attestation) {
            let total_blocks = content.blocks.len();
            let challenge = manager.generate_storage_challenge(
                content.content_hash.clone(),
                total_blocks,
                validator_id.to_string(),
            )?;

            let proof = generate_storage_proof(
                content.content_hash.clone(),
                &content.blocks,
                challenge.nonce,
                challenge.block_index.unwrap_or(0),
                validator_id.to_string(),
            )?;

            let result = manager.submit_storage_proof(proof.clone(), challenge.challenge_id.clone())?;
            let verification = match result {
                VerificationResult::Valid => VerificationResult::Valid,
                other => other,
            };

            challenge_results.push(ChallengeResult {
                challenge,
                proof,
                result: verification,
            });
        }

        Ok(StorageCapacityAttestation::new(
            validator_id.clone(),
            state.storage_capacity,
            utilization,
            challenge_results,
        ))
    }
}
