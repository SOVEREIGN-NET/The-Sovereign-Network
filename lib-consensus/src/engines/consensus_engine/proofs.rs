use super::*;
use crate::proofs::StorageCapacityAttestation;
use lib_crypto::{hash_blake3, Hash, PostQuantumSignature};

impl ConsensusEngine {
    /// Create a new proposal
    pub(super) async fn create_proposal(&self) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Get previous block hash from blockchain state
        let previous_hash = self.get_previous_block_hash().await?;

        // Collect pending transactions for this block
        let block_data = self.collect_block_transactions().await?;

        // Generate proposal ID from deterministic data
        let proposal_id = Hash::from_bytes(&hash_blake3(
            &[
                &self.current_round.height.to_le_bytes(),
                previous_hash.as_bytes(),
                &block_data,
                validator_id.as_bytes(),
            ]
            .concat(),
        ));

        // Create consensus proof
        let consensus_proof = self.create_consensus_proof().await?;

        // Sign the proposal data
        let proposal_data = self.serialize_proposal_data(
            &proposal_id,
            validator_id,
            self.current_round.height,
            &previous_hash,
            &block_data,
        )?;

        let signature = self.sign_proposal_data(&proposal_data).await?;

        let proposal = ConsensusProposal {
            id: proposal_id,
            proposer: validator_id.clone(),
            height: self.current_round.height,
            previous_hash,
            block_data,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
            consensus_proof,
        };

        tracing::info!(
            "Created proposal {:?} for height {} by {:?}",
            proposal.id,
            proposal.height,
            proposal.proposer
        );

        Ok(proposal)
    }

    /// Get the hash of the previous block
    async fn get_previous_block_hash(&self) -> ConsensusResult<Hash> {
        // In production, this would query the blockchain for the latest block hash
        if self.current_round.height == 0 {
            // Genesis block
            Ok(Hash([0u8; 32]))
        } else {
            // For demo, create deterministic previous hash based on height
            let prev_hash_data = format!("block_{}", self.current_round.height - 1);
            Ok(Hash::from_bytes(&hash_blake3(prev_hash_data.as_bytes())))
        }
    }

    /// Collect transactions for the new block
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        // In production, this would:
        // 1. Get pending transactions from mempool
        // 2. Validate transactions
        // 3. Select transactions based on fees and priority
        // 4. Create block data with transaction merkle tree

        // For demo, create minimal block data
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        let block_data = format!(
            "block_height:{},timestamp:{},validator_count:{}",
            self.current_round.height,
            timestamp,
            self.validator_manager.get_active_validators().len()
        );

        Ok(block_data.into_bytes())
    }

    /// Serialize proposal data for signing
    pub(super) fn serialize_proposal_data(
        &self,
        proposal_id: &Hash,
        proposer: &IdentityId,
        height: u64,
        previous_hash: &Hash,
        block_data: &[u8],
    ) -> ConsensusResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(proposal_id.as_bytes());
        data.extend_from_slice(proposer.as_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
        data.extend_from_slice(block_data);
        Ok(data)
    }

    /// Sign proposal data
    async fn sign_proposal_data(&self, data: &[u8]) -> ConsensusResult<PostQuantumSignature> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        let keypair = self.local_signing_keypair(validator)?;
        let signature = keypair.sign(data)?;
        Ok(signature)
    }

    /// Create consensus proof based on configuration
    async fn create_consensus_proof(&self) -> ConsensusResult<ConsensusProof> {
        let consensus_type = self.config.consensus_type.clone();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        match consensus_type {
            ConsensusType::ProofOfStake => {
                let stake_proof = self.create_stake_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: None,
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ProofOfStorage => {
                let storage_proof = self.create_storage_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: None,
                    storage_proof: Some(storage_proof),
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ProofOfUsefulWork => {
                let work_proof = self.create_work_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: None,
                    storage_proof: None,
                    work_proof: Some(work_proof),
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::Hybrid => {
                let stake_proof = self.create_stake_proof().await?;
                let storage_proof = self.create_storage_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: Some(storage_proof),
                    work_proof: None,
                    zk_did_proof: None,
                    timestamp,
                })
            }
            ConsensusType::ByzantineFaultTolerance => {
                // BFT uses all proof types
                let stake_proof = self.create_stake_proof().await?;
                let storage_proof = self.create_storage_proof().await?;
                let work_proof = self.create_work_proof().await?;
                Ok(ConsensusProof {
                    consensus_type,
                    stake_proof: Some(stake_proof),
                    storage_proof: Some(storage_proof),
                    work_proof: Some(work_proof),
                    zk_did_proof: None,
                    timestamp,
                })
            }
        }
    }

    /// Create stake proof
    async fn create_stake_proof(&self) -> ConsensusResult<StakeProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create deterministic stake transaction hash based on validator identity and stake
        let stake_tx_data = [
            validator_id.as_bytes(),
            &validator.stake.to_le_bytes(),
            b"stake_transaction",
        ]
        .concat();
        let stake_tx_hash = Hash::from_bytes(&hash_blake3(&stake_tx_data));

        let stake_proof = StakeProof::new(
            validator_id.clone(),
            validator.stake,
            stake_tx_hash,
            self.current_round.height.saturating_sub(1), // Stake was made in previous block
            86400,                                       // 1 day lock time in seconds
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(stake_proof)
    }

    /// Create storage proof
    async fn create_storage_proof(&self) -> ConsensusResult<StorageCapacityAttestation> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        let provider = self
            .storage_proof_provider
            .as_ref()
            .ok_or_else(|| {
                ConsensusError::ProofVerificationFailed(
                    "No storage proof provider configured".to_string(),
                )
            })?;

        let unsigned = provider
            .capacity_attestation(&Hash::from_bytes(validator_id.as_bytes()))
            .await
            .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        let keypair = self.local_signing_keypair(validator)?;
        let attestation = unsigned
            .sign(keypair)
            .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(attestation)
    }

    /// Create work proof
    async fn create_work_proof(&self) -> ConsensusResult<WorkProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Calculate realistic work values based on validator capabilities
        let routing_work = (validator.voting_power * 10).min(5000); // Based on voting power
        let storage_work = (validator.storage_provided / (1024 * 1024 * 1024)).min(1000); // GB to work units
        let compute_work = (validator.reputation as u64 * 5).min(2000); // Based on reputation

        let work_proof = WorkProof::new(
            routing_work,
            storage_work,
            compute_work,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            validator_id.as_bytes().try_into().unwrap_or([0u8; 32]),
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(work_proof)
    }

    /// Serialize vote data for signing
    pub(super) fn serialize_vote_data(
        &self,
        vote_id: &Hash,
        voter: &IdentityId,
        proposal_id: &Hash,
        vote_type: &VoteType,
        height: u64,
        round: u32,
    ) -> ConsensusResult<Vec<u8>> {
        // **CRITICAL INVARIANT**: Vote signature MUST be bound to the vote's own height/round,
        // not the local consensus state. This ensures:
        // - Signature verifies against the exact vote data, not local state
        // - Commit votes from past rounds/heights can be properly validated
        // - No latent safety faults when strict verification is enabled
        let mut data = Vec::new();
        data.extend_from_slice(vote_id.as_bytes());
        data.extend_from_slice(voter.as_bytes());
        data.extend_from_slice(proposal_id.as_bytes());
        data.push(vote_type.clone() as u8);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&round.to_le_bytes());
        Ok(data)
    }

    /// Sign vote data
    pub(super) async fn sign_vote_data(
        &self,
        data: &[u8],
        validator: &crate::validators::Validator,
    ) -> ConsensusResult<PostQuantumSignature> {
        let keypair = self.local_signing_keypair(validator)?;
        let signature = keypair.sign(data)?;
        Ok(signature)
    }

    fn local_signing_keypair(
        &self,
        validator: &crate::validators::Validator,
    ) -> ConsensusResult<&lib_crypto::KeyPair> {
        let keypair = self
            .validator_keypair
            .as_ref()
            .ok_or_else(|| {
                ConsensusError::ValidatorError(
                    "No signing keypair configured for local validator".to_string(),
                )
            })?;

        if keypair.public_key.dilithium_pk != validator.consensus_key {
            return Err(ConsensusError::ValidatorError(
                "Local keypair does not match validator consensus key".to_string(),
            ));
        }

        Ok(keypair)
    }
}
