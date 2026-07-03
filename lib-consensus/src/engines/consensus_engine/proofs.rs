use super::*;
use lib_crypto::{hash_blake3, Hash, PostQuantumSignature};
// CONS-104 / AD-003: storage attestation type stays in lib-storage; it was
// already there pre-CONS-104 and only re-exported through lib-consensus.
use lib_storage::proofs::StorageCapacityAttestation;

impl ConsensusEngine {
    /// Create a new proposal.
    ///
    /// Tendermint valid-value rule: if this node holds a `valid_value` —
    /// a block that reached a prevote quorum in an earlier round of the
    /// CURRENT height — the proposer re-proposes that exact block,
    /// **re-using its proposal id**, and advertises `valid_round`. Locked
    /// validators recognise the id (or honour `valid_round` via the unlock
    /// rule) and can prevote it; without this a locked network could never
    /// make progress. Otherwise a fresh block is built with no `valid_round`.
    pub(super) async fn create_proposal(&self) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Locate the valid_value artifact to re-propose, if we hold one.
        let mut reproposal = match (
            self.current_round.valid_proposal.as_ref(),
            self.current_round.valid_round,
        ) {
            (Some(valid_id), Some(_)) => self
                .pending_proposals
                .iter()
                .find(|p| &p.id == valid_id)
                .or_else(|| self.proposal_for_round.values().find(|p| &p.id == valid_id))
                .cloned(),
            _ => None,
        };

        // Tendermint requires reproposing a cached valid_value, but an empty
        // block that became valid before mempool txs arrived will never pick
        // them up. When the cached block has no transactions and the mempool
        // now has work, build a fresh proposal instead (valid_round = None).
        if let Some(ref artifact) = reproposal {
            if self.cached_proposal_has_no_transactions(&artifact.block_data).await
                && self.mempool_has_pending_transactions().await
            {
                tracing::info!(
                    "Skipping empty valid_value {:?} reproposal at H={} R={} — \
                     mempool has pending transactions",
                    artifact.id,
                    self.current_round.height,
                    self.current_round.round,
                );
                reproposal = None;
            }
        }

        let (proposal_id, previous_hash, block_data, valid_round) = match reproposal {
            Some(artifact) => {
                tracing::info!(
                    "Re-proposing valid_value {:?} (valid_round {:?}) at H={} R={}",
                    artifact.id,
                    self.current_round.valid_round,
                    self.current_round.height,
                    self.current_round.round,
                );
                (
                    artifact.id.clone(),
                    artifact.previous_hash.clone(),
                    artifact.block_data.clone(),
                    self.current_round.valid_round,
                )
            }
            None => {
                // Fresh block. Proposal ID is bound to (height, round,
                // proposer, previous_hash, block_data) so the same proposer
                // at the same height but a different round produces a
                // distinct ID. `valid_round` is None — this is a new value.
                let previous_hash = self.get_previous_block_hash().await?;
                let block_data = self.collect_block_transactions().await?;
                let proposal_id = Hash::from_bytes(&hash_blake3(
                    &[
                        b"ZHTP/PROPOSAL/ID/v1\0" as &[u8],
                        validator_id.as_bytes(),
                        &self.current_round.height.to_le_bytes(),
                        &self.current_round.round.to_le_bytes(),
                        previous_hash.as_bytes(),
                        &block_data,
                    ]
                    .concat(),
                ));
                (proposal_id, previous_hash, block_data, None)
            }
        };

        // Create consensus proof
        let consensus_proof = self.create_consensus_proof().await?;

        // Sign the proposal data
        let proposal_data = self.serialize_proposal_data(
            &proposal_id,
            validator_id,
            self.current_round.height,
            self.current_round.round,
            &previous_hash,
            &block_data,
            valid_round,
        )?;

        let signature = self.sign_proposal_data(&proposal_data).await?;

        // Use height as the proposal timestamp — deterministic across all
        // nodes.  Wall-clock timestamps are nondeterministic and would cause
        // different nodes to compute different proposal IDs for the same block.
        let proposal = ConsensusProposal {
            id: proposal_id,
            proposer: validator_id.clone(),
            height: self.current_round.height,
            round: self.current_round.round,
            protocol_version: super::CONSENSUS_PROTOCOL_VERSION,
            previous_hash,
            block_data,
            timestamp: self.current_round.height,
            signature,
            consensus_proof,
            valid_round,
        };

        tracing::info!(
            "Created proposal {:?} for height {} by {:?}",
            proposal.id,
            proposal.height,
            proposal.proposer
        );

        Ok(proposal)
    }

    /// Get the hash of the previous block.
    ///
    /// Returns an error if the blockchain provider is unavailable or fails.
    /// A proposer MUST know the chain tip to create a valid proposal — a
    /// synthetic fallback hash would be rejected by every other validator's
    /// `validate_previous_hash` check.
    async fn get_previous_block_hash(&self) -> ConsensusResult<Hash> {
        if self.current_round.height == 0 {
            return Ok(Hash([0u8; 32]));
        }

        let provider = self.blockchain_provider.as_ref().ok_or_else(|| {
            ConsensusError::ValidatorError(
                "Cannot propose: no blockchain provider configured".to_string(),
            )
        })?;

        provider.get_latest_block_hash().await.map_err(|e| {
            ConsensusError::ValidatorError(format!(
                "Cannot propose at height {}: failed to get previous block hash: {}",
                self.current_round.height, e,
            ))
        })
    }

    /// Returns true when `block_data` decodes to a block with zero transactions.
    async fn cached_proposal_has_no_transactions(&self, block_data: &[u8]) -> bool {
        if block_data.is_empty() {
            return true;
        }
        let Some(provider) = self.blockchain_provider.as_ref() else {
            return true;
        };
        match provider.decode_block_data(block_data).await {
            Ok((tx_count, _)) => tx_count == 0,
            Err(_) => true,
        }
    }

    /// Returns true when the blockchain provider reports pending mempool work.
    async fn mempool_has_pending_transactions(&self) -> bool {
        let Some(provider) = self.blockchain_provider.as_ref() else {
            return false;
        };
        if !provider.is_ready().await {
            return false;
        }
        match provider.get_pending_transactions().await {
            Ok(data) => {
                if data.is_empty() {
                    return false;
                }
                match provider.decode_block_data(&data).await {
                    Ok((tx_count, _)) => tx_count > 0,
                    Err(_) => !data.is_empty(),
                }
            }
            Err(_) => false,
        }
    }

    /// Collect transactions for the new block.
    ///
    /// Returns the serialized block payload from the blockchain provider.
    /// If the provider returns an empty payload (no pending transactions),
    /// that is a valid empty block — returned as-is.  If the provider is
    /// unavailable or not ready, returns an error.
    ///
    /// The old fallback generated a nondeterministic `"empty_block:..."` string
    /// containing `SystemTime::now()`, which would produce different proposal
    /// IDs on different nodes and break consensus.
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        let provider = self.blockchain_provider.as_ref().ok_or_else(|| {
            ConsensusError::ValidatorError(
                "Cannot propose: no blockchain provider configured".to_string(),
            )
        })?;

        if !provider.is_ready().await {
            return Err(ConsensusError::ValidatorError(
                "Cannot propose: blockchain provider is not ready".to_string(),
            ));
        }

        let tx_data = provider.get_pending_transactions().await.map_err(|e| {
            ConsensusError::ValidatorError(format!(
                "Cannot propose at height {}: failed to get pending transactions: {}",
                self.current_round.height, e,
            ))
        })?;

        if !tx_data.is_empty() {
            tracing::info!(
                "📦 Collected {} bytes of pending transactions for block {}",
                tx_data.len(),
                self.current_round.height
            );
        } else {
            tracing::debug!(
                "No pending transactions for block {}",
                self.current_round.height
            );
        }

        Ok(tx_data)
    }

    /// Serialize proposal data for signing.
    ///
    /// The signed envelope is domain-tagged and binds all consensus-critical
    /// fields so that a signature for one (height, round) cannot be replayed
    /// at a different position in the chain.
    pub(super) fn serialize_proposal_data(
        &self,
        proposal_id: &Hash,
        proposer: &IdentityId,
        height: u64,
        round: u32,
        previous_hash: &Hash,
        block_data: &[u8],
        valid_round: Option<u32>,
    ) -> ConsensusResult<Vec<u8>> {
        let mut data = Vec::new();
        // v2 payload: appends the Tendermint `valid_round` field. The
        // domain tag is bumped alongside CONSENSUS_PROTOCOL_VERSION 3 so
        // a v1-payload signature can never validate against a v2 verifier.
        data.extend_from_slice(b"ZHTP/PROPOSAL/SIG/v2\0");
        data.extend_from_slice(proposal_id.as_bytes());
        data.extend_from_slice(proposer.as_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&round.to_le_bytes());
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
        data.extend_from_slice(block_data);
        // valid_round: 1 presence byte + u32 value (0 when absent), so the
        // signed payload is fixed-layout and unambiguous.
        match valid_round {
            Some(vr) => {
                data.push(1);
                data.extend_from_slice(&vr.to_le_bytes());
            }
            None => {
                data.push(0);
                data.extend_from_slice(&0u32.to_le_bytes());
            }
        }
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
        // Deterministic: height-based logical timestamp, not wall-clock.
        let timestamp = self.current_round.height;

        // CONS-201 Scope B: build via `ConsensusProof::empty` + the
        // `ConsensusProofExt` builder helpers so the underlying opaque
        // bytes are produced by a single bincode call per field.
        use crate::types::ConsensusProofExt;
        let proof = ConsensusProof::empty(consensus_type.clone(), timestamp);
        match consensus_type {
            ConsensusType::ProofOfStake => {
                let stake_proof = self.create_stake_proof().await?;
                Ok(proof.with_stake_proof(&stake_proof))
            }
            ConsensusType::ProofOfStorage => {
                let storage_proof = self.create_storage_proof().await?;
                Ok(proof.with_storage_proof(&storage_proof))
            }
            ConsensusType::ProofOfUsefulWork => {
                let work_proof = self.create_work_proof().await?;
                Ok(proof.with_work_proof(&work_proof))
            }
            ConsensusType::ByzantineFaultTolerance => {
                // BFT uses all proof types.
                let stake_proof = self.create_stake_proof().await?;
                let storage_proof = self.create_storage_proof().await?;
                let work_proof = self.create_work_proof().await?;
                Ok(proof
                    .with_stake_proof(&stake_proof)
                    .with_storage_proof(&storage_proof)
                    .with_work_proof(&work_proof))
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

        let keypair = self.local_signing_keypair(validator)?;

        if let Some(ref provider) = self.storage_proof_provider {
            let unsigned = provider
                .capacity_attestation(&Hash::from_bytes(validator_id.as_bytes()))
                .await
                .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

            let attestation = unsigned
                .sign(keypair)
                .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

            return Ok(attestation);
        }

        // No storage proof provider — emit a signed stub attestation (0 capacity, no challenges).
        // This allows consensus to proceed on dev/testnet nodes that don't provide storage.
        // Production (Mainnet) deployments should always configure a real provider.
        let validator_hash = Hash::from_bytes(validator_id.as_bytes());
        let unsigned = StorageCapacityAttestation::new(
            validator_hash,
            0,      // storage_capacity: none
            0,      // utilization: 0%
            vec![], // no challenge results
        );
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
            self.engine_start_time,
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
        let keypair = self.validator_keypair.as_ref().ok_or_else(|| {
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
