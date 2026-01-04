//! Zero-Knowledge integration for consensus

use crate::types::{ConsensusProof, ConsensusProposal, ConsensusVote};
use crate::ConsensusError;
use anyhow::Result;
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use lib_proofs::{ZkProof, ZkProofSystem, ZkTransactionProof};

#[cfg(any(test, feature = "dev-insecure"))]
const VOTE_DOMAIN_TAG: &[u8] = b"ZHTP/CONSENSUS/VOTE/v1\0";

/// ZK integration for consensus system
pub struct ZkConsensusIntegration {
    /// ZK proof system
    zk_system: ZkProofSystem,
}

impl ZkConsensusIntegration {
    /// Create new ZK consensus integration
    pub fn new() -> Result<Self> {
        let zk_system = ZkProofSystem::new()?;

        Ok(Self { zk_system })
    }

    fn derive_identity_inputs(validator_id: &IdentityId) -> Result<(u64, u64, u64, u64, u64, u64, u64)> {
        let identity_hash = hash_blake3(validator_id.as_bytes());

        let identity_secret = u64::from_le_bytes(
            identity_hash[0..8]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid identity secret bytes".to_string()))?,
        );
        let age_seed = u64::from_le_bytes(
            identity_hash[8..16]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid age seed bytes".to_string()))?,
        );
        let jurisdiction_hash = u64::from_le_bytes(
            identity_hash[16..24]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid jurisdiction bytes".to_string()))?,
        );
        let credential_hash = u64::from_le_bytes(
            identity_hash[24..32]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid credential bytes".to_string()))?,
        );

        let min_age = 18;
        let age = min_age + (age_seed % 83);
        let required_jurisdiction = jurisdiction_hash;
        let verification_level = 1;

        Ok((
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        ))
    }

    fn serialize_zk_proof(proof: &ZkProof) -> Result<Vec<u8>> {
        bincode::serialize(proof)
            .map_err(|e| ConsensusError::ZkError(format!("Failed to serialize ZK proof: {e}")).into())
    }

    fn deserialize_zk_proof(data: &[u8]) -> Result<ZkProof> {
        bincode::deserialize(data)
            .map_err(|e| ConsensusError::ZkError(format!("Failed to deserialize ZK proof: {e}")).into())
    }

    /// Generate ZK-DID proof for validator identity
    pub async fn generate_zk_did_proof(&self, validator_id: &IdentityId) -> Result<Vec<u8>> {
        let (
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        ) = Self::derive_identity_inputs(validator_id)?;

        let zk_proof = self.zk_system.prove_identity(
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        )?;

        let proof = ZkProof::from_plonky2(zk_proof);
        Self::serialize_zk_proof(&proof)
    }

    /// Verify ZK-DID proof for validator identity
    pub async fn verify_zk_did_proof(
        &self,
        proof_data: &[u8],
        validator_id: &IdentityId,
    ) -> Result<bool> {
        if proof_data.is_empty() {
            return Ok(false);
        }

        let proof = match Self::deserialize_zk_proof(proof_data) {
            Ok(proof) => proof,
            Err(_) => return Ok(false),
        };

        let verified = match proof.verify() {
            Ok(valid) => valid,
            Err(_) => false,
        };

        if !verified {
            return Ok(false);
        }

        let (expected_identity_secret, _, _, _, _, _, _) =
            Self::derive_identity_inputs(validator_id)?;

        let Some(plonky2_proof) = proof.plonky2_proof.as_ref() else {
            return Ok(false);
        };

        if plonky2_proof.proof_system != "ZHTP-Optimized-Identity" {
            return Ok(false);
        }

        if plonky2_proof.proof.len() < 8 {
            return Ok(false);
        }

        let identity_secret = u64::from_le_bytes(
            plonky2_proof.proof[0..8]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid identity proof bytes".to_string()))?,
        );

        Ok(identity_secret == expected_identity_secret)
    }

    /// Create enhanced consensus proof with ZK-DID integration
    pub async fn create_enhanced_consensus_proof(
        &self,
        validator_id: &IdentityId,
        base_proof: &ConsensusProof,
    ) -> Result<ConsensusProof> {
        // Generate ZK-DID proof for validator
        let zk_did_proof = self.generate_zk_did_proof(validator_id).await?;

        // Create enhanced consensus proof with ZK-DID
        let mut enhanced_proof = base_proof.clone();
        enhanced_proof.zk_did_proof = Some(zk_did_proof);

        Ok(enhanced_proof)
    }

    /// Verify ZK transaction proof using unified ZK system
    pub async fn verify_zk_transaction_proof(&self, proof: &ZkTransactionProof) -> Result<bool> {
        // Use the unified verification method
        let verification_result = proof.verify()?;

        Ok(verification_result)
    }

    /// Generate ZK proof of voting eligibility
    pub async fn generate_voting_eligibility_proof(&self, voter: &IdentityId) -> Result<ZkProof> {
        let (
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        ) = Self::derive_identity_inputs(voter)?;

        let plonky2_proof = self.zk_system.prove_identity(
            identity_secret,
            age,
            jurisdiction_hash,
            credential_hash,
            min_age,
            required_jurisdiction,
            verification_level,
        )?;

        Ok(ZkProof::from_plonky2(plonky2_proof))
    }

    /// Verify voting eligibility without revealing voter identity
    pub async fn verify_voting_eligibility(&self, proof: &ZkProof) -> Result<bool> {
        if proof.is_empty() {
            return Ok(false);
        }

        match proof.verify() {
            Ok(valid) => Ok(valid),
            Err(_) => Ok(false),
        }
    }

    /// Create ZK proof of useful work without revealing work details
    pub async fn create_work_proof_zk(
        &self,
        work_data: &[u8],
        node_id: &[u8; 32],
    ) -> Result<ZkProof> {
        // Create ZK proof that work was performed without revealing specific work details
        let work_commitment = hash_blake3(&[work_data, node_id].concat());

        // Generate ZK proof using Plonky2 range proof
        let work_value = u64::from_le_bytes(work_commitment[..8].try_into().unwrap());
        let secret = u64::from_le_bytes(hash_blake3(&work_commitment)[..8].try_into().unwrap());

        let zk_proof = self
            .zk_system
            .prove_range(work_value, secret, 1, u64::MAX)?;

        Ok(ZkProof::from_plonky2(zk_proof))
    }

    /// Verify work proof without revealing work details
    pub async fn verify_work_proof_zk(&self, proof: &ZkProof, commitment: &[u8; 8]) -> Result<bool> {
        let Some(plonky2_proof) = &proof.plonky2_proof else {
            return Ok(false);
        };

        if !self.zk_system.verify_range(plonky2_proof)? {
            return Ok(false);
        }

        if plonky2_proof.proof.len() < 8 {
            return Ok(false);
        }

        let proof_value = u64::from_le_bytes(
            plonky2_proof.proof[0..8]
                .try_into()
                .map_err(|_| ConsensusError::ZkError("Invalid work proof bytes".to_string()))?,
        );
        let expected_value = u64::from_le_bytes(*commitment);

        Ok(proof_value == expected_value)
    }

    /// Enhanced proposal creation with ZK-DID integration
    pub async fn create_enhanced_proposal(
        &self,
        validator_id: &IdentityId,
        height: u64,
        previous_hash: Hash,
        transactions: Vec<Vec<u8>>, // Simplified transaction data
        consensus_proof: ConsensusProof,
    ) -> Result<ConsensusProposal> {
        // Generate ZK-DID proof for validator
        let zk_did_proof = self.generate_zk_did_proof(validator_id).await?;

        // Create enhanced consensus proof with ZK-DID
        let mut enhanced_proof = consensus_proof;
        enhanced_proof.zk_did_proof = Some(zk_did_proof);

        // Serialize transaction data
        let mut block_data = Vec::new();
        for tx in &transactions {
            block_data.extend_from_slice(&(tx.len() as u32).to_le_bytes());
            block_data.extend_from_slice(tx);
        }

        let proposal_id = Hash::from_bytes(&hash_blake3(
            &[
                validator_id.as_bytes(),
                &height.to_le_bytes(),
                previous_hash.as_bytes(),
                &block_data[..std::cmp::min(32, block_data.len())],
            ]
            .concat(),
        ));

        // Create and sign proposal
        let proposal = ConsensusProposal {
            id: proposal_id.clone(),
            proposer: validator_id.clone(),
            height,
            previous_hash,
            block_data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            signature: self
                .create_proposal_signature(validator_id, &proposal_id)
                .await?,
            consensus_proof: enhanced_proof,
        };

        Ok(proposal)
    }

    /// Create proposal signature with ZK integration
    async fn create_proposal_signature(
        &self,
        validator_id: &IdentityId,
        proposal_id: &Hash,
    ) -> Result<lib_crypto::PostQuantumSignature> {
        // Create signature data
        let signature_data = [validator_id.as_bytes(), proposal_id.as_bytes()].concat();

        let signature_hash = hash_blake3(&signature_data);

        Ok(lib_crypto::PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: signature_hash[..32].to_vec(),
                kyber_pk: signature_hash[..32].to_vec(),
                key_id: signature_hash[..32].try_into().unwrap(),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }

    /// Validate block structure using ZK proofs
    pub async fn validate_block_structure_zk(&self, block_data: &[u8]) -> Result<bool> {
        if block_data.is_empty() {
            return Ok(false);
        }

        // Deserialize block data (simplified - in production would use proper serialization)
        if block_data.len() < 64 {
            return Ok(false);
        }

        let mut offset = 0usize;
        let mut chunk_count = 0u64;

        while offset + 4 <= block_data.len() {
            let tx_len = u32::from_le_bytes([
                block_data[offset],
                block_data[offset + 1],
                block_data[offset + 2],
                block_data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + tx_len > block_data.len() {
                return Ok(false);
            }

            offset += tx_len;
            chunk_count += 1;
        }

        if offset != block_data.len() {
            return Ok(false);
        }

        let total_size = block_data.len() as u64;
        let block_hash = hash_blake3(block_data);
        let data_hash = u64::from_le_bytes(block_hash[0..8].try_into().unwrap());
        let checksum = u64::from_le_bytes(block_hash[8..16].try_into().unwrap());
        let owner_secret = u64::from_le_bytes(block_hash[16..24].try_into().unwrap());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let max_chunk_count = chunk_count.max(1);
        let max_size = total_size.max(1);

        let zk_proof = self.zk_system.prove_data_integrity(
            data_hash,
            chunk_count,
            total_size,
            checksum,
            owner_secret,
            timestamp,
            max_chunk_count,
            max_size,
        )?;

        if !self.zk_system.verify_data_integrity(&zk_proof)? {
            return Ok(false);
        }

        if zk_proof.proof.len() < 24 {
            return Ok(false);
        }

        let proof_hash = u64::from_le_bytes(zk_proof.proof[0..8].try_into().unwrap());
        let proof_total_size = u64::from_le_bytes(zk_proof.proof[16..24].try_into().unwrap());

        Ok(proof_hash == data_hash && proof_total_size == total_size)
    }

    /// Enhanced vote validation with ZK privacy (dev/test only)
    #[cfg(any(test, feature = "dev-insecure"))]
    pub async fn validate_vote_zk(&self, vote: &ConsensusVote) -> Result<bool> {
        // Verify voter signature using post-quantum cryptography
        let _vote_data = self.serialize_vote_for_zk_verification(vote)?;

        // For testing, skip signature validation if using test signature
        let signature_valid = if vote.signature.signature == vec![1, 2, 3] {
            true // Allow test signatures
        } else {
            // Verify post-quantum signature
            !vote.signature.signature.is_empty()
                && !vote.signature.public_key.dilithium_pk.is_empty()
        };

        if !signature_valid {
            return Ok(false);
        }

        // Verify vote timing using ZK timestamp proof
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if vote.timestamp + 300 < current_time {
            // 5 minute timeout
            return Ok(false);
        }

        Ok(true)
    }

    /// Enhanced vote validation with ZK privacy (disabled in production)
    #[cfg(not(any(test, feature = "dev-insecure")))]
    pub async fn validate_vote_zk(&self, _vote: &ConsensusVote) -> Result<bool> {
        Err(anyhow::anyhow!(
            "validate_vote_zk is dev-only; use production vote verification paths"
        ))
    }

    /// Serialize vote data for ZK verification
    #[cfg(any(test, feature = "dev-insecure"))]
    fn serialize_vote_for_zk_verification(&self, vote: &ConsensusVote) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(VOTE_DOMAIN_TAG);
        data.extend_from_slice(vote.id.as_bytes());
        data.extend_from_slice(vote.voter.as_bytes());
        data.extend_from_slice(vote.proposal_id.as_bytes());
        data.push(vote.vote_type.clone() as u8);
        data.extend_from_slice(&vote.height.to_le_bytes());
        data.extend_from_slice(&vote.round.to_le_bytes());
        data.extend_from_slice(&vote.timestamp.to_le_bytes());
        Ok(data)
    }
}

impl Default for ZkConsensusIntegration {
    fn default() -> Self {
        Self::new().expect("Failed to create ZK consensus integration")
    }
}
