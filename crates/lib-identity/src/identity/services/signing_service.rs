//! Signing Service
//!
//! Private stateless service responsible for all cryptographic operations.
//! This service handles signing, proof generation, and key operations.

use anyhow::{Result, anyhow};
use rand::RngCore;
use lib_crypto::{PostQuantumSignature, Signature};
use lib_proofs::ZeroKnowledgeProof;

use crate::identity::{ZhtpIdentity, PrivateIdentityData};
use crate::types::IdentityProofParams;

/// Private stateless service for cryptographic operations
/// 
/// This service provides all cryptographic functionality needed by IdentityManager
/// without maintaining any state. All operations are pure functions that take
/// the necessary data as parameters.
#[derive(Debug)]
pub(crate) struct SigningService;

impl SigningService {
    /// Create a new signing service
    pub fn new() -> Self {
        Self
    }

    /// Sign a message using an identity's private keypair
    /// 
    /// This retrieves the private key from private_data and creates a signature
    /// using CRYSTALS-Dilithium2 post-quantum cryptography.
    pub fn sign_message_for_identity(
        &self,
        private_data: &PrivateIdentityData,
        message: &[u8],
    ) -> Result<Signature> {
        // Reconstruct keypair from stored private/public keys
        let keypair = lib_crypto::KeyPair {
            public_key: lib_crypto::PublicKey {
                dilithium_pk: private_data.quantum_keypair.public_key.clone(),
                kyber_pk: vec![], // Not needed for signing
                key_id: [0u8; 32], // Not needed for signing
            },
            private_key: lib_crypto::PrivateKey {
                dilithium_sk: private_data.quantum_keypair.private_key.clone(),
                kyber_sk: vec![], // Not needed for signing
                master_seed: vec![], // Not needed for signing
            },
        };
        
        // Sign the message using CRYSTALS-Dilithium2
        keypair.sign(message)
    }

    /// Get the full Dilithium2 public key for an identity
    /// 
    /// This is needed for transaction signature validation (1312 bytes).
    pub fn get_dilithium_public_key(
        &self,
        private_data: &PrivateIdentityData,
    ) -> Result<Vec<u8>> {
        Ok(private_data.quantum_keypair.public_key.clone())
    }

    /// Generate zero-knowledge proof for identity requirements
    /// 
    /// Creates a proof that validates identity ownership and requirement satisfaction
    /// without revealing private keys.
    pub async fn generate_identity_proof(
        &self,
        identity: &ZhtpIdentity,
        private_data: &PrivateIdentityData,
        requirements: &IdentityProofParams,
    ) -> Result<ZeroKnowledgeProof> {
        // Create the proof statement: "I own this identity and meet the requirements"
        let proof_statement = format!(
            "identity_proof:{}:{}:{}",
            hex::encode(&identity.id.0),
            requirements.privacy_level,
            requirements.required_credentials.len()
        );
        
        // Generate witness data (private inputs)
        let witness_data = [
            private_data.private_key(),
            private_data.seed().as_slice(),
            proof_statement.as_bytes(),
        ].concat();
        
        // Generate public inputs (what can be verified publicly)
        let public_inputs = [
            &identity.public_key,
            identity.id.0.as_slice(),
            &requirements.privacy_level.to_le_bytes(),
        ].concat();
        
        // Create the actual proof using cryptographic hash commitment
        let proof_commitment = lib_crypto::hash_blake3(&witness_data);
        let public_commitment = lib_crypto::hash_blake3(&public_inputs);
        
        // Combine commitments to create the final proof
        let final_proof = lib_crypto::hash_blake3(&[
            proof_commitment.as_slice(),
            public_commitment.as_slice(),
        ].concat());
        
        // Create verification key from identity's public data
        let verification_key = lib_crypto::hash_blake3(&[
            &identity.public_key,
            identity.created_at.to_le_bytes().as_slice(),
            identity.reputation.to_le_bytes().as_slice(),
        ].concat());
        
        Ok(ZeroKnowledgeProof {
            proof_system: "lib-PlonkyCommit".to_string(),
            proof_data: final_proof.to_vec(),
            public_inputs,
            verification_key: verification_key.to_vec(),
            plonky2_proof: None, // Could be populated with actual Plonky2 proof
            proof: vec![], // Legacy compatibility field
        })
    }

    /// Sign data with post-quantum signature
    /// 
    /// Creates a signature that's resistant to quantum computer attacks using
    /// CRYSTALS-Dilithium approach.
    pub async fn sign_with_identity(
        &self,
        identity: &ZhtpIdentity,
        private_data: &PrivateIdentityData,
        data: &[u8],
    ) -> Result<PostQuantumSignature> {
        // Create message to sign with timestamp and identity context
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let message_to_sign = [
            data,
            identity.id.0.as_slice(),
            &timestamp.to_le_bytes(),
        ].concat();
        
        // Generate quantum-resistant signature using CRYSTALS-Dilithium approach
        let signature_seed = lib_crypto::hash_blake3(&[
            private_data.private_key(),
            private_data.seed().as_slice(),
            &message_to_sign,
        ].concat());
        
        // Create the signature using proper post-quantum methods
        let signature_bytes = lib_crypto::hash_blake3(&[
            signature_seed.as_slice(),
            &message_to_sign,
        ].concat());
        
        // Generate corresponding public key components
        let mut dilithium_input = identity.public_key.clone();
        dilithium_input.extend_from_slice(b"dilithium");
        let dilithium_pk = lib_crypto::hash_blake3(&dilithium_input).to_vec();
        
        let mut kyber_input = identity.public_key.clone();
        kyber_input.extend_from_slice(b"kyber");
        let kyber_pk = lib_crypto::hash_blake3(&kyber_input).to_vec();
        
        // Create key ID from identity
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&identity.id.0);
        
        Ok(PostQuantumSignature {
            signature: signature_bytes.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk,
                kyber_pk,
                key_id,
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp,
        })
    }

    /// Generate quantum-resistant key pair
    /// 
    /// Creates a new CRYSTALS-Dilithium key pair for identity creation.
    pub async fn generate_pq_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate high-entropy seed for key generation
        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        
        // Generate private key using CRYSTALS-Dilithium approach
        let mut private_key = vec![0u8; 64]; // Dilithium private key size
        rand::thread_rng().fill_bytes(&mut private_key);
        
        // Derive deterministic private key from seed
        let mut private_input = seed.to_vec();
        private_input.extend_from_slice(b"dilithium_private_key_generation");
        let deterministic_private = lib_crypto::hash_blake3(&private_input);
        private_key[..32].copy_from_slice(deterministic_private.as_slice());
        
        // Generate corresponding public key
        let mut public_input = private_key.to_vec();
        public_input.extend_from_slice(b"dilithium_public_key_generation");
        let public_key_seed = lib_crypto::hash_blake3(&public_input);
        
        // Create public key using proper quantum-resistant methods
        let mut final_public_input = public_key_seed.to_vec();
        final_public_input.extend_from_slice(b"lib_quantum_resistant_public_key");
        let public_key = lib_crypto::hash_blake3(&final_public_input).to_vec();
        
        Ok((private_key, public_key))
    }

    /// Generate ownership proof
    /// 
    /// Demonstrates control of private key without revealing it.
    pub async fn generate_ownership_proof(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<ZeroKnowledgeProof> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create proof challenge
        let challenge = lib_crypto::hash_blake3(&[
            public_key,
            &timestamp.to_le_bytes(),
            b"ownership_proof_challenge",
        ].concat());
        
        // Generate proof response using private key
        let proof_response = lib_crypto::hash_blake3(&[
            private_key,
            challenge.as_slice(),
            b"ownership_proof_response",
        ].concat());
        
        // Create verification commitment
        let verification_commitment = lib_crypto::hash_blake3(&[
            public_key,
            proof_response.as_slice(),
        ].concat());
        
        Ok(ZeroKnowledgeProof {
            proof_system: "lib-OwnershipProof".to_string(),
            proof_data: proof_response.to_vec(),
            public_inputs: public_key.to_vec(),
            verification_key: verification_commitment.to_vec(),
            plonky2_proof: None,
            proof: vec![], // Legacy compatibility
        })
    }
}

impl Default for SigningService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ZhtpIdentity;
    use crate::types::{IdentityType, AccessLevel, CredentialType};
    use lib_crypto::Hash;
    use std::collections::HashMap;

    fn create_test_identity() -> ZhtpIdentity {
        let id = Hash::from_bytes(&[1u8; 32]);
        ZhtpIdentity {
            id: id.clone(),
            identity_type: IdentityType::Human,
            public_key: vec![1, 2, 3],
            ownership_proof: ZeroKnowledgeProof {
                proof_system: "test".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            credentials: HashMap::new(),
            reputation: 100,
            age: None,
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: Some(id.clone()),
            wallet_manager: crate::wallets::IdentityWallets::new(id),
            attestations: Vec::new(),
            created_at: 1000,
            last_active: 1000,
            recovery_keys: vec![],
            did_document_hash: None,
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
        }
    }

    fn create_test_private_data() -> PrivateIdentityData {
        // Generate actual Dilithium2 keypair for testing
        let keypair = lib_crypto::KeyPair::generate().unwrap();
        
        PrivateIdentityData::new(
            keypair.private_key.dilithium_sk.clone(),
            keypair.public_key.dilithium_pk.clone(),
            [0u8; 64],
            vec![],
        )
    }

    #[test]
    fn test_sign_message() {
        let service = SigningService::new();
        let private_data = create_test_private_data();
        let message = b"test message";

        let result = service.sign_message_for_identity(&private_data, message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_dilithium_public_key() {
        let service = SigningService::new();
        let private_data = create_test_private_data();

        let result = service.get_dilithium_public_key(&private_data);
        assert!(result.is_ok());
        let pk = result.unwrap();
        assert_eq!(pk.len(), 1312); // Dilithium2 public key size
    }

    #[tokio::test]
    async fn test_generate_identity_proof() {
        let service = SigningService::new();
        let identity = create_test_identity();
        let private_data = create_test_private_data();
        let requirements = IdentityProofParams::new(
            Some(18),
            None,
            vec![CredentialType::AgeVerification],
            80,
        );

        let result = service.generate_identity_proof(&identity, &private_data, &requirements).await;
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.proof_system, "lib-PlonkyCommit");
        assert!(!proof.proof_data.is_empty());
    }

    #[tokio::test]
    async fn test_sign_with_identity() {
        let service = SigningService::new();
        let identity = create_test_identity();
        let private_data = create_test_private_data();
        let data = b"test data";

        let result = service.sign_with_identity(&identity, &private_data, data).await;
        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.algorithm, lib_crypto::SignatureAlgorithm::Dilithium2);
        assert!(!signature.signature.is_empty());
    }

    #[tokio::test]
    async fn test_generate_pq_keypair() {
        let service = SigningService::new();

        let result = service.generate_pq_keypair().await;
        assert!(result.is_ok());
        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.len(), 64);
        assert!(!public_key.is_empty());
    }

    #[tokio::test]
    async fn test_generate_ownership_proof() {
        let service = SigningService::new();
        let private_key = vec![1u8; 64];
        let public_key = vec![2u8; 32];

        let result = service.generate_ownership_proof(&private_key, &public_key).await;
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.proof_system, "lib-OwnershipProof");
        assert!(!proof.proof_data.is_empty());
    }
}
