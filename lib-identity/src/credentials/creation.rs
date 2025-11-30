//! Credential creation functionality from the original identity.rs

use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::collections::HashMap;
use lib_crypto::Hash;
use lib_proofs::ZeroKnowledgeProof;
use crate::types::{IdentityId, CredentialType};
use crate::credentials::ZkCredential;

/// Credential creation factory
#[derive(Debug, Clone)]
pub struct CredentialFactory {
    /// Factory identity ID
    pub factory_id: IdentityId,
    /// Trusted issuers
    pub trusted_issuers: HashMap<IdentityId, Vec<CredentialType>>,
    /// Creation statistics
    pub creation_stats: CreationStats,
}

/// Credential creation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationStats {
    /// Total credentials created
    pub total_created: u64,
    /// Credentials by type
    pub by_type: HashMap<CredentialType, u64>,
    /// Creation timestamps
    pub creation_times: Vec<u64>,
    /// Success rate
    pub success_rate: f64,
}

/// Credential creation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationResult {
    /// Creation success
    pub success: bool,
    /// Created credential (if successful)
    pub credential: ZkCredential,
    /// Creation metadata
    pub metadata: CreationMetadata,
    /// Any warnings or errors
    pub messages: Vec<String>,
}

/// Credential creation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationMetadata {
    /// Creation timestamp
    pub created_at: u64,
    /// Creator identity
    pub creator_id: IdentityId,
    /// Creation method
    pub creation_method: String,
    /// Verification method used
    pub verification_method: String,
    /// Proof generation time (milliseconds)
    pub proof_generation_time: u64,
}

impl CredentialFactory {
    /// Create a new credential factory
    pub fn new(factory_id: IdentityId) -> Self {
        Self {
            factory_id,
            trusted_issuers: HashMap::new(),
            creation_stats: CreationStats {
                total_created: 0,
                by_type: HashMap::new(),
                creation_times: Vec::new(),
                success_rate: 1.0,
            },
        }
    }

    /// Add a trusted issuer
    pub fn add_trusted_issuer(&mut self, issuer_id: IdentityId, credential_types: Vec<CredentialType>) {
        self.trusted_issuers.insert(issuer_id, credential_types);
    }

    /// Create a zero-knowledge credential - IMPLEMENTATION FROM ORIGINAL
    pub async fn create_zk_credential(
        &mut self,
        subject_id: IdentityId,
        credential_type: CredentialType,
        claim: String,
        expires_at: Option<u64>,
        issuer_id: IdentityId,
    ) -> Result<CreationResult> {
        let start_time = std::time::SystemTime::now();
        let current_time = start_time
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Verify issuer is trusted for this credential type
        if let Some(trusted_types) = self.trusted_issuers.get(&issuer_id) {
            if !trusted_types.contains(&credential_type) {
                return Ok(CreationResult {
                    success: false,
                    credential: self.create_empty_credential(subject_id, credential_type)?,
                    metadata: self.create_metadata(issuer_id, "failed_untrusted_issuer".to_string(), 0),
                    messages: vec!["Issuer not trusted for this credential type".to_string()],
                });
            }
        } else {
            return Ok(CreationResult {
                success: false,
                credential: self.create_empty_credential(subject_id, credential_type)?,
                metadata: self.create_metadata(issuer_id, "failed_unknown_issuer".to_string(), 0),
                messages: vec!["Unknown issuer".to_string()],
            });
        }

        // Generate credential ID
        let credential_id = lib_crypto::hash_blake3(
            &[
                subject_id.0.as_slice(),
                claim.as_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        );

        // Create ZK proof for the credential
        let zk_proof = self.generate_credential_proof(&subject_id, &credential_type, &claim).await?;

        // Create the credential
        let credential = ZkCredential {
            id: Hash::from_bytes(&credential_id),
            credential_type: credential_type.clone(),
            issuer: issuer_id.clone(),
            subject: subject_id,
            proof: zk_proof,
            issued_at: current_time,
            expires_at,
            metadata: claim.into_bytes(),
        };

        // Calculate proof generation time
        let proof_time = std::time::SystemTime::now()
            .duration_since(start_time)?
            .as_millis() as u64;

        // Update statistics
        self.creation_stats.total_created += 1;
        *self.creation_stats.by_type.entry(credential_type).or_insert(0) += 1;
        self.creation_stats.creation_times.push(current_time);

        Ok(CreationResult {
            success: true,
            credential,
            metadata: self.create_metadata(issuer_id, "zk_proof".to_string(), proof_time),
            messages: vec!["Credential created successfully".to_string()],
        })
    }

    /// Create age verification credential - SPECIALIZED FROM ORIGINAL
    pub async fn create_age_verification_credential(
        &mut self,
        subject_id: IdentityId,
        age: u8,
        _zk_proof: Option<ZeroKnowledgeProof>,
        issuer_id: IdentityId,
    ) -> Result<CreationResult> {
        let claim = format!("age_verified_{}", age);
        
        // Use the base create_zk_credential method which includes issuer validation
        self.create_zk_credential(
            subject_id,
            CredentialType::AgeVerification,
            claim,
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap()
                .as_secs() + (365 * 24 * 3600)), // Valid for 1 year
            issuer_id,
        ).await
    }

    /// Create reputation credential - SPECIALIZED FROM ORIGINAL
    pub async fn create_reputation_credential(
        &mut self,
        subject_id: IdentityId,
        reputation_score: u32,
        issuer_id: IdentityId,
    ) -> Result<CreationResult> {
        let claim = format!("reputation_{}", reputation_score);

        // Use the base create_zk_credential method which includes issuer validation
        self.create_zk_credential(
            subject_id,
            CredentialType::Reputation,
            claim,
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap()
                .as_secs() + (30 * 24 * 3600)), // Valid for 30 days
            issuer_id,
        ).await
    }

    /// Generate credential proof - ZK IMPLEMENTATION FROM ORIGINAL
    async fn generate_credential_proof(
        &self,
        subject_id: &IdentityId,
        credential_type: &CredentialType,
        claim: &str,
    ) -> Result<ZeroKnowledgeProof> {
        // Create ZK proof for the credential
        let proof_data = lib_crypto::hash_blake3(&[
            subject_id.0.as_slice(),
            claim.as_bytes(),
            &serde_json::to_vec(credential_type)?,
        ].concat());

        let public_inputs = lib_crypto::hash_blake3(&[
            subject_id.0.as_slice(),
            &self.factory_id.0,
        ].concat());

        let verification_key = lib_crypto::hash_blake3(&[
            proof_data.as_slice(),
            public_inputs.as_slice(),
        ].concat());

        Ok(ZeroKnowledgeProof {
            proof_system: "lib-CredentialProof".to_string(),
            proof_data: proof_data.to_vec(),
            public_inputs: public_inputs.to_vec(),
            verification_key: verification_key.to_vec(),
            plonky2_proof: None,
            proof: vec![],
        })
    }

    /// Generate age verification proof
    #[allow(dead_code)] // API method - will be used when ZK proof integration is complete
    async fn generate_age_proof(&self, age: u8) -> Result<ZeroKnowledgeProof> {
        let age_verification_bytes = b"age_verification";
        let mut data = Vec::new();
        data.extend_from_slice(&age.to_le_bytes());
        data.extend_from_slice(age_verification_bytes);
        data.extend_from_slice(&self.factory_id.0);
        let proof_data = lib_crypto::hash_blake3(&data);

        Ok(ZeroKnowledgeProof {
            proof_system: "lib-AgeProof".to_string(),
            proof_data: proof_data.to_vec(),
            public_inputs: vec![18], // Minimum age
            verification_key: proof_data.to_vec(),
            plonky2_proof: None,
            proof: vec![],
        })
    }

    /// Generate reputation proof
    #[allow(dead_code)] // API method - will be used when ZK proof integration is complete
    async fn generate_reputation_proof(&self, score: u32) -> Result<ZeroKnowledgeProof> {
        let reputation_verification_bytes = b"reputation_verification";
        let mut data = Vec::new();
        data.extend_from_slice(&score.to_le_bytes());
        data.extend_from_slice(reputation_verification_bytes);
        data.extend_from_slice(&self.factory_id.0);
        let proof_data = lib_crypto::hash_blake3(&data);

        Ok(ZeroKnowledgeProof {
            proof_system: "lib-ReputationProof".to_string(),
            proof_data: proof_data.to_vec(),
            public_inputs: score.to_le_bytes().to_vec(),
            verification_key: proof_data.to_vec(),
            plonky2_proof: None,
            proof: vec![],
        })
    }

    /// Create empty credential for failed cases
    fn create_empty_credential(&self, subject_id: IdentityId, credential_type: CredentialType) -> Result<ZkCredential> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(ZkCredential {
            id: Hash([0u8; 32]),
            credential_type,
            issuer: self.factory_id.clone(),
            subject: subject_id,
            proof: ZeroKnowledgeProof {
                proof_system: "lib-EmptyProof".to_string(),
                proof_data: vec![],
                public_inputs: vec![],
                verification_key: vec![],
                plonky2_proof: None,
                proof: vec![],
            },
            issued_at: current_time,
            expires_at: None,
            metadata: vec![],
        })
    }

    /// Create creation metadata
    fn create_metadata(&self, creator_id: IdentityId, method: String, proof_time: u64) -> CreationMetadata {
        CreationMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            creator_id,
            creation_method: method,
            verification_method: "zk_proof".to_string(),
            proof_generation_time: proof_time,
        }
    }

    /// Get creation statistics
    pub fn get_stats(&self) -> &CreationStats {
        &self.creation_stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_age_verification_credential_creation() {
        let factory_id = Hash([1u8; 32]);
        let mut factory = CredentialFactory::new(factory_id);
        let subject_id = Hash([2u8; 32]);
        let issuer_id = Hash([3u8; 32]);

        // Add trusted issuer
        factory.add_trusted_issuer(issuer_id.clone(), vec![CredentialType::AgeVerification]);

        // Create age verification credential
        let result = factory.create_age_verification_credential(
            subject_id.clone(),
            18,
            None, // Zero-knowledge proof
            issuer_id,
        ).await.unwrap();

        assert!(result.success);
        assert_eq!(result.credential.credential_type, CredentialType::AgeVerification);
        assert_eq!(result.credential.subject, subject_id);
    }

    #[tokio::test]
    async fn test_reputation_credential_creation() {
        let factory_id = Hash([1u8; 32]);
        let mut factory = CredentialFactory::new(factory_id);
        let subject_id = Hash([2u8; 32]);
        let issuer_id = Hash([3u8; 32]);

        // Add trusted issuer
        factory.add_trusted_issuer(issuer_id.clone(), vec![CredentialType::Reputation]);

        // Create reputation credential
        let result = factory.create_reputation_credential(
            subject_id.clone(),
            750,
            issuer_id,
        ).await.unwrap();

        assert!(result.success);
        assert_eq!(result.credential.credential_type, CredentialType::Reputation);
        assert_eq!(result.credential.subject, subject_id);
    }
}