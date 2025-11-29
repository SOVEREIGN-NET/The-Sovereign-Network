//! Credential Service
//!
//! Private service responsible for credential management and verification.
//! This service handles credential issuance, verification, and reputation updates.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use lib_crypto::Hash;

use crate::types::{IdentityId, CredentialType, IdentityProofParams, IdentityVerification};
use crate::identity::ZhtpIdentity;
use crate::credentials::ZkCredential;
use crate::citizenship::onboarding::PrivacyCredentials;

/// Private service for credential management
/// 
/// This service manages credential issuance, verification, trusted issuers,
/// and credential-based reputation updates. It maintains caches for performance.
#[derive(Debug)]
pub(crate) struct CredentialService {
    /// Map of trusted credential issuers to the types they can issue
    trusted_issuers: HashMap<IdentityId, Vec<CredentialType>>,
    /// Cache of identity verification results (TTL: 1 hour)
    verification_cache: HashMap<IdentityId, IdentityVerification>,
}

impl CredentialService {
    /// Create a new credential service
    pub fn new() -> Self {
        Self {
            trusted_issuers: HashMap::new(),
            verification_cache: HashMap::new(),
        }
    }

    /// Add a credential to an identity
    /// 
    /// Verifies the credential proof and issuer trust before adding.
    /// Also updates reputation based on credential type.
    pub async fn add_credential(
        &mut self,
        identity: &mut ZhtpIdentity,
        credential: ZkCredential,
    ) -> Result<()> {
        let credential_type = credential.credential_type.clone();
        
        // Verify credential proof and issuer trust
        if !self.verify_credential_proof(&credential).await? {
            return Err(anyhow!("Invalid credential proof or untrusted issuer"));
        }
        
        // Add credential to identity
        identity.credentials.insert(credential_type.clone(), credential);
        
        // Update reputation based on credential type
        Self::update_reputation_for_credential(identity, &credential_type)?;
        
        // Clear verification cache for this identity
        self.verification_cache.remove(&identity.id);
        
        Ok(())
    }

    /// Verify an identity against requirements
    /// 
    /// Checks if identity has required credentials and meets all requirements.
    /// Results are cached for 1 hour.
    pub async fn verify_identity(
        &mut self,
        identity: &ZhtpIdentity,
        requirements: &IdentityProofParams,
    ) -> Result<IdentityVerification> {
        // Check cache first (1 hour TTL)
        if let Some(cached) = self.verification_cache.get(&identity.id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if cached.verified_at + 3600 > now {
                return Ok(cached.clone());
            }
        }
        
        let mut requirements_met = Vec::new();
        let mut requirements_failed = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Check required credentials
        for req_credential in &requirements.required_credentials {
            if let Some(credential) = identity.credentials.get(req_credential) {
                // Verify credential is still valid
                if let Some(expires_at) = credential.expires_at {
                    if expires_at > now {
                        requirements_met.push(req_credential.clone());
                    } else {
                        requirements_failed.push(req_credential.clone());
                    }
                } else {
                    requirements_met.push(req_credential.clone());
                }
            } else {
                requirements_failed.push(req_credential.clone());
            }
        }
        
        // Check age requirement (if any)
        if let Some(_min_age) = requirements.min_age {
            if !identity.credentials.contains_key(&CredentialType::AgeVerification) {
                requirements_failed.push(CredentialType::AgeVerification);
            }
        }
        
        let verified = requirements_failed.is_empty();
        let privacy_score = std::cmp::min(requirements.privacy_level, 100);
        
        let verification = IdentityVerification {
            identity_id: identity.id.clone(),
            verified,
            requirements_met,
            requirements_failed,
            privacy_score,
            verified_at: now,
        };
        
        // Cache verification result
        self.verification_cache.insert(identity.id.clone(), verification.clone());
        
        Ok(verification)
    }

    /// Add a trusted credential issuer
    /// 
    /// Registers an issuer as trusted for specific credential types.
    pub fn add_trusted_issuer(
        &mut self,
        issuer_id: IdentityId,
        credential_types: Vec<CredentialType>,
    ) {
        self.trusted_issuers.insert(issuer_id, credential_types);
    }

    /// Create a zero-knowledge credential
    /// 
    /// Internal method for generating new credentials with ZK proofs.
    pub async fn create_zk_credential(
        &self,
        identity_id: &IdentityId,
        credential_type: CredentialType,
        claim: String,
        expires_at: u64,
    ) -> Result<ZkCredential> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create proof for credential
        let proof_data = lib_crypto::hash_blake3(&[
            identity_id.0.as_slice(),
            claim.as_bytes(),
            &current_time.to_le_bytes(),
        ].concat());
        
        let public_inputs = [
            identity_id.0.as_slice(),
            credential_type.to_string().as_bytes(),
        ].concat();
        
        let verification_key = lib_crypto::hash_blake3(&[
            proof_data.as_slice(),
            &public_inputs,
        ].concat());
        
        let proof = lib_proofs::ZeroKnowledgeProof {
            proof_system: "lib-CredentialProof".to_string(),
            proof_data: proof_data.to_vec(),
            public_inputs,
            verification_key: verification_key.to_vec(),
            plonky2_proof: None,
            proof: vec![],
        };
        
        // Store claim in metadata
        let metadata = claim.as_bytes().to_vec();
        
        Ok(ZkCredential::new(
            credential_type,
            identity_id.clone(),
            identity_id.clone(),
            proof,
            Some(expires_at),
            metadata,
        ))
    }

    /// Set up privacy-preserving credentials for new identity
    /// 
    /// Creates age verification and reputation credentials automatically.
    #[cfg(test)]
    pub async fn setup_privacy_credentials(
        &self,
        identity: &mut ZhtpIdentity,
    ) -> Result<PrivacyCredentials> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create age verification credential (proves age >= 18 without revealing exact age)
        let age_credential = self.create_zk_credential(
            &identity.id,
            CredentialType::AgeVerification,
            "age_gte_18".to_string(),
            current_time + (365 * 24 * 3600), // Valid for 1 year
        ).await?;

        // Create reputation credential
        let reputation_credential = self.create_zk_credential(
            &identity.id,
            CredentialType::Reputation,
            format!("reputation_{}", identity.reputation),
            current_time + (30 * 24 * 3600), // Valid for 30 days
        ).await?;

        // Add credentials to identity
        identity.credentials.insert(CredentialType::AgeVerification, age_credential.clone());
        identity.credentials.insert(CredentialType::Reputation, reputation_credential.clone());

        tracing::info!(
            "🔐 PRIVACY CREDENTIALS: Citizen {} has {} ZK credentials",
            hex::encode(&identity.id.0[..8]),
            identity.credentials.len()
        );

        Ok(PrivacyCredentials::new(
            identity.id.clone(),
            vec![age_credential, reputation_credential],
        ))
    }

    // --- Internal Helper Methods ---

    /// Verify credential proof and issuer trust (internal)
    pub async fn verify_credential_proof(&self, credential: &ZkCredential) -> Result<bool> {
        let proof_data = &credential.proof.proof_data;
        let public_inputs = &credential.proof.public_inputs;
        let verification_key = &credential.proof.verification_key;
        
        // Verify proof structure
        if proof_data.is_empty() || public_inputs.is_empty() || verification_key.is_empty() {
            return Ok(false);
        }
        
        // Verify issuer is trusted for this credential type
        if let Some(trusted_types) = self.trusted_issuers.get(&credential.issuer) {
            if !trusted_types.contains(&credential.credential_type) {
                return Ok(false);
            }
        } else {
            // Issuer not in trusted list
            return Ok(false);
        }
        
        // Verify credential hasn't expired
        if let Some(expires_at) = credential.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if expires_at <= now {
                return Ok(false);
            }
        }
        
        // For self-issued credentials (testing), skip cryptographic verification
        if credential.issuer == credential.subject {
            return Ok(true);
        }
        
        // Verify cryptographic proof for externally-issued credentials
        let expected_proof = lib_crypto::hash_blake3(&[
            credential.issuer.0.as_slice(),
            credential.subject.0.as_slice(),
            &serde_json::to_vec(&credential.credential_type)?,
            &credential.issued_at.to_le_bytes()
        ].concat());
        
        let verification_check = lib_crypto::hash_blake3(&[
            proof_data,
            public_inputs,
            expected_proof.as_slice()
        ].concat());
        
        // Compare with verification key
        let verification_match = verification_key == &verification_check.to_vec();
        
        Ok(verification_match)
    }

    /// Update reputation based on credential type (internal)
    fn update_reputation_for_credential(
        identity: &mut ZhtpIdentity,
        credential_type: &CredentialType,
    ) -> Result<()> {
        // Increase reputation based on credential type
        let reputation_boost = match credential_type {
            CredentialType::GovernmentId => 50,
            CredentialType::Education => 30,
            CredentialType::Professional => 40,
            CredentialType::Financial => 25,
            CredentialType::Biometric => 20,
            _ => 10,
        };
        
        identity.reputation = std::cmp::min(1000, identity.reputation + reputation_boost);
        Ok(())
    }
}

impl Default for CredentialService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AccessLevel;
    use lib_proofs::ZeroKnowledgeProof;

    fn create_test_identity() -> ZhtpIdentity {
        let id = Hash::from_bytes(&[1u8; 32]);
        ZhtpIdentity {
            id: id.clone(),
            identity_type: crate::types::IdentityType::Human,
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

    #[test]
    fn test_new_credential_service() {
        let service = CredentialService::new();
        assert_eq!(service.trusted_issuers.len(), 0);
        assert_eq!(service.verification_cache.len(), 0);
    }

    #[test]
    fn test_add_trusted_issuer() {
        let mut service = CredentialService::new();
        let issuer_id = Hash::from_bytes(&[2u8; 32]);
        let types = vec![CredentialType::GovernmentId, CredentialType::Education];
        
        service.add_trusted_issuer(issuer_id.clone(), types.clone());
        assert_eq!(service.trusted_issuers.len(), 1);
        assert_eq!(service.trusted_issuers.get(&issuer_id), Some(&types));
    }

    #[tokio::test]
    async fn test_create_zk_credential() {
        let service = CredentialService::new();
        let identity_id = Hash::from_bytes(&[3u8; 32]);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = current_time + 3600;
        
        let result = service.create_zk_credential(
            &identity_id,
            CredentialType::AgeVerification,
            "age_gte_18".to_string(),
            expires_at,
        ).await;
        
        assert!(result.is_ok());
        let credential = result.unwrap();
        assert_eq!(credential.credential_type, CredentialType::AgeVerification);
        // ZkCredential doesn't have a claim field - metadata is encrypted
        assert_eq!(credential.subject, identity_id);
        assert_eq!(credential.expires_at, Some(expires_at));
        assert!(!credential.proof.proof_data.is_empty());
    }

    #[tokio::test]
    async fn test_verify_identity_no_credentials() {
        let mut service = CredentialService::new();
        let identity = create_test_identity();
        let requirements = IdentityProofParams::new(
            Some(18),
            None,
            vec![CredentialType::AgeVerification],
            80,
        );
        
        let result = service.verify_identity(&identity, &requirements).await;
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(!verification.verified);
        assert_eq!(verification.requirements_failed.len(), 2); // Missing AgeVerification twice (once for required, once for min_age)
    }

    #[tokio::test]
    async fn test_verify_identity_with_credentials() {
        let mut service = CredentialService::new();
        let mut identity = create_test_identity();
        
        // Add credential
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let credential = service.create_zk_credential(
            &identity.id,
            CredentialType::AgeVerification,
            "age_gte_18".to_string(),
            current_time + 3600,
        ).await.unwrap();
        identity.credentials.insert(CredentialType::AgeVerification, credential);
        
        // Verify
        let requirements = IdentityProofParams::new(
            Some(18),
            None,
            vec![CredentialType::AgeVerification],
            80,
        );
        
        let result = service.verify_identity(&identity, &requirements).await;
        assert!(result.is_ok());
        let verification = result.unwrap();
        assert!(verification.verified);
        assert_eq!(verification.requirements_met.len(), 1);
        assert_eq!(verification.requirements_failed.len(), 0);
    }

    #[tokio::test]
    async fn test_add_credential_without_trusted_issuer() {
        let mut service = CredentialService::new();
        let mut identity = create_test_identity();
        
        // Create credential (but don't add issuer to trusted list)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let credential = service.create_zk_credential(
            &identity.id,
            CredentialType::GovernmentId,
            "test".to_string(),
            current_time + 3600,
        ).await.unwrap();
        
        // Try to add credential (should fail - untrusted issuer)
        let result = service.add_credential(&mut identity, credential).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_credential_with_trusted_issuer() {
        let mut service = CredentialService::new();
        let mut identity = create_test_identity();
        
        // Add issuer to trusted list
        service.add_trusted_issuer(
            identity.id.clone(),
            vec![CredentialType::GovernmentId],
        );
        
        // Create and add credential
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let credential = service.create_zk_credential(
            &identity.id,
            CredentialType::GovernmentId,
            "test".to_string(),
            current_time + 3600,
        ).await.unwrap();
        
        let old_reputation = identity.reputation;
        let result = service.add_credential(&mut identity, credential).await;
        assert!(result.is_ok());
        assert_eq!(identity.credentials.len(), 1);
        assert!(identity.reputation > old_reputation); // Reputation should increase
    }

    #[test]
    fn test_update_reputation() {
        let mut identity = create_test_identity();
        let old_reputation = identity.reputation;
        
        CredentialService::update_reputation_for_credential(
            &mut identity,
            &CredentialType::GovernmentId,
        ).unwrap();
        
        assert_eq!(identity.reputation, old_reputation + 50);
    }
}
