//! Comprehensive tests for Identity Manager
//! 
//! These tests cover all aspects of the IdentityManager functionality,
//! including citizen onboarding, credential management, and verification.

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::types::*;
    use crate::credentials::*;
    use crate::citizenship::*;
    use crate::economics::EconomicModel;
    use crate::wallets::WalletType;
    use lib_crypto::Hash;
    use std::collections::HashMap;

    fn create_mock_economic_model() -> EconomicModel {
        EconomicModel::new()
    }

    #[tokio::test]
    async fn test_identity_manager_creation() {
        let manager = IdentityManager::new();
        
        assert_eq!(manager.list_identities().len(), 0);
        assert!(manager.trusted_issuers.is_empty());
        assert!(manager.verification_cache.is_empty());
    }

    #[tokio::test]
    async fn test_create_basic_identity() {
        let mut manager = IdentityManager::new();
        
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["test recovery phrase".to_string()],
        ).await.expect("Failed to create identity");
        
        assert!(!identity_id.0.is_empty());
        
        let identity = manager.get_identity(&identity_id).expect("Identity not found");
        assert_eq!(identity.identity_type, IdentityType::Human);
        assert_eq!(identity.reputation, 100); // Starting reputation
        assert!(identity.wallet_manager.wallets.is_empty()); // No automatic wallets for basic identity
    }

    #[tokio::test]
    async fn test_create_citizen_identity_full_flow() {
        let mut manager = IdentityManager::new();
        let mut economic_model = create_mock_economic_model();
        
        let citizenship_result = manager.create_citizen_identity(
            vec!["recovery phrase one".to_string(), "recovery phrase two".to_string()],
            &mut economic_model,
        ).await.expect("Failed to create citizen identity");
        
        // Verify identity creation
        assert!(!citizenship_result.identity_id.0.is_empty());
        
        // Verify wallet creation
        assert!(!citizenship_result.primary_wallet_id.0.is_empty());
        assert!(!citizenship_result.ubi_wallet_id.0.is_empty());
        assert!(!citizenship_result.savings_wallet_id.0.is_empty());
        assert_ne!(citizenship_result.primary_wallet_id, citizenship_result.ubi_wallet_id);
        assert_ne!(citizenship_result.primary_wallet_id, citizenship_result.savings_wallet_id);
        
        // Verify DAO registration
        assert_eq!(citizenship_result.dao_registration.voting_power, 1);
        assert!(citizenship_result.dao_registration.voting_eligibility);
        assert!(citizenship_result.dao_registration.proposal_eligibility);
        assert!(!citizenship_result.dao_registration.membership_proof.is_empty());
        
        // Verify UBI registration
        assert_eq!(citizenship_result.ubi_registration.monthly_amount, 1000);
        assert!(citizenship_result.ubi_registration.daily_amount > 0);
        assert!(citizenship_result.ubi_registration.daily_amount <= 35); // Roughly 1000/30
        assert!(!citizenship_result.ubi_registration.eligibility_proof.is_empty());
        
        // Verify Web4 access
        assert_eq!(citizenship_result.web4_access.access_level, AccessLevel::FullCitizen);
        assert!(citizenship_result.web4_access.restrictions.is_empty());
        assert!(citizenship_result.web4_access.service_tokens.len() >= 10);
        
        // Verify essential services
        let essential_services = [
            "zhtp.browse", "zhtp.publish", "zhtp.storage", "zhtp.messaging",
            "zhtp.identity", "zhtp.wallet", "zhtp.voting", "zhtp.marketplace"
        ];
        for service in &essential_services {
            assert!(citizenship_result.web4_access.service_tokens.contains_key(*service),
                "Missing essential service: {}", service);
        }
        
        // Verify privacy credentials
        assert_eq!(citizenship_result.privacy_credentials.identity_id, citizenship_result.identity_id);
        assert_eq!(citizenship_result.privacy_credentials.credentials.len(), 2); // Age + Reputation
        
        // Verify welcome bonus
        assert_eq!(citizenship_result.welcome_bonus.bonus_amount, 5000);
        assert_eq!(citizenship_result.welcome_bonus.wallet_id, citizenship_result.primary_wallet_id);
        
        // Verify the identity was stored in manager
        let stored_identity = manager.get_identity(&citizenship_result.identity_id)
            .expect("Citizen identity not found in manager");
        assert_eq!(stored_identity.identity_type, IdentityType::Human);
        assert_eq!(stored_identity.reputation, 1000); // Citizens start with higher reputation
        
        // Verify wallets are created in the identity
        assert_eq!(stored_identity.wallet_manager.wallets.len(), 3);
    }

    #[tokio::test]
    async fn test_onboard_new_citizen_with_display_name() {
        let mut manager = IdentityManager::new();
        let mut economic_model = create_mock_economic_model();
        
        let citizenship_result = manager.onboard_new_citizen(
            "John Doe".to_string(),
            vec!["word1".to_string(), "word2".to_string(), "word3".to_string()],
            &mut economic_model,
        ).await.expect("Failed to onboard citizen");
        
        // Verify all components are created
        assert!(!citizenship_result.identity_id.0.is_empty());
        assert_eq!(citizenship_result.dao_registration.voting_power, 1);
        assert_eq!(citizenship_result.ubi_registration.monthly_amount, 1000);
        assert_eq!(citizenship_result.web4_access.access_level, AccessLevel::FullCitizen);
        assert_eq!(citizenship_result.welcome_bonus.bonus_amount, 1000); // Different bonus amount in this method
        
        // Verify identity is stored
        let identity = manager.get_identity(&citizenship_result.identity_id).unwrap();
        assert_eq!(identity.reputation, 500); // Different starting reputation
    }

    #[tokio::test]
    async fn test_multiple_citizen_creation() {
        let mut manager = IdentityManager::new();
        let mut economic_model = create_mock_economic_model();
        
        let mut citizen_ids = Vec::new();
        
        // Create multiple citizens
        for i in 0..5 {
            let result = manager.onboard_new_citizen(
                format!("Citizen {}", i),
                vec![format!("recovery{}", i)],
                &mut economic_model,
            ).await.expect("Failed to create citizen");
            
            citizen_ids.push(result.identity_id);
        }
        
        // Verify all citizens are unique
        assert_eq!(citizen_ids.len(), 5);
        for i in 0..5 {
            for j in i+1..5 {
                assert_ne!(citizen_ids[i], citizen_ids[j]);
            }
        }
        
        // Verify all are stored in manager
        assert_eq!(manager.list_identities().len(), 5);
        
        // Verify each has proper citizen privileges
        for citizen_id in &citizen_ids {
            let identity = manager.get_identity(citizen_id).unwrap();
            assert_eq!(identity.identity_type, IdentityType::Human);
            assert_eq!(identity.wallet_manager.wallets.len(), 3); // 3 wallets each
        }
    }

    #[tokio::test]
    async fn test_credential_management() {
        let mut manager = IdentityManager::new();
        
        // Create basic identity
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["recovery".to_string()],
        ).await.expect("Failed to create identity");
        
        // Add trusted issuer
        let issuer_id = Hash([99u8; 32]);
        manager.add_trusted_issuer(issuer_id.clone(), vec![
            CredentialType::AgeVerification,
            CredentialType::Education,
        ]);
        
        // Create and add credential
        let credential = ZkCredential {
            id: Hash([1u8; 32]),
            credential_type: CredentialType::AgeVerification,
            issuer: issuer_id,
            subject: identity_id.clone(),
            proof: lib_proofs::ZeroKnowledgeProof {
                proof_system: "Test".to_string(),
                proof_data: vec![1, 2, 3],
                public_inputs: vec![4, 5, 6],
                verification_key: vec![7, 8, 9],
                plonky2_proof: None,
                proof: vec![],
            },
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600),
            metadata: b"age_18_or_older".to_vec(),
        };
        
        manager.add_credential(&identity_id, credential).await
            .expect("Failed to add credential");
        
        // Verify credential was added
        let identity = manager.get_identity(&identity_id).unwrap();
        assert!(identity.credentials.contains_key(&CredentialType::AgeVerification));
    }

    #[tokio::test]
    async fn test_identity_verification() {
        let mut manager = IdentityManager::new();
        
        // Create identity
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["recovery".to_string()],
        ).await.expect("Failed to create identity");
        
        // Test verification without requirements
        let requirements = IdentityProofParams {
            min_age: None,
            jurisdiction: None,
            required_credentials: vec![],
            privacy_level: 50,
        };
        
        let verification = manager.verify_identity(&identity_id, &requirements)
            .await.expect("Failed to verify identity");
        
        assert!(verification.verified);
        assert!(verification.requirements_met.is_empty());
        assert!(verification.requirements_failed.is_empty());
        assert_eq!(verification.privacy_score, 50);
        
        // Test verification with requirements (should fail)
        let strict_requirements = IdentityProofParams {
            min_age: Some(18),
            jurisdiction: None,
            required_credentials: vec![CredentialType::AgeVerification],
            privacy_level: 80,
        };
        
        let strict_verification = manager.verify_identity(&identity_id, &strict_requirements)
            .await.expect("Failed to verify identity");
        
        assert!(!strict_verification.verified);
        assert!(strict_verification.requirements_failed.contains(&CredentialType::AgeVerification));
    }

    #[tokio::test]
    async fn test_identity_proof_generation() {
        let mut manager = IdentityManager::new();
        
        // Create identity
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["recovery".to_string()],
        ).await.expect("Failed to create identity");
        
        let requirements = IdentityProofParams {
            min_age: None,
            jurisdiction: None,
            required_credentials: vec![],
            privacy_level: 75,
        };
        
        let proof = manager.generate_identity_proof(&identity_id, &requirements)
            .await.expect("Failed to generate identity proof");
        
        assert_eq!(proof.proof_system, "lib-PlonkyCommit");
        assert!(!proof.proof_data.is_empty());
        assert!(!proof.public_inputs.is_empty());
        assert!(!proof.verification_key.is_empty());
    }

    #[tokio::test]
    async fn test_signing_with_identity() {
        let mut manager = IdentityManager::new();
        
        // Create identity
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["recovery".to_string()],
        ).await.expect("Failed to create identity");
        
        let data_to_sign = b"Important message to sign";
        
        let signature = manager.sign_with_identity(&identity_id, data_to_sign)
            .await.expect("Failed to sign with identity");
        
        assert!(!signature.signature.is_empty());
        assert!(!signature.public_key.dilithium_pk.is_empty());
        assert!(!signature.public_key.kyber_pk.is_empty());
        assert_eq!(signature.algorithm, lib_crypto::SignatureAlgorithm::Dilithium2);
        assert!(signature.timestamp > 0);
    }

    #[tokio::test]
    async fn test_trusted_issuer_management() {
        let mut manager = IdentityManager::new();
        
        let issuer_id = Hash([42u8; 32]);
        let credential_types = vec![
            CredentialType::Education,
            CredentialType::Professional,
            CredentialType::GovernmentId,
        ];
        
        // Add trusted issuer
        manager.add_trusted_issuer(issuer_id.clone(), credential_types.clone());
        
        // Verify issuer was added
        assert!(manager.trusted_issuers.contains_key(&issuer_id));
        assert_eq!(manager.trusted_issuers.get(&issuer_id).unwrap(), &credential_types);
    }

    #[tokio::test]
    async fn test_different_identity_types() {
        let mut manager = IdentityManager::new();
        
        // Test different identity types
        let identity_types = vec![
            IdentityType::Human,
            IdentityType::Agent,
            IdentityType::Contract,
            IdentityType::Organization,
            IdentityType::Device,
        ];
        
        let mut created_identities = Vec::new();
        
        for identity_type in identity_types {
            let identity_id = manager.create_identity(
                identity_type.clone(),
                vec![format!("recovery_{:?}", identity_type)],
            ).await.expect("Failed to create identity");
            
            created_identities.push((identity_id, identity_type));
        }
        
        // Verify all identities were created with correct types
        for (identity_id, expected_type) in created_identities {
            let identity = manager.get_identity(&identity_id).unwrap();
            assert_eq!(identity.identity_type, expected_type);
        }
    }

    #[tokio::test]
    async fn test_wallet_creation_and_management() {
        let mut manager = IdentityManager::new();
        let mut economic_model = create_mock_economic_model();
        
        // Create citizen (which automatically creates wallets)
        let citizenship_result = manager.create_citizen_identity(
            vec!["recovery".to_string()],
            &mut economic_model,
        ).await.expect("Failed to create citizen");
        
        let identity = manager.get_identity(&citizenship_result.identity_id).unwrap();
        
        // Verify wallet creation
        assert_eq!(identity.wallet_manager.wallets.len(), 3);
        
        // Test wallet access by alias
        assert!(identity.get_wallet("primary").is_some());
        assert!(identity.get_wallet("ubi").is_some());
        assert!(identity.get_wallet("savings").is_some());
        
        // Test wallet listing
        let wallet_summaries = identity.list_wallets();
        assert_eq!(wallet_summaries.len(), 3);
        
        // Test total balance calculation
        let total_balance = identity.get_total_balance();
        assert_eq!(total_balance, 0); // No funds added yet
    }

    #[tokio::test]
    async fn test_error_handling_invalid_operations() {
        let mut manager = IdentityManager::new();
        
        // Try to get non-existent identity
        let fake_id = Hash([255u8; 32]);
        assert!(manager.get_identity(&fake_id).is_none());
        
        // Try to verify non-existent identity
        let requirements = IdentityProofParams {
            min_age: None,
            jurisdiction: None,
            required_credentials: vec![],
            privacy_level: 50,
        };
        
        let verification_result = manager.verify_identity(&fake_id, &requirements).await;
        assert!(verification_result.is_err());
        
        // Try to sign with non-existent identity
        let sign_result = manager.sign_with_identity(&fake_id, b"test data").await;
        assert!(sign_result.is_err());
    }

    #[tokio::test]
    async fn test_verification_cache_functionality() {
        let mut manager = IdentityManager::new();
        
        // Create identity
        let identity_id = manager.create_identity(
            IdentityType::Human,
            vec!["recovery".to_string()],
        ).await.expect("Failed to create identity");
        
        let requirements = IdentityProofParams {
            min_age: None,
            jurisdiction: None,
            required_credentials: vec![],
            privacy_level: 60,
        };
        
        // First verification (should cache result)
        let verification1 = manager.verify_identity(&identity_id, &requirements)
            .await.expect("Failed to verify identity");
        
        // Second verification (should use cache)
        let verification2 = manager.verify_identity(&identity_id, &requirements)
            .await.expect("Failed to verify identity");
        
        // Results should be identical
        assert_eq!(verification1.verified, verification2.verified);
        assert_eq!(verification1.privacy_score, verification2.privacy_score);
        
        // Cache should contain entry
        assert!(!manager.verification_cache.is_empty());
    }
}
