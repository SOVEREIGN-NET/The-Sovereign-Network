//! Integration tests for ZHTP Identity Management System
//! 
//! These tests verify the complete functionality of the modularized identity system,
//! including citizen onboarding, credential verification, and zero-knowledge proofs.

use lib_identity::*;
use lib_identity::credentials::creation::CredentialFactory;
use lib_identity::identity::activity_tracking::{ActivityTracker, ActivityType};
use lib_crypto::Hash;
use std::collections::HashMap;

#[tokio::test]
async fn test_complete_citizen_onboarding_flow() {
    println!(" Testing complete citizen onboarding flow...");
    
    // Initialize identity system
    let mut manager = initialize_identity_system().await.expect("Failed to initialize identity system");
    
    // Mock economic model
    let mut economic_model = create_mock_economic_model();
    
    // Create a new citizen identity with complete onboarding
    let citizenship_result = manager.create_citizen_identity(
        vec!["test recovery phrase".to_string()],
        &mut economic_model,
    ).await.expect("Failed to create citizen identity");
    
    // Verify citizenship result
    assert!(!citizenship_result.identity_id.0.is_empty());
    assert!(!citizenship_result.primary_wallet_id.0.is_empty());
    assert!(!citizenship_result.ubi_wallet_id.0.is_empty());
    assert!(!citizenship_result.savings_wallet_id.0.is_empty());
    
    // Verify DAO registration
    assert_eq!(citizenship_result.dao_registration.voting_power, 1);
    assert!(citizenship_result.dao_registration.voting_eligibility);
    assert!(citizenship_result.dao_registration.proposal_eligibility);
    
    // Verify UBI registration
    assert_eq!(citizenship_result.ubi_registration.monthly_amount, 1000);
    assert!(citizenship_result.ubi_registration.daily_amount > 0);
    
    // Verify Web4 access
    assert_eq!(citizenship_result.web4_access.access_level, AccessLevel::FullCitizen);
    assert!(citizenship_result.web4_access.service_tokens.len() >= 10);
    assert!(citizenship_result.web4_access.service_tokens.contains_key("zhtp.browse"));
    assert!(citizenship_result.web4_access.service_tokens.contains_key("zhtp.wallet"));
    assert!(citizenship_result.web4_access.service_tokens.contains_key("zhtp.voting"));
    
    // Verify welcome bonus
    assert_eq!(citizenship_result.welcome_bonus.bonus_amount, 5000);
    
    println!("Complete citizen onboarding test passed!");
}

#[tokio::test]
async fn test_credential_management_lifecycle() {
    println!(" Testing credential management lifecycle...");
    
    // Create credential factory
    let factory_id = Hash([1u8; 32]);
    let mut factory = CredentialFactory::new(factory_id.clone());
    
    // Create test identities
    let issuer_id = Hash([2u8; 32]);
    let subject_id = Hash([3u8; 32]);
    
    // Add trusted issuer
    factory.add_trusted_issuer(
        issuer_id.clone(),
        vec![
            CredentialType::AgeVerification,
            CredentialType::Reputation,
            CredentialType::Education,
            CredentialType::Professional,
        ]
    );
    
    // Test age verification credential
    let age_result = factory.create_age_verification_credential(
        subject_id.clone(),
        25,
        None,
        issuer_id.clone(),
    ).await.expect("Failed to create age credential");
    
    assert!(age_result.success);
    assert_eq!(age_result.credential.credential_type, CredentialType::AgeVerification);
    assert!(age_result.credential.expires_at.is_some());
    
    // Test reputation credential
    let reputation_result = factory.create_reputation_credential(
        subject_id.clone(),
        850,
        issuer_id.clone(),
    ).await.expect("Failed to create reputation credential");
    
    assert!(reputation_result.success);
    assert_eq!(reputation_result.credential.credential_type, CredentialType::Reputation);
    
    // Test custom credential
    let custom_result = factory.create_zk_credential(
        subject_id.clone(),
        CredentialType::Education,
        "Computer Science Degree".to_string(),
        Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + (5 * 365 * 24 * 3600)), // 5 years
        issuer_id.clone(),
    ).await.expect("Failed to create custom credential");
    
    assert!(custom_result.success);
    assert_eq!(custom_result.credential.credential_type, CredentialType::Education);
    
    // Verify factory statistics
    let stats = factory.get_stats();
    assert_eq!(stats.total_created, 3);
    assert_eq!(stats.by_type.get(&CredentialType::AgeVerification), Some(&1));
    assert_eq!(stats.by_type.get(&CredentialType::Reputation), Some(&1));
    assert_eq!(stats.by_type.get(&CredentialType::Education), Some(&1));
    
    println!("Credential management lifecycle test passed!");
}

#[tokio::test]
async fn test_identity_verification_system() {
    println!(" Testing identity verification system...");
    
    use verification::*;
    
    // Create identity verifier
    let mut verifier = IdentityVerifier::new();
    verifier.initialize().await.expect("Failed to initialize verifier");
    
    // Create test identity
    let identity = create_test_identity().await;
    
    // Test basic verification
    let basic_verification = verifier.verify_identity_complete(
        &identity,
        VerificationLevel::BasicExistence,
        None,
    ).await.expect("Failed to perform basic verification");
    
    assert!(basic_verification.verified);
    assert!(basic_verification.trust_score > 0.0);
    assert!(!basic_verification.verification_methods.is_empty());
    
    // Test privacy-preserving verification
    let privacy_verification = verifier.verify_identity_complete(
        &identity,
        VerificationLevel::PrivacyPreserving,
        None,
    ).await.expect("Failed to perform privacy verification");
    
    assert!(privacy_verification.verified);
    assert!(privacy_verification.verification_methods.contains(&"zero_knowledge".to_string()));
    
    // Test complete verification
    let complete_verification = verifier.verify_identity_complete(
        &identity,
        VerificationLevel::Complete,
        None,
    ).await.expect("Failed to perform complete verification");
    
    assert!(complete_verification.verified);
    assert!(complete_verification.trust_score >= 0.8);
    assert!(complete_verification.verification_methods.len() >= 3);
    
    // Verify cache functionality
    let (cache_size, cache_ops, hit_rate) = verifier.get_cache_stats();
    assert!(cache_ops > 0);
    
    println!("Identity verification system test passed!");
}

#[tokio::test]
async fn test_recovery_system() {
    println!(" Testing recovery system...");
    
    use recovery::*;
    
    // Create recovery phrase manager
    let mut phrase_manager = RecoveryPhraseManager::new();
    
    // Generate recovery phrase
    let generation_options = PhraseGenerationOptions {
        word_count: 15, // Use 15 words for higher strength score
        language: "english".to_string(),
        entropy_source: EntropySource::SystemRandom,
        include_checksum: true,
        custom_wordlist: None,
    };
    
    let recovery_phrase = phrase_manager.generate_recovery_phrase(
        "test_identity_123",
        generation_options,
    ).await.expect("Failed to generate recovery phrase");
    
    assert_eq!(recovery_phrase.words.len(), 15);
    assert_eq!(recovery_phrase.language, "english");
    assert!(!recovery_phrase.checksum.is_empty());
    assert!(!recovery_phrase.entropy.is_empty());
    
    // Store recovery phrase
    let phrase_id = phrase_manager.store_recovery_phrase(
        "test_identity_123",
        &recovery_phrase,
        Some("additional_auth_123"),
    ).await.expect("Failed to store recovery phrase");
    
    assert!(!phrase_id.is_empty());
    
    // Test recovery
    let recovered_identity = phrase_manager.recover_identity_with_phrase(
        &recovery_phrase.words,
        Some("additional_auth_123"),
    ).await.expect("Failed to recover identity");
    
    assert_eq!(recovered_identity, "test_identity_123");
    
    // Test phrase validation
    let validation_result = phrase_manager.validate_phrase(&recovery_phrase)
        .await.expect("Failed to validate phrase");
    
    println!("DEBUG: validation_result = {:?}", validation_result);
    assert!(validation_result.valid);
    assert!(validation_result.word_count_valid);
    assert!(validation_result.checksum_valid);
    assert!(validation_result.entropy_sufficient);
    assert!(validation_result.strength_score > 0.7);
    
    println!("Recovery system test passed!");
}

#[tokio::test]
async fn test_wallet_integration() {
    println!(" Testing wallet integration...");
    
    use wallets::*;
    
    // Create wallet manager
    let owner_id = Hash([42u8; 32]);
    let mut wallet_manager = WalletManager::new(owner_id.clone());
    
    // Create different types of wallets
    let primary_wallet = wallet_manager.create_wallet(
        WalletType::Primary,
        "Primary Wallet".to_string(),
        Some("primary".to_string()),
    ).expect("Failed to create primary wallet");
    
    let ubi_wallet = wallet_manager.create_wallet(
        WalletType::UBI,
        "UBI Wallet".to_string(),
        Some("ubi".to_string()),
    ).expect("Failed to create UBI wallet");
    
    let savings_wallet = wallet_manager.create_wallet(
        WalletType::Savings,
        "Savings Wallet".to_string(),
        Some("savings".to_string()),
    ).expect("Failed to create savings wallet");
    
    // Test wallet retrieval
    assert!(wallet_manager.get_wallet(&primary_wallet).is_some());
    assert!(wallet_manager.get_wallet_by_alias("primary").is_some());
    assert!(wallet_manager.get_wallet_by_alias("ubi").is_some());
    assert!(wallet_manager.get_wallet_by_alias("savings").is_some());
    
    // Test wallet listing
    let wallet_summaries = wallet_manager.list_wallets();
    assert_eq!(wallet_summaries.len(), 3);
    
    // Test wallet counts
    assert_eq!(wallet_manager.wallet_count(), 3);
    assert_eq!(wallet_manager.active_wallet_count(), 3);
    
    // Test wallets by type
    let primary_wallets = wallet_manager.get_wallets_by_type(&WalletType::Primary);
    assert_eq!(primary_wallets.len(), 1);
    
    let ubi_wallets = wallet_manager.get_wallets_by_type(&WalletType::UBI);
    assert_eq!(ubi_wallets.len(), 1);
    
    println!("Wallet integration test passed!");
}

#[tokio::test]
async fn test_activity_tracking() {
    println!(" Testing activity tracking...");
    
    // Create activity tracker
    let mut tracker = ActivityTracker::new();
    let identity_id = Hash([123u8; 32]);
    
    // Record various activities
    tracker.record_activity(&identity_id, ActivityType::IdentityCreation);
    tracker.record_activity(&identity_id, ActivityType::WalletCreated);
    tracker.record_activity(&identity_id, ActivityType::CredentialAdded);
    tracker.record_activity(&identity_id, ActivityType::TransactionSigned);
    
    // Verify activity record
    let record = tracker.get_activity_record(&identity_id).expect("Activity record not found");
    assert_eq!(record.activity_count, 4);
    assert_eq!(record.activity_types.len(), 4);
    assert!(record.activity_types.contains(&ActivityType::IdentityCreation));
    assert!(record.activity_types.contains(&ActivityType::WalletCreated));
    
    // Test session tracking
    let session_id = tracker.start_session(&identity_id);
    assert!(!session_id.is_empty());
    
    tracker.add_activity_to_session(&identity_id, &session_id, ActivityType::VerificationRequested);
    tracker.end_session(&identity_id, &session_id);
    
    let updated_record = tracker.get_activity_record(&identity_id).unwrap();
    assert_eq!(updated_record.sessions.len(), 1);
    assert!(updated_record.sessions[0].end_time.is_some());
    
    // Verify global statistics
    let stats = tracker.get_global_stats();
    assert_eq!(stats.total_activities, 4);
    assert!(stats.most_active_identity.is_some());
    assert_eq!(stats.most_active_identity.as_ref().unwrap(), &identity_id);
    
    println!("Activity tracking test passed!");
}

#[tokio::test]
async fn test_citizenship_system_integration() {
    println!(" Testing citizenship system integration...");
    
    // Test the complete citizenship flow
    let mut manager = initialize_identity_system().await.unwrap();
    let mut economic_model = create_mock_economic_model();
    
    // Create multiple citizens
    let mut citizen_results = Vec::new();
    
    for i in 0..3 {
        let result = manager.onboard_new_citizen(
            format!("Citizen {}", i + 1),
            vec![format!("recovery phrase for citizen {}", i + 1)],
            &mut economic_model,
        ).await.expect("Failed to onboard citizen");
        
        citizen_results.push(result);
    }
    
    // Verify all citizens were created
    assert_eq!(citizen_results.len(), 3);
    
    // Verify each citizen has unique identity
    let mut identity_ids = std::collections::HashSet::new();
    for result in &citizen_results {
        assert!(identity_ids.insert(result.identity_id.clone()));
    }
    
    // Verify all citizens have proper access levels
    for result in &citizen_results {
        assert_eq!(result.web4_access.access_level, AccessLevel::FullCitizen);
        assert!(result.web4_access.restrictions.is_empty());
        assert_eq!(result.dao_registration.voting_power, 1);
        assert_eq!(result.ubi_registration.monthly_amount, 1000);
        assert_eq!(result.welcome_bonus.bonus_amount, 5000);
    }
    
    println!("Citizenship system integration test passed!");
}

// Helper functions for tests

async fn create_test_identity() -> identity::ZhtpIdentity {
    use lib_proofs::ZeroKnowledgeProof;
    
    let public_key = vec![42u8; 32];
    let ownership_proof = ZeroKnowledgeProof {
        proof_system: "Test".to_string(),
        proof_data: vec![1, 2, 3, 4],
        public_inputs: vec![5, 6, 7, 8],
        verification_key: vec![9, 10, 11, 12],
        plonky2_proof: None,
        proof: vec![],
    };
    
    identity::ZhtpIdentity::new(
        IdentityType::Human,
        public_key,
        ownership_proof,
    ).expect("Failed to create test identity")
}

fn create_mock_economic_model() -> economics::EconomicModel {
    economics::EconomicModel::new()
}

#[tokio::test]
async fn test_error_handling_and_edge_cases() {
    println!(" Testing error handling and edge cases...");
    
    // Test invalid credential creation
    let factory_id = Hash([1u8; 32]);
    let mut factory = CredentialFactory::new(factory_id);
    let subject_id = Hash([2u8; 32]);
    let untrusted_issuer = Hash([99u8; 32]);
    
    // Try to create credential with untrusted issuer
    let result = factory.create_age_verification_credential(
        subject_id,
        18,
        None,
        untrusted_issuer,
    ).await.expect("Should return result even for failed creation");
    
    assert!(!result.success);
    assert!(!result.messages.is_empty());
    
    // Test recovery phrase validation with invalid input
    let mut phrase_manager = recovery::RecoveryPhraseManager::new();
    
    let invalid_phrase = recovery::RecoveryPhrase {
        words: vec!["invalid".to_string()], // Too few words
        entropy: vec![1, 2, 3], // Insufficient entropy
        checksum: String::new(),
        language: "unsupported".to_string(),
        word_count: 1,
    };
    
    let validation_result = phrase_manager.validate_phrase(&invalid_phrase)
        .await.expect("Validation should complete");
    
    assert!(!validation_result.valid);
    assert!(!validation_result.word_count_valid);
    assert!(!validation_result.entropy_sufficient);
    assert!(!validation_result.language_supported);
    assert!(!validation_result.errors.is_empty());
    
    println!("Error handling and edge cases test passed!");
}

#[tokio::test]
async fn test_performance_benchmarks() {
    println!(" Testing performance benchmarks...");
    
    let start_time = std::time::Instant::now();
    
    // Benchmark credential creation
    let factory_id = Hash([1u8; 32]);
    let mut factory = CredentialFactory::new(factory_id.clone());
    let issuer_id = Hash([2u8; 32]);
    
    factory.add_trusted_issuer(
        issuer_id.clone(),
        vec![CredentialType::AgeVerification, CredentialType::Reputation]
    );
    
    // Create multiple credentials and measure time
    let credential_start = std::time::Instant::now();
    
    for i in 0..10 {
        let subject_id = Hash([i as u8; 32]);
        let _result = factory.create_age_verification_credential(
            subject_id,
            18 + i,
            None,
            issuer_id.clone(),
        ).await.expect("Failed to create credential");
    }
    
    let credential_duration = credential_start.elapsed();
    println!("Created 10 credentials in {:?}", credential_duration);
    
    // Benchmark verification
    let mut verifier = verification::IdentityVerifier::new();
    let identity = create_test_identity().await;
    
    let verification_start = std::time::Instant::now();
    
    for _ in 0..5 {
        let _result = verifier.verify_identity_complete(
            &identity,
            verification::VerificationLevel::BasicExistence,
            None,
        ).await.expect("Failed to verify identity");
    }
    
    let verification_duration = verification_start.elapsed();
    println!("Performed 5 verifications in {:?}", verification_duration);
    
    let total_duration = start_time.elapsed();
    println!("Total benchmark time: {:?}", total_duration);
    
    // Assert reasonable performance
    assert!(credential_duration.as_millis() < 1000, "Credential creation too slow");
    assert!(verification_duration.as_millis() < 500, "Verification too slow");
    
    println!("Performance benchmarks test passed!");
}