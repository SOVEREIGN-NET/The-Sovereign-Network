//! Comprehensive tests for recovery systems
//! 
//! Tests recovery phrases, biometric recovery, and other recovery mechanisms.

#[cfg(test)]
mod tests {
    use super::super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_recovery_phrase_generation() {
        let mut manager = RecoveryPhraseManager::new();
        
        let options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let phrase = manager.generate_recovery_phrase("test_identity", options)
            .await.expect("Failed to generate recovery phrase");
        
        assert_eq!(phrase.words.len(), 12);
        assert_eq!(phrase.language, "english");
        assert_eq!(phrase.word_count, 12);
        assert!(!phrase.checksum.is_empty());
        assert!(!phrase.entropy.is_empty());
    }

    #[tokio::test]
    async fn test_recovery_phrase_validation() {
        let manager = RecoveryPhraseManager::new();
        
        // Test valid phrase
        let valid_phrase = RecoveryPhrase {
            words: (0..12).map(|i| format!("word{:04}", i)).collect(),
            entropy: vec![0u8; 16], // 128 bits
            checksum: "valid_checksum".to_string(),
            language: "english".to_string(),
            word_count: 12,
        };
        
        let validation = manager.validate_phrase(&valid_phrase)
            .await.expect("Failed to validate phrase");
        
        assert!(validation.valid);
        assert!(validation.word_count_valid);
        assert!(validation.entropy_sufficient);
        assert!(validation.language_supported);
        assert!(validation.strength_score > 0.0);
        
        // Test invalid phrase (too few words)
        let invalid_phrase = RecoveryPhrase {
            words: vec!["word1".to_string()],
            entropy: vec![0u8; 2], // Too little entropy
            checksum: String::new(),
            language: "unsupported".to_string(),
            word_count: 1,
        };
        
        let invalid_validation = manager.validate_phrase(&invalid_phrase)
            .await.expect("Failed to validate phrase");
        
        assert!(!invalid_validation.valid);
        assert!(!invalid_validation.word_count_valid);
        assert!(!invalid_validation.entropy_sufficient);
        assert!(!invalid_validation.language_supported);
        assert!(!invalid_validation.errors.is_empty());
    }

    #[tokio::test]
    async fn test_recovery_phrase_storage_and_retrieval() {
        let mut manager = RecoveryPhraseManager::new();
        
        // Generate phrase
        let options = PhraseGenerationOptions {
            word_count: 24,
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let phrase = manager.generate_recovery_phrase("test_user", options)
            .await.expect("Failed to generate phrase");
        
        // Store phrase
        let phrase_id = manager.store_recovery_phrase(
            "test_user",
            &phrase,
            Some("additional_password"),
        ).await.expect("Failed to store phrase");
        
        assert!(!phrase_id.is_empty());
        
        // Recover identity using phrase
        let recovered_identity = manager.recover_identity_with_phrase(
            &phrase.words,
            Some("additional_password"),
        ).await.expect("Failed to recover identity");
        
        assert_eq!(recovered_identity, "test_user");
    }

    #[tokio::test]
    async fn test_different_entropy_sources() {
        let mut manager = RecoveryPhraseManager::new();
        
        // Test system random
        let system_options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: false,
            custom_wordlist: None,
        };
        
        let system_phrase = manager.generate_recovery_phrase("user1", system_options)
            .await.expect("Failed with system random");
        
        // Test user provided entropy
        let user_entropy = vec![42u8; 32];
        let user_options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::UserProvided(user_entropy),
            include_checksum: false,
            custom_wordlist: None,
        };
        
        let user_phrase = manager.generate_recovery_phrase("user2", user_options)
            .await.expect("Failed with user entropy");
        
        // Test combined entropy
        let combined_options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::Combined(vec![
                EntropySource::SystemRandom,
                EntropySource::UserProvided(vec![123u8; 16]),
            ]),
            include_checksum: false,
            custom_wordlist: None,
        };
        
        let combined_phrase = manager.generate_recovery_phrase("user3", combined_options)
            .await.expect("Failed with combined entropy");
        
        // All should be different
        assert_ne!(system_phrase.words, user_phrase.words);
        assert_ne!(system_phrase.words, combined_phrase.words);
        assert_ne!(user_phrase.words, combined_phrase.words);
    }

    #[tokio::test]
    async fn test_multiple_language_support() {
        let mut manager = RecoveryPhraseManager::new();
        
        let languages = vec!["english", "spanish", "french"];
        
        for language in languages {
            let options = PhraseGenerationOptions {
                word_count: 12,
                language: language.to_string(),
                entropy_source: EntropySource::SystemRandom,
                include_checksum: true,
                custom_wordlist: None,
            };
            
            let phrase = manager.generate_recovery_phrase(
                &format!("user_{}", language),
                options
            ).await.expect("Failed to generate phrase");
            
            assert_eq!(phrase.language, language);
            assert_eq!(phrase.words.len(), 12);
        }
    }

    #[tokio::test]
    async fn test_phrase_strength_calculation() {
        let manager = RecoveryPhraseManager::new();
        
        // Strong phrase (24 words, good entropy, checksum)
        let strong_phrase = RecoveryPhrase {
            words: (0..24).map(|i| format!("word{:04}", i)).collect(),
            entropy: vec![0u8; 32], // 256 bits
            checksum: "checksum".to_string(),
            language: "english".to_string(),
            word_count: 24,
        };
        
        let strong_score = manager.calculate_phrase_strength(&strong_phrase);
        assert!(strong_score > 0.8);
        
        // Weak phrase (12 words, minimal entropy, no checksum)
        let weak_phrase = RecoveryPhrase {
            words: (0..12).map(|i| format!("word{:04}", i)).collect(),
            entropy: vec![0u8; 16], // 128 bits
            checksum: String::new(),
            language: "english".to_string(),
            word_count: 12,
        };
        
        let weak_score = manager.calculate_phrase_strength(&weak_phrase);
        assert!(weak_score < strong_score);
    }

    #[tokio::test]
    async fn test_recovery_with_wrong_password() {
        let mut manager = RecoveryPhraseManager::new();
        
        let options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let phrase = manager.generate_recovery_phrase("secure_user", options)
            .await.expect("Failed to generate phrase");
        
        // Store with password
        let _phrase_id = manager.store_recovery_phrase(
            "secure_user",
            &phrase,
            Some("correct_password"),
        ).await.expect("Failed to store phrase");
        
        // Try to recover with wrong password
        let recovery_result = manager.recover_identity_with_phrase(
            &phrase.words,
            Some("wrong_password"),
        ).await;
        
        assert!(recovery_result.is_err());
    }

    #[tokio::test]
    async fn test_phrase_expiration() {
        let mut manager = RecoveryPhraseManager::new();
        
        // Set short expiration for testing
        manager.security_settings.auto_expire_days = Some(0); // Expire immediately
        
        let options = PhraseGenerationOptions {
            word_count: 12,
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let phrase = manager.generate_recovery_phrase("expiring_user", options)
            .await.expect("Failed to generate phrase");
        
        let _phrase_id = manager.store_recovery_phrase(
            "expiring_user",
            &phrase,
            None,
        ).await.expect("Failed to store phrase");
        
        // Wait a moment and try to recover (should fail due to expiration)
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        let recovery_result = manager.recover_identity_with_phrase(
            &phrase.words,
            None,
        ).await;
        
        assert!(recovery_result.is_err());
    }

    #[tokio::test]
    async fn test_validation_rules_enforcement() {
        let mut manager = RecoveryPhraseManager::new();
        
        // Set strict validation rules
        manager.validation_rules.min_word_count = 20;
        manager.validation_rules.min_entropy_bits = 256;
        manager.validation_rules.banned_words = vec!["password".to_string(), "secret".to_string()];
        
        // Try to generate phrase that violates rules
        let options = PhraseGenerationOptions {
            word_count: 12, // Too few words
            language: "english".to_string(),
            entropy_source: EntropySource::SystemRandom,
            include_checksum: true,
            custom_wordlist: None,
        };
        
        let generation_result = manager.generate_recovery_phrase("strict_user", options).await;
        assert!(generation_result.is_err());
        
        // Test with banned words
        let phrase_with_banned_words = RecoveryPhrase {
            words: vec!["password".to_string(), "secret".to_string()],
            entropy: vec![0u8; 32],
            checksum: "checksum".to_string(),
            language: "english".to_string(),
            word_count: 2,
        };
        
        let validation = manager.validate_phrase(&phrase_with_banned_words)
            .await.expect("Validation should complete");
        
        assert!(!validation.valid);
        assert_eq!(validation.banned_words_found.len(), 2);
    }

    #[tokio::test]
    async fn test_concurrent_phrase_operations() {
        let mut manager = RecoveryPhraseManager::new();
        
        let mut handles = Vec::new();
        
        // Generate multiple phrases concurrently
        for i in 0..5 {
            let mut manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                let options = PhraseGenerationOptions {
                    word_count: 12,
                    language: "english".to_string(),
                    entropy_source: EntropySource::SystemRandom,
                    include_checksum: true,
                    custom_wordlist: None,
                };
                
                manager_clone.generate_recovery_phrase(&format!("user_{}", i), options).await
            });
            handles.push(handle);
        }
        
        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        
        // Verify all succeeded and are unique
        let mut phrase_sets = std::collections::HashSet::new();
        for result in results {
            let phrase = result.expect("Task failed").expect("Phrase generation failed");
            assert!(phrase_sets.insert(phrase.words)); // Should be unique
        }
        
        assert_eq!(phrase_sets.len(), 5);
    }
}
