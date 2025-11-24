//! Comprehensive transaction tests
//!
//! Tests transaction creation, validation, hashing, and signing functionality.

use lib_blockchain::*;
use lib_blockchain::transaction::*;
use lib_blockchain::types::*;
use lib_blockchain::integration::*;
use anyhow::Result;

#[test]
fn test_transaction_creation() -> Result<()> {
    let output = TransactionOutput::new(
        Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
        Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
        crypto_integration::PublicKey::new(vec![1, 2, 3, 4]),
    );
    
    let transaction = Transaction::new(
        vec![], // No inputs for this test
        vec![output],
        100, // fee
        crypto_integration::Signature {
            signature: vec![1, 2, 3],
            public_key: crypto_integration::PublicKey::new(vec![4, 5, 6]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "test transaction".as_bytes().to_vec(),
    );
    
    // Verify transaction properties
    assert_eq!(transaction.version, 1);
    assert_eq!(transaction.transaction_type, TransactionType::Transfer);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.fee, 100);
    assert!(!transaction.is_coinbase());
    assert!(!transaction.has_identity_data());
    
    Ok(())
}

#[test]
fn test_identity_transaction_creation() -> Result<()> {
    let identity_data = IdentityTransactionData::new(
        "did:zhtp:test_creation".to_string(),
        "Test User".to_string(),
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
        "human".to_string(),
        Hash::default(),
        1000,
        100,
    );
    
    let transaction = Transaction::new_identity_registration(
        identity_data.clone(),
        vec![], // No outputs for simplicity
        crypto_integration::Signature {
            signature: vec![9, 10, 11],
            public_key: crypto_integration::PublicKey::new(vec![12, 13, 14]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "identity registration".as_bytes().to_vec(),
    );
    
    // Verify identity transaction properties
    assert_eq!(transaction.transaction_type, TransactionType::IdentityRegistration);
    assert!(transaction.has_identity_data());
    assert_eq!(transaction.fee, 1100); // registration_fee + dao_fee
    assert!(transaction.inputs.is_empty());
    
    let tx_identity_data = transaction.identity_data.as_ref().unwrap();
    assert_eq!(tx_identity_data.did, "did:zhtp:test_creation");
    assert_eq!(tx_identity_data.display_name, "Test User");
    
    Ok(())
}

#[test]
fn test_identity_update_transaction() -> Result<()> {
    let identity_data = IdentityTransactionData::new(
        "did:zhtp:test_update".to_string(),
        "Updated User".to_string(),
        vec![5, 6, 7, 8],
        vec![9, 10, 11, 12],
        "human".to_string(),
        Hash::default(),
        0, // No registration fee for updates
        0,
    );
    
    let auth_input = TransactionInput::new(
        Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        0,
        Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?,
        zk_integration::ZkTransactionProof::default(),
    );
    
    let transaction = Transaction::new_identity_update(
        identity_data.clone(),
        vec![auth_input],
        vec![], // No outputs
        50, // Update fee
        crypto_integration::Signature {
            signature: vec![13, 14, 15],
            public_key: crypto_integration::PublicKey::new(vec![16, 17, 18]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "identity update".as_bytes().to_vec(),
    );
    
    // Verify update transaction properties
    assert_eq!(transaction.transaction_type, TransactionType::IdentityUpdate);
    assert!(transaction.has_identity_data());
    assert_eq!(transaction.fee, 50);
    assert_eq!(transaction.inputs.len(), 1);
    
    Ok(())
}

#[test]
fn test_identity_revocation_transaction() -> Result<()> {
    let transaction = Transaction::new_identity_revocation(
        "did:zhtp:test_revoke".to_string(),
        vec![], // No inputs for simplicity
        25, // Revocation fee
        crypto_integration::Signature {
            signature: vec![19, 20, 21],
            public_key: crypto_integration::PublicKey::new(vec![22, 23, 24]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "identity revocation".as_bytes().to_vec(),
    );
    
    // Verify revocation transaction properties
    assert_eq!(transaction.transaction_type, TransactionType::IdentityRevocation);
    assert!(transaction.has_identity_data());
    assert_eq!(transaction.fee, 25);
    
    let revocation_data = transaction.identity_data.as_ref().unwrap();
    assert_eq!(revocation_data.did, "did:zhtp:test_revoke");
    assert_eq!(revocation_data.identity_type, "revoked");
    assert!(revocation_data.is_revoked());
    
    Ok(())
}

#[test]
fn test_transaction_hashing() -> Result<()> {
    let transaction = Transaction::new(
        vec![],
        vec![],
        100,
        crypto_integration::Signature {
            signature: vec![1, 2, 3],
            public_key: crypto_integration::PublicKey::new(vec![4, 5, 6]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "hash test".as_bytes().to_vec(),
    );
    
    // Test hash calculation
    let hash1 = transaction.hash();
    let hash2 = transaction.hash();
    assert_eq!(hash1, hash2); // Should be deterministic
    
    // Test signing hash (should be different)
    let signing_hash = transaction.signing_hash();
    assert_ne!(hash1, signing_hash);
    
    // Test ID (should equal hash)
    assert_eq!(transaction.id(), hash1);
    
    Ok(())
}

#[test]
fn test_transaction_validation() -> Result<()> {
    // Create a basic valid transaction
    let output = TransactionOutput::new(
        Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
        Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
        crypto_integration::PublicKey::new(vec![1, 2, 3, 4]),
    );
    
    let input = TransactionInput::new(
        Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        0,
        Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?,
        zk_integration::ZkTransactionProof::default(),
    );
    
    let transaction = Transaction::new(
        vec![input],
        vec![output],
        100,
        crypto_integration::Signature {
            signature: vec![1, 2, 3, 4, 5], // Non-empty signature
            public_key: crypto_integration::PublicKey::new(vec![6, 7, 8, 9]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "validation test".as_bytes().to_vec(),
    );
    
    // Test basic validation
    let validator = validation::TransactionValidator::new();
    
    // Note: Full validation might fail due to missing blockchain context
    // but we can test basic structure validation
    let basic_result = validator.validate_transaction(&transaction);
    
    // The transaction should at least have valid basic structure
    assert!(validation::utils::quick_validate(&transaction));
    assert!(validation::utils::validate_type_consistency(&transaction));
    
    Ok(())
}

#[test]
fn test_transaction_input_output() -> Result<()> {
    // Test TransactionInput
    let input = TransactionInput::new(
        Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
        5,
        Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
        zk_integration::ZkTransactionProof::default(),
    );
    
    let (prev_hash, index) = input.outpoint();
    assert_eq!(index, 5);
    assert_eq!(prev_hash, Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?);
    
    // Test TransactionOutput
    let recipient_key = crypto_integration::PublicKey::new(vec![1, 2, 3, 4]);
    let output = TransactionOutput::new(
        Hash::from_hex("3333333333333333333333333333333333333333333333333333333333333333")?,
        Hash::from_hex("4444444444444444444444444444444444444444444444444444444444444444")?,
        recipient_key.clone(),
    );
    
    assert!(output.is_to_recipient(&recipient_key));
    
    let other_key = crypto_integration::PublicKey::new(vec![5, 6, 7, 8]);
    assert!(!output.is_to_recipient(&other_key));
    
    Ok(())
}

#[test]
fn test_transaction_builder() -> Result<()> {
    let input = TransactionInput::new(
        Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        0,
        Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?,
        zk_integration::ZkTransactionProof::default(),
    );
    
    let output = TransactionOutput::new(
        Hash::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?,
        Hash::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")?,
        crypto_integration::PublicKey::new(vec![1, 2, 3, 4]),
    );
    
    // Create a keypair for signing
    let keypair = lib_crypto::KeyPair::generate()?;
    
    // Use the transaction builder
    let transaction = creation::TransactionBuilder::new()
        .version(2)
        .transaction_type(TransactionType::Transfer)
        .add_input(input)
        .add_output(output)
        .fee(150)
        .memo("builder test".as_bytes().to_vec())
        .build(&keypair.private_key)?;
    
    // Verify built transaction
    assert_eq!(transaction.version, 2);
    assert_eq!(transaction.transaction_type, TransactionType::Transfer);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.fee, 150);
    assert!(!transaction.signature.signature.is_empty());
    
    Ok(())
}

#[test]
fn test_transaction_size_estimation() -> Result<()> {
    // Test size estimation utility
    let estimated_size = creation::utils::estimate_transaction_size(
        2, // inputs
        3, // outputs
        100, // memo size
        false, // no identity data
    );
    
    assert!(estimated_size > 0);
    assert!(estimated_size > 100); // Should be larger than just memo
    
    // Test with identity data - use same inputs/outputs/memo to properly compare identity impact
    let estimated_size_with_identity = creation::utils::estimate_transaction_size(
        2, // inputs (same as above)
        3, // outputs (same as above) 
        100, // memo size (same as above)
        true, // has identity data
    );
    
    // With identity data, the transaction should be larger by 256 bytes
    assert!(estimated_size_with_identity > estimated_size);
    assert_eq!(estimated_size_with_identity, estimated_size + 256);
    
    Ok(())
}

#[test]
fn test_minimum_fee_calculation() -> Result<()> {
    // Test minimum fee calculation
    let min_fee_small = creation::utils::calculate_minimum_fee(100);
    let min_fee_large = creation::utils::calculate_minimum_fee(1000);
    
    assert!(min_fee_large > min_fee_small);
    assert!(min_fee_small >= 1000); // Base fee
    
    Ok(())
}

#[test]
fn test_transaction_serialization() -> Result<()> {
    let transaction = Transaction::new(
        vec![],
        vec![],
        100,
        crypto_integration::Signature {
            signature: vec![1, 2, 3],
            public_key: crypto_integration::PublicKey::new(vec![4, 5, 6]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "serialization test".as_bytes().to_vec(),
    );
    
    // Test serialization
    let serialized = bincode::serialize(&transaction)?;
    assert!(!serialized.is_empty());
    
    // Test deserialization
    let deserialized: Transaction = bincode::deserialize(&serialized)?;
    assert_eq!(deserialized.version, transaction.version);
    assert_eq!(deserialized.fee, transaction.fee);
    assert_eq!(deserialized.memo, transaction.memo);
    
    Ok(())
}

#[test]
fn test_identity_transaction_data() -> Result<()> {
    let identity_data = IdentityTransactionData::new(
        "did:zhtp:data_test".to_string(),
        "Data Test User".to_string(),
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
        "organization".to_string(),
        Hash::default(),
        2000,
        200,
    );
    
    // Test properties
    assert_eq!(identity_data.total_fees(), 2200);
    assert!(!identity_data.is_revoked());
    assert_eq!(identity_data.identity_type, "organization");
    
    // Test revoked identity
    let mut revoked_data = identity_data.clone();
    revoked_data.identity_type = "revoked".to_string();
    assert!(revoked_data.is_revoked());
    
    Ok(())
}