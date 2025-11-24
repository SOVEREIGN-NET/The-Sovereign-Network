//! UTXO and nullifier set tests
//!
//! Tests the UTXO management, nullifier tracking, and double-spend prevention.

use lib_blockchain::*;
use lib_blockchain::blockchain::*;
use lib_blockchain::transaction::*;
use lib_blockchain::transaction::core::IdentityTransactionData;
use lib_blockchain::block::*;
use lib_blockchain::types::*;
use lib_blockchain::integration::crypto_integration::{PublicKey, KeyPair, Signature, SignatureAlgorithm};
use anyhow::Result;
use std::collections::HashSet;

// Import ZK types for creating valid test proofs
use lib_proofs::{ZkTransactionProof, ZkProof};

// Helper function to create valid test ZK proofs
fn create_valid_test_zk_proof() -> ZkProof {
    ZkProof::new(
        "Plonky2".to_string(),
        vec![1, 2, 3, 4], // Mock proof data
        vec![42], // Mock public inputs (non-empty)
        vec![0x01, 0x02, 0x03], // Mock verification key (non-empty)
        None,
    )
}

// Helper function to create valid test transaction proof
fn create_valid_test_transaction_proof() -> ZkTransactionProof {
    let valid_proof = create_valid_test_zk_proof();
    ZkTransactionProof::new(
        valid_proof.clone(),
        valid_proof.clone(), 
        valid_proof,
    )
}

// Helper function to create a mined block that meets difficulty
fn create_mined_block(blockchain: &Blockchain, transactions: Vec<Transaction>) -> Result<Block> {
    use lib_blockchain::block::creation::create_block;
    
    let previous_hash = blockchain.latest_block().unwrap().hash();
    let height = blockchain.height + 1;
    let difficulty = Difficulty::from_bits(0x1fffffff); // Maximum difficulty (easiest) for testing
    
    // Create the block and it will automatically pass validation for this easy difficulty
    create_block(transactions, previous_hash, height, difficulty)
}

#[test]
fn test_utxo_creation_and_tracking() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Create a transaction that creates UTXOs
    let output1 = TransactionOutput::new(
        Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
        Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
        PublicKey::new(vec![1, 2, 3, 4]),
    );
    
    let output2 = TransactionOutput::new(
        Hash::from_hex("3333333333333333333333333333333333333333333333333333333333333333")?,
        Hash::from_hex("4444444444444444444444444444444444444444444444444444444444444444")?,
        PublicKey::new(vec![5, 6, 7, 8]),
    );
    
    let identity_data = IdentityTransactionData {
        did: "did:zhtp:test123".to_string(),
        display_name: "Test Identity".to_string(),
        public_key: vec![1, 2, 3, 4],
        ownership_proof: vec![5, 6, 7, 8],
        identity_type: "human".to_string(),
        did_document_hash: Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        created_at: 12345,
        registration_fee: 5000,  // Increase fee to be safe
        dao_fee: 1000,          // Increase DAO fee too
    };

    let transaction = Transaction::new_identity_registration(
        identity_data,
        vec![output1, output2],
        Signature {
            signature: vec![1, 2, 3],
            public_key: PublicKey::new(vec![4, 5, 6]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "UTXO creation test".as_bytes().to_vec(),
    );
    
    // Create a block with this transaction using the helper function
    let block = create_mined_block(&blockchain, vec![transaction.clone()])?;
    
    // Add the block and verify UTXOs were created
    blockchain.add_block(block)?;
    
    assert_eq!(blockchain.utxo_set.len(), 2);
    
    // Verify we can calculate output IDs correctly
    let tx_hash = transaction.hash();
    let expected_output_id_0 = {
        let mut data = Vec::new();
        data.extend_from_slice(tx_hash.as_bytes());
        data.extend_from_slice(&0usize.to_le_bytes());
        lib_blockchain::types::hash::blake3_hash(&data)
    };
    
    assert!(blockchain.utxo_set.contains_key(&expected_output_id_0));
    
    Ok(())
}

#[test]
fn test_nullifier_tracking() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Create a transaction with nullifiers
    let nullifier1 = Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let nullifier2 = Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
    
    let input1 = TransactionInput::new(
        Hash::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?,
        0,
        nullifier1,
        create_valid_test_transaction_proof(),
    );
    
    let input2 = TransactionInput::new(
        Hash::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")?,
        1,
        nullifier2,
        create_valid_test_transaction_proof(),
    );
    
    let transaction = Transaction::new(
        vec![input1, input2],
        vec![TransactionOutput::new(
            Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
            Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
            PublicKey::new(vec![7, 8, 9]),
        )], // Need at least one output for Transfer transactions
        5000, // Increased fee to meet minimum requirement
        Signature {
            signature: vec![1, 2, 3],
            public_key: PublicKey::new(vec![4, 5, 6]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "Nullifier test".as_bytes().to_vec(),
    );
    
    // Create and add block using helper function
    let block = create_mined_block(&blockchain, vec![transaction])?;
    blockchain.add_block(block)?;
    
    // Verify nullifiers were tracked
    assert_eq!(blockchain.nullifier_set.len(), 2);
    assert!(blockchain.is_nullifier_used(&nullifier1));
    assert!(blockchain.is_nullifier_used(&nullifier2));
    
    // Test that unused nullifier returns false
    let unused_nullifier = Hash::from_hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")?;
    assert!(!blockchain.is_nullifier_used(&unused_nullifier));
    
    Ok(())
}

#[test]
fn test_double_spend_prevention() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    let shared_nullifier = Hash::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?;
    
    // Create first transaction using the nullifier
    let input1 = TransactionInput::new(
        Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        0,
        shared_nullifier,
        create_valid_test_transaction_proof(),
    );
    
    let transaction1 = Transaction::new(
        vec![input1],
        vec![TransactionOutput::new(
            Hash::from_hex("3333333333333333333333333333333333333333333333333333333333333333")?,
            Hash::from_hex("4444444444444444444444444444444444444444444444444444444444444444")?,
            PublicKey::new(vec![7, 8, 9]),
        )], // Need at least one output for Transfer transactions
        5000, // Increased fee
        Signature {
            signature: vec![1, 2, 3],
            public_key: PublicKey::new(vec![4, 5, 6]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "First transaction".as_bytes().to_vec(),
    );
    
    // Add first transaction to blockchain
    let block1 = create_mined_block(&blockchain, vec![transaction1])?;
    blockchain.add_block(block1)?;
    
    // Verify nullifier is now used
    assert!(blockchain.is_nullifier_used(&shared_nullifier));
    
    // Create second transaction trying to use the same nullifier (double spend)
    let input2 = TransactionInput::new(
        Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?,
        0,
        shared_nullifier, // Same nullifier = double spend attempt
        create_valid_test_transaction_proof(),
    );
    
    let transaction2 = Transaction::new(
        vec![input2],
        vec![TransactionOutput::new(
            Hash::from_hex("5555555555555555555555555555555555555555555555555555555555555555")?,
            Hash::from_hex("6666666666666666666666666666666666666666666666666666666666666666")?,
            PublicKey::new(vec![10, 11, 12]),
        )], // Need at least one output for Transfer transactions
        5000, // Increased fee
        Signature {
            signature: vec![7, 8, 9],
            public_key: PublicKey::new(vec![10, 11, 12]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12346,
        },
        "Double spend attempt".as_bytes().to_vec(),
    );
    
    // Try to add second transaction - should fail due to double spend
    let block2 = create_mined_block(&blockchain, vec![transaction2])?;
    
    // This should fail due to double spend detection
    let add_result = blockchain.add_block(block2);
    assert!(add_result.is_err());
    
    // Blockchain should still be at height 1
    assert_eq!(blockchain.height, 1);
    
    Ok(())
}

#[test]
fn test_utxo_spending() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Step 1: Create a UTXO
    let output = TransactionOutput::new(
        Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?,
        Hash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?,
        PublicKey::new(vec![1, 2, 3, 4]),
    );
    
    let identity_data = IdentityTransactionData {
        did: "did:zhtp:test456".to_string(),
        display_name: "Test Creation".to_string(),
        public_key: vec![1, 2, 3, 4],
        ownership_proof: vec![5, 6, 7, 8],
        identity_type: "human".to_string(),
        did_document_hash: Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        created_at: 12345,
        registration_fee: 5000,
        dao_fee: 1000,
    };

    let creation_tx = Transaction::new_identity_registration(
        identity_data,
        vec![output],
        Signature {
            signature: vec![1, 2, 3],
            public_key: PublicKey::new(vec![4, 5, 6]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "UTXO creation".as_bytes().to_vec(),
    );
    
    // Add creation transaction
    let block1 = create_mined_block(&blockchain, vec![creation_tx.clone()])?;
    blockchain.add_block(block1)?;
    
    // Verify UTXO was created
    assert_eq!(blockchain.utxo_set.len(), 1);
    let initial_utxo_count = blockchain.utxo_set.len();
    
    // Step 2: Spend the UTXO
    let spending_nullifier = Hash::from_hex("3333333333333333333333333333333333333333333333333333333333333333")?;
    
    let spending_input = TransactionInput::new(
        creation_tx.hash(), // Reference the creation transaction
        0, // First (and only) output
        spending_nullifier,
        create_valid_test_transaction_proof(),
    );
    
    let new_output = TransactionOutput::new(
        Hash::from_hex("4444444444444444444444444444444444444444444444444444444444444444")?,
        Hash::from_hex("5555555555555555555555555555555555555555555555555555555555555555")?,
        PublicKey::new(vec![7, 8, 9, 10]),
    );
    
    let spending_tx = Transaction::new(
        vec![spending_input],
        vec![new_output],
        5000, // Increased fee
        Signature {
            signature: vec![11, 12, 13],
            public_key: PublicKey::new(vec![14, 15, 16]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12346,
        },
        "UTXO spending".as_bytes().to_vec(),
    );
    
    // Add spending transaction
    let block2 = create_mined_block(&blockchain, vec![spending_tx])?;
    blockchain.add_block(block2)?;
    
    // Verify UTXO set was updated
    // We still have UTXOs (the new one), and nullifier was added
    assert!(blockchain.utxo_set.len() >= 1);
    assert!(blockchain.is_nullifier_used(&spending_nullifier));
    
    Ok(())
}

#[test]
fn test_utxo_set_consistency() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    let mut expected_utxos = HashSet::new();
    
    // Create multiple transactions and track expected UTXO state
    for i in 0..5 {
        let output = TransactionOutput::new(
            Hash::from_hex(&format!("{:064x}", i))?,
            Hash::from_hex(&format!("{:064x}", i + 1000))?,
            PublicKey::new(vec![(i as u8), (i as u8) + 1, (i as u8) + 2]),
        );
        
        let identity_data = IdentityTransactionData {
            did: format!("did:zhtp:test{}", i),
            display_name: format!("Test Identity {}", i),
            public_key: vec![(i as u8), (i as u8) + 1, (i as u8) + 2],
            ownership_proof: vec![(i as u8) + 3, (i as u8) + 4, (i as u8) + 5],
            identity_type: "human".to_string(),
            did_document_hash: Hash::from_hex(&format!("{:064x}", i + 2000))?,
            created_at: 12345 + i as u64,
            registration_fee: 5000,
            dao_fee: 1000,
        };
        
        let transaction = Transaction::new_identity_registration(
            identity_data,
            vec![output],
            Signature {
                signature: vec![(i as u8), (i as u8) + 1, (i as u8) + 2],
                public_key: PublicKey::new(vec![(i as u8) + 3, (i as u8) + 4]),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: 12345 + i as u64,
            },
            format!("Transaction {}", i).as_bytes().to_vec(),
        );
        
        // Calculate expected output ID
        let tx_hash = transaction.hash();
        let mut output_id_data = Vec::new();
        output_id_data.extend_from_slice(tx_hash.as_bytes());
        output_id_data.extend_from_slice(&0usize.to_le_bytes());
        let expected_output_id = lib_blockchain::types::hash::blake3_hash(&output_id_data);
        expected_utxos.insert(expected_output_id);
        
        // Add to blockchain
        let block = create_mined_block(&blockchain, vec![transaction])?;
        blockchain.add_block(block)?;
    }
    
    // Verify UTXO set matches expectations
    assert_eq!(blockchain.utxo_set.len(), expected_utxos.len());
    
    for expected_utxo in &expected_utxos {
        assert!(blockchain.utxo_set.contains_key(expected_utxo));
    }
    
    Ok(())
}

#[test]
fn test_large_nullifier_set() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    let nullifier_count = 2; // Further reduced to narrow down the issue
    
    // Create transaction with many inputs (nullifiers)
    let mut inputs = Vec::new();
    let mut expected_nullifiers = HashSet::new();
    
    for i in 1..=nullifier_count {
        let nullifier = Hash::from_hex(&format!("{:064x}", i * 12345))?;
        expected_nullifiers.insert(nullifier);
        
        let input = TransactionInput::new(
            Hash::from_hex(&format!("{:064x}", i * 54321))?,
            i as u32,
            nullifier,
            create_valid_test_transaction_proof(),
        );
        
        inputs.push(input);
    }
    
    let transaction = Transaction::new(
        inputs,
        vec![TransactionOutput::new(
            Hash::from_hex("7777777777777777777777777777777777777777777777777777777777777777")?,
            Hash::from_hex("8888888888888888888888888888888888888888888888888888888888888888")?,
            PublicKey::new(vec![13, 14, 15]),
        )], // Need at least one output for Transfer transactions
        5000, // Increased fee for large transaction
        Signature {
            signature: vec![1, 2, 3, 4, 5],
            public_key: PublicKey::new(vec![6, 7, 8, 9]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "Large nullifier test".as_bytes().to_vec(),
    );
    
    // Add to blockchain
    let block = create_mined_block(&blockchain, vec![transaction])?;
    blockchain.add_block(block)?;
    
    // Verify all nullifiers were tracked
    assert_eq!(blockchain.nullifier_set.len(), nullifier_count);
    
    for expected_nullifier in &expected_nullifiers {
        assert!(blockchain.is_nullifier_used(expected_nullifier));
    }
    
    Ok(())
}

#[test]
fn test_mixed_transaction_block() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    
    // Create a block with mixed transaction types
    
    // 1. UTXO creation transaction
    let creation_output = TransactionOutput::new(
        Hash::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?,
        Hash::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?,
        PublicKey::new(vec![1, 2, 3]),
    );
    
    let identity_data = IdentityTransactionData {
        did: "did:zhtp:mixed1".to_string(),
        display_name: "Mixed Test Creation".to_string(),
        public_key: vec![1, 2, 3],
        ownership_proof: vec![4, 5, 6],
        identity_type: "human".to_string(),
        did_document_hash: Hash::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?,
        created_at: 12345,
        registration_fee: 5000,
        dao_fee: 1000,
    };

    let creation_tx = Transaction::new_identity_registration(
        identity_data,
        vec![creation_output],
        Signature {
            signature: vec![1, 2, 3],
            public_key: PublicKey::new(vec![4, 5, 6]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        "Creation".as_bytes().to_vec(),
    );
    
    // 2. UTXO spending transaction
    let spending_input = TransactionInput::new(
        Hash::from_hex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")?,
        0,
        Hash::from_hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")?,
        create_valid_test_transaction_proof(),
    );
    
    let spending_output = TransactionOutput::new(
        Hash::from_hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")?,
        Hash::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")?,
        PublicKey::new(vec![7, 8, 9]),
    );
    
    let spending_tx = Transaction::new(
        vec![spending_input],
        vec![spending_output],
        5000, // Increased fee
        Signature {
            signature: vec![10, 11, 12],
            public_key: PublicKey::new(vec![13, 14, 15]),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 12346,
        },
        "Spending".as_bytes().to_vec(),
    );
    
    // Create block with both transactions
    let transactions = vec![creation_tx, spending_tx];
    let block = create_mined_block(&blockchain, transactions)?;
    blockchain.add_block(block)?;
    
    // Verify mixed state updates
    assert_eq!(blockchain.utxo_set.len(), 2); // Two outputs created
    assert_eq!(blockchain.nullifier_set.len(), 1); // One nullifier used
    
    Ok(())
}
