//! Blockchain Integration Traits for Economy Transactions
//! 
//! This module provides trait-based conversion utilities for transforming
//! lib-economy transactions into blockchain-compatible format.
//! 
//! Architecture Note: lib-economy is Layer 2, lib-blockchain is Layer 3.
//! Direct dependency would violate architecture, so we use traits that
//! lib-blockchain implements via the integration layer in zhtp.

use anyhow::Result;
use crate::transactions::Transaction as EconomyTransaction;
use crate::types::TransactionType as EconomyTxType;
use crate::types::TransactionTypeExt;

/// Economy transaction data needed for blockchain conversion
/// This struct provides the necessary data without importing blockchain types
#[derive(Debug, Clone)]
pub struct BlockchainTransactionData {
    pub version: u32,
    pub chain_id: u32,
    pub tx_type_name: String,
    pub inputs: Vec<u8>, // Serialized inputs (empty for system transactions)
    pub outputs: Vec<BlockchainOutput>,
    pub fee: u64,
    pub signature_data: Vec<u8>,
    pub public_key: Vec<u8>,
    pub timestamp: u64,
    pub memo: Vec<u8>,
}

/// Output data for blockchain transactions
#[derive(Debug, Clone)]
pub struct BlockchainOutput {
    pub commitment: [u8; 32],
    pub note: [u8; 32],
    pub recipient: Vec<u8>,
}

/// Convert economics transaction to blockchain-compatible data
/// 
/// This creates a data structure that lib-blockchain can convert into its Transaction type.
/// System transactions (UBI, rewards) don't spend UTXOs - they create new money from protocol rules.
/// 
/// # Arguments
/// * `economics_tx` - The economy transaction to convert
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn to_blockchain_data(
    economics_tx: &EconomyTransaction,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use lib_crypto::{sign_message, hashing::hash_blake3};
    
    // Create SYSTEM TRANSACTION with empty inputs
    // System transactions don't spend UTXOs - they create new money from protocol rules
    let inputs = Vec::new(); // Empty for system transactions

    // Create outputs for the transaction
    let outputs = vec![BlockchainOutput {
        commitment: hash_blake3(
            format!("commitment_{}", economics_tx.amount).as_bytes()
        ),
        note: hash_blake3(
            format!("note_{}", hex::encode(economics_tx.tx_id)).as_bytes()
        ),
        recipient: economics_tx.to.to_vec(),
    }];

    // Map economics transaction type to blockchain transaction type name
    let tx_type_name = match economics_tx.tx_type {
        EconomyTxType::UbiDistribution => "Transfer",
        EconomyTxType::Reward => "Transfer",
        EconomyTxType::Payment => "Transfer",
        _ => "Transfer",
    }.to_string();

    // Create signing data
    let signing_data = format!(
        "{}:{}:{}:{}:{}",
        chain_id,
        tx_type_name,
        economics_tx.amount,
        hex::encode(&economics_tx.to),
        economics_tx.timestamp
    );
    let signing_hash = hash_blake3(signing_data.as_bytes());
    
    // Sign the transaction
    let signature = sign_message(system_keypair, &signing_hash)?;

    // Create memo with transaction details
    let memo = format!(
        "System TX: {} {} SOV to {:?}", 
        economics_tx.tx_type.description(), 
        economics_tx.amount,
        economics_tx.to
    ).into_bytes();

    // Return blockchain-compatible data
    Ok(BlockchainTransactionData {
        version: 1,
        chain_id,
        tx_type_name,
        inputs, // Empty inputs = system transaction
        outputs,
        fee: 0, // System transactions are fee-free
        signature_data: signature.signature,
        public_key: system_keypair.public_key.dilithium_pk.to_vec(),
        timestamp: economics_tx.timestamp,
        memo,
    })
}

/// Create UBI distribution as blockchain-compatible data
/// 
/// # Arguments
/// * `citizen_id` - Identity of the citizen receiving UBI
/// * `amount` - Amount of SOV tokens to distribute
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn create_ubi_blockchain_data(
    citizen_id: crate::wasm::IdentityId,
    amount: u64,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use crate::transactions::creation::create_ubi_distributions;
    
    // Create UBI distributions using economics package
    let ubi_distributions = create_ubi_distributions(&[(citizen_id, amount)])?;
    
    if ubi_distributions.is_empty() {
        return Err(anyhow::anyhow!("No UBI distributions created"));
    }
    
    // Convert economics transaction to blockchain data
    let economics_tx = &ubi_distributions[0];
    to_blockchain_data(economics_tx, chain_id, system_keypair)
}

/// Create reward as blockchain-compatible data
/// 
/// # Arguments
/// * `node_id` - The 32-byte unique identifier of the node receiving the reward
/// * `reward_amount` - The amount of SOV tokens to award
/// * `chain_id` - The blockchain chain ID
/// * `system_keypair` - Keypair for signing system transactions
pub fn create_reward_blockchain_data(
    node_id: [u8; 32],
    reward_amount: u64,
    chain_id: u32,
    system_keypair: &lib_crypto::KeyPair,
) -> Result<BlockchainTransactionData> {
    use crate::transactions::creation::create_reward_transaction;
    
    // Create reward for network services (routing, storage, etc.)
    let reward_tx = create_reward_transaction(node_id, reward_amount)?;
    
    // Convert economics transaction to blockchain data
    to_blockchain_data(&reward_tx, chain_id, system_keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ubi_blockchain_data_creation() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let citizen_id = crate::wasm::IdentityId([1u8; 32]);
        
        let result = create_ubi_blockchain_data(
            citizen_id,
            1000,
            1, // chain_id
            &keypair,
        );
        
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.chain_id, 1);
        assert_eq!(data.fee, 0); // System transactions are fee-free
        assert!(data.inputs.is_empty()); // System transactions have no inputs
        assert_eq!(data.outputs.len(), 1);
        assert_eq!(data.tx_type_name, "Transfer");
    }
    
    #[test]
    fn test_reward_blockchain_data_creation() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let node_id = [2u8; 32];
        
        let result = create_reward_blockchain_data(
            node_id,
            500,
            1, // chain_id
            &keypair,
        );
        
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.chain_id, 1);
        assert_eq!(data.fee, 0);
        assert!(data.inputs.is_empty());
        assert_eq!(data.outputs.len(), 1);
    }
    
    #[test]
    fn test_blockchain_data_signatures() {
        let keypair = lib_crypto::generate_keypair().unwrap();
        let node_id = [3u8; 32];
        
        let data = create_reward_blockchain_data(
            node_id,
            250,
            1,
            &keypair,
        ).unwrap();
        
        // Signature should be present and non-empty
        assert!(!data.signature_data.is_empty());
        assert!(!data.public_key.is_empty());
        assert!(data.timestamp > 0);
        
        // Verify public key matches keypair
        assert_eq!(data.public_key, keypair.public_key.dilithium_pk);
    }
}
