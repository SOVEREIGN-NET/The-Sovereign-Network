//! Transaction Builder Service
//! 
//! Handles creation and signing of blockchain transactions from economic data.
//! Supports:
//! - UBI distribution transactions
//! - Reward transactions (routing, storage)
//! - System transactions (no UTXO inputs)

use anyhow::Result;
use lib_blockchain::{Transaction, TransactionOutput, TransactionInput};
use lib_blockchain::types::TransactionType as BlockchainTxType;
use lib_blockchain::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};

/// Transaction builder for creating blockchain transactions from economic data
pub struct TransactionBuilder;

impl TransactionBuilder {
    /// Create UBI distribution transaction using lib-economy
    pub async fn create_ubi_transaction(
        environment: &crate::config::Environment
    ) -> Result<Transaction> {
        use lib_economy::transactions::creation::create_ubi_distributions;
        use lib_economy::wasm::IdentityId;
        
        // Create a citizen identity for UBI distribution
        let citizen_id = IdentityId([1u8; 32]); // In production this would be a citizen
        let ubi_amount = 1000; // 1000 ZHTP tokens as UBI
        
        // Create UBI distributions using economics package
        let ubi_distributions = create_ubi_distributions(&[(citizen_id, ubi_amount)])?;
        
        if ubi_distributions.is_empty() {
            return Err(anyhow::anyhow!("No UBI distributions created"));
        }
        
        // Convert economics transaction to blockchain transaction
        let economics_tx = &ubi_distributions[0];
        Self::convert_economics_to_system_tx(economics_tx, environment).await
    }

    /// Create reward transaction using lib-economy
    /// 
    /// # Arguments
    /// * `node_id` - The 32-byte unique identifier of the node receiving the reward
    /// * `reward_amount` - The amount of ZHTP tokens to award
    /// * `environment` - The node's environment configuration
    pub async fn create_reward_transaction(
        node_id: [u8; 32],
        reward_amount: u64,
        environment: &crate::config::Environment
    ) -> Result<Transaction> {
        use lib_economy::transactions::creation::create_reward_transaction;
        
        // Create reward for network services (routing, storage, etc.)
        let reward_tx = create_reward_transaction(node_id, reward_amount)?;
        
        // Convert economics transaction to blockchain transaction
        Self::convert_economics_to_system_tx(&reward_tx, environment).await
    }

    /// Convert economics transaction to blockchain transaction format as system transaction
    async fn convert_economics_to_system_tx(
        economics_tx: &lib_economy::transactions::Transaction,
        environment: &crate::config::Environment,
    ) -> Result<Transaction> {
        // Create SYSTEM TRANSACTION with empty inputs (like UBI/rewards in original)
        // System transactions don't spend UTXOs - they create new money from protocol rules
        let inputs = vec![]; // Empty inputs for system transactions (no ZK proofs needed)

        // Create outputs for the transaction
        let outputs = vec![TransactionOutput {
            commitment: lib_blockchain::types::hash::blake3_hash(
                &format!("commitment_{}", economics_tx.amount).as_bytes()
            ),
            note: lib_blockchain::types::hash::blake3_hash(
                &format!("note_{}", hex::encode(economics_tx.tx_id)).as_bytes()
            ),
            recipient: PublicKey::new(economics_tx.to.to_vec()),
        }];

        // Map economics transaction type to blockchain transaction type
        let blockchain_tx_type = match economics_tx.tx_type {
            lib_economy::types::TransactionType::UbiDistribution => BlockchainTxType::Transfer,
            lib_economy::types::TransactionType::Reward => BlockchainTxType::Transfer,
            lib_economy::types::TransactionType::Payment => BlockchainTxType::Transfer,
            _ => BlockchainTxType::Transfer,
        };

        // Create properly signed transaction using system keypair
        let signature = Self::create_system_signature(
            economics_tx, 
            &inputs, 
            &outputs, 
            blockchain_tx_type.clone(), 
            environment
        ).await?;

        // Create memo with transaction details
        let memo = format!(
            "System TX: {} {} ZHTP to {:?}", 
            economics_tx.tx_type.description(), 
            economics_tx.amount,
            economics_tx.to
        ).into_bytes();

        // Create the blockchain transaction as SYSTEM TRANSACTION (no inputs, no ZK proofs needed)
        Ok(Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: blockchain_tx_type,
            inputs, // Empty inputs = system transaction (creates new money like mining)
            outputs,
            fee: 0, // System transactions are fee-free
            signature,
            wallet_data: None,
            memo,
            identity_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        })
    }

    /// Create a proper cryptographic signature for system transactions
    async fn create_system_signature(
        economics_tx: &lib_economy::transactions::Transaction,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        tx_type: BlockchainTxType,
        environment: &crate::config::Environment,
    ) -> Result<Signature> {
        use lib_crypto::{generate_keypair, sign_message};
        
        // Generate a system keypair (in production, this would be a well-known system keypair)
        let system_keypair = generate_keypair()?;
        
        // Create the transaction for signing (without signature)
        let temp_signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(system_keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economics_tx.timestamp,
        };
        
        let temp_transaction = Transaction {
            version: 1,
            chain_id: environment.chain_id(),
            transaction_type: tx_type,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            fee: economics_tx.total_fee,
            signature: temp_signature,
            memo: format!(
                "System TX: {} {} ZHTP from {:?} to {:?}", 
                economics_tx.tx_type.description(), 
                economics_tx.amount,
                economics_tx.from,
                economics_tx.to
            ).into_bytes(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };

        // Create signing hash using the exact same method as blockchain validation
        let signing_hash = lib_blockchain::transaction::hashing::hash_for_signature(&temp_transaction);
        
        // Sign the transaction hash
        let crypto_signature = sign_message(&system_keypair, signing_hash.as_bytes())?;
        
        // Create blockchain signature structure
        Ok(Signature {
            signature: crypto_signature.signature,
            public_key: PublicKey::new(system_keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economics_tx.timestamp,
        })
    }
}
