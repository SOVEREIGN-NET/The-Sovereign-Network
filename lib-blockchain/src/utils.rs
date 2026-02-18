//! Utility functions for the ZHTP blockchain
//! 
//! Common utilities used throughout the blockchain package.

use crate::types::{Hash, Difficulty};
use crate::transaction::Transaction;
use crate::block::Block;

/// Time utilities
pub mod time {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counter tracking active consensus validation scopes.
    /// When non-zero, nondeterministic operations will panic.
    static CONSENSUS_VALIDATION_ACTIVE: AtomicUsize = AtomicUsize::new(0);

    /// Mark that consensus validation is active
    /// This should be called when entering consensus-critical paths
    #[inline]
    pub fn enter_consensus_validation() {
        CONSENSUS_VALIDATION_ACTIVE.fetch_add(1, Ordering::SeqCst);
    }

    /// Mark that consensus validation is inactive
    #[inline]
    pub fn exit_consensus_validation() {
        let prev = CONSENSUS_VALIDATION_ACTIVE.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(prev > 0, "exit_consensus_validation called more times than enter_consensus_validation");
    }

    /// Check if consensus validation is currently active
    #[inline]
    pub fn is_consensus_validation_active() -> bool {
        CONSENSUS_VALIDATION_ACTIVE.load(Ordering::SeqCst) > 0
    }

    /// Get current UNIX timestamp
    ///
    /// # Panics
    ///
    /// This function will panic if called during consensus validation,
    /// as using wall-clock time during consensus can lead to chain splits
    /// and nondeterministic behavior.
    #[track_caller]
    pub fn current_timestamp() -> u64 {
        if is_consensus_validation_active() {
            panic!(
                "FATAL: current_timestamp() called during consensus validation at {}. \
                This is a nondeterministic operation that can cause chain splits. \
                Use block timestamps or deterministic time sources instead.",
                std::panic::Location::caller()
            );
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// Check if timestamp is reasonable (not too far in future)
    pub fn is_reasonable_timestamp(timestamp: u64) -> bool {
        let now = current_timestamp();
        // Allow up to 2 hours in the future
        timestamp <= now + 7200
    }
    
    /// Format timestamp for display
    pub fn format_timestamp(timestamp: u64) -> String {
        use std::time::{UNIX_EPOCH, Duration};
        let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
        format!("{:?}", datetime)
    }
}

/// Size utilities
pub mod size {
    use super::*;
    
    /// Calculate transaction size in bytes
    pub fn transaction_size(transaction: &Transaction) -> usize {
        bincode::serialize(transaction).map(|data| data.len()).unwrap_or(0)
    }
    
    /// Calculate block size in bytes
    pub fn block_size(block: &Block) -> usize {
        bincode::serialize(block).map(|data| data.len()).unwrap_or(0)
    }
    
    /// Format size for human reading
    pub fn format_size(size: usize) -> String {
        if size < 1024 {
            format!("{} B", size)
        } else if size < 1024 * 1024 {
            format!("{:.2} KB", size as f64 / 1024.0)
        } else {
            format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Hash utilities
pub mod hash {
    use super::*;

    /// Convert hash to hex string
    pub fn hash_to_hex(hash: &Hash) -> String {
        hex::encode(hash.as_bytes())
    }

    /// Parse hex string to hash
    pub fn hex_to_hash(hex: &str) -> Result<Hash, String> {
        let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err("Hash must be 32 bytes".to_string());
        }
        Ok(Hash::from_slice(&bytes))
    }

    /// Generate random hash (for testing)
    ///
    /// # Panics
    ///
    /// This function will panic if called during consensus validation,
    /// as using random number generation during consensus can lead to
    /// nondeterministic behavior and chain splits.
    #[track_caller]
    pub fn random_hash() -> Hash {
        use super::time;
        if time::is_consensus_validation_active() {
            panic!(
                "FATAL: random_hash() called during consensus validation at {}. \
                This is a nondeterministic operation that can cause chain splits. \
                Use deterministic hash generation instead.",
                std::panic::Location::caller()
            );
        }
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Hash::from_slice(&bytes)
    }
}

/// Fee calculation utilities
pub mod fees {
    use super::*;
    
    /// Calculate minimum fee for transaction
    pub fn calculate_minimum_fee(transaction: &Transaction) -> u64 {
        crate::transaction::creation::utils::calculate_minimum_fee(transaction.size())
    }
    
    /// Calculate fee rate (fee per byte)
    pub fn calculate_fee_rate(transaction: &Transaction) -> f64 {
        let tx_size = size::transaction_size(transaction);
        if tx_size > 0 {
            transaction.fee as f64 / tx_size as f64
        } else {
            0.0
        }
    }
    
    /// Check if transaction has sufficient fee
    pub fn has_sufficient_fee(transaction: &Transaction) -> bool {
        transaction.fee >= calculate_minimum_fee(transaction)
    }
}

/// Difficulty utilities
pub mod difficulty {
    use super::*;
    
    /// Calculate target from difficulty
    pub fn calculate_target(difficulty: Difficulty) -> [u8; 32] {
        difficulty.target()
    }
    
    /// Check if hash meets difficulty
    pub fn meets_difficulty(hash: &Hash, difficulty: Difficulty) -> bool {
        difficulty.check_hash(hash)
    }
    
    /// Calculate next difficulty adjustment
    pub fn calculate_next_difficulty(
        current_difficulty: Difficulty,
        actual_timespan: u64,
        target_timespan: u64,
    ) -> Difficulty {
        let actual_timespan = actual_timespan.max(target_timespan / 4).min(target_timespan * 4);
        let new_bits = (current_difficulty.bits() as u64 * target_timespan / actual_timespan) as u32;
        Difficulty::from_bits(new_bits)
    }
}

/// Validation utilities
pub mod validation {
    use super::*;
    
    /// Quick validation of transaction structure
    pub fn quick_validate_transaction(transaction: &Transaction) -> bool {
        // Basic checks
        transaction.version > 0 &&
        !transaction.signature.signature.is_empty() &&
        (transaction.inputs.is_empty() || transaction.transaction_type.is_identity_transaction())
    }
    
    /// Quick validation of block structure
    pub fn quick_validate_block(block: &Block) -> bool {
        block.header.version > 0 &&
        block.header.height < u64::MAX &&
        block.header.timestamp > 0 &&
        block.transaction_count() <= crate::MAX_TRANSACTIONS_PER_BLOCK
    }
    
    /// Check if DID format is valid
    pub fn is_valid_did_format(did: &str) -> bool {
        did.starts_with("did:zhtp:") && did.len() > 9
    }
}

/// Encoding utilities
pub mod encoding {
    use super::*;
    
    /// Encode transaction as JSON
    pub fn transaction_to_json(transaction: &Transaction) -> Result<String, String> {
        serde_json::to_string_pretty(transaction).map_err(|e| e.to_string())
    }
    
    /// Decode transaction from JSON
    pub fn transaction_from_json(json: &str) -> Result<Transaction, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
    
    /// Encode block as JSON
    pub fn block_to_json(block: &Block) -> Result<String, String> {
        serde_json::to_string_pretty(block).map_err(|e| e.to_string())
    }
    
    /// Decode block from JSON
    pub fn block_from_json(json: &str) -> Result<Block, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
    
    /// Encode as hex
    pub fn encode_hex(data: &[u8]) -> String {
        hex::encode(data)
    }
    
    /// Decode from hex
    pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
        hex::decode(hex).map_err(|e| e.to_string())
    }
}

/// Testing utilities (only available in test builds)
#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::transaction::IdentityTransactionData;
    use lib_crypto::{Signature, PublicKey, SignatureAlgorithm};
    
    /// Create a dummy transaction for testing
    pub fn create_dummy_transaction() -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x01, // mainnet
            transaction_type: crate::types::TransactionType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: Signature {
                signature: vec![1, 2, 3, 4], // Dummy signature
                public_key: PublicKey::new(vec![5, 6, 7, 8]),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: time::current_timestamp(),
            },
            memo: b"test transaction".to_vec(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            token_mint_data: None,
                        governance_config_data: None,
        }
    }
    
    /// Create a dummy block for testing
    pub fn create_dummy_block(height: u64) -> Block {
        let header = crate::block::BlockHeader::new(
            1, // version
            hash::random_hash(), // previous_block_hash
            hash::random_hash(), // merkle_root
            time::current_timestamp(),
            Difficulty::minimum(),
            height,
            0, // transaction_count
            0, // block_size
            Difficulty::minimum(),
        );

        Block::new(header, vec![])
    }
    
    /// Create dummy identity data for testing
    pub fn create_dummy_identity_data() -> IdentityTransactionData {
        IdentityTransactionData {
            did: "did:zhtp:test123".to_string(),
            display_name: "Test User".to_string(),
            public_key: vec![1, 2, 3, 4, 5],
            ownership_proof: vec![6, 7, 8, 9, 10],
            identity_type: "human".to_string(),
            did_document_hash: Hash::default(),
            created_at: time::current_timestamp(),
            registration_fee: 1000,
            dao_fee: 100,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        }
    }
}

#[cfg(test)]
mod nondeterminism_tests;
