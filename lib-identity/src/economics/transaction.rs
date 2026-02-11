//! Transaction types and economic integration from the original identity.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use lib_crypto::Hash;

/// Transaction types supported by SOV
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    /// Standard payment transaction
    Standard,
    /// UBI distribution transaction
    UbiDistribution,
    /// DAO fee transaction
    DaoFee,
    /// Reward transaction (welcome bonus, etc.)
    Reward,
    /// Smart contract execution
    Contract,
    /// Governance transaction
    Governance,
}

/// Transaction priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Priority {
    /// Low priority (longer confirmation time)
    Low,
    /// Normal priority
    Normal,
    /// High priority (faster confirmation)
    High,
    /// Urgent priority (immediate processing)
    Urgent,
}

/// SOV Transaction from the original identity.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID
    pub tx_id: Hash,
    /// Sender address
    pub from: [u8; 32],
    /// Recipient address
    pub to: [u8; 32],
    /// Transaction amount
    pub amount: u64,
    /// Base transaction fee
    pub base_fee: u64,
    /// DAO fee portion
    pub dao_fee: u64,
    /// Total fee (base_fee + dao_fee)
    pub total_fee: u64,
    /// Transaction type
    pub tx_type: TransactionType,
    /// Timestamp
    pub timestamp: u64,
    /// Block height when included
    pub block_height: u64,
    /// DAO fee proof
    pub dao_fee_proof: Option<[u8; 32]>,
}

impl Transaction {
    /// Create a new transaction - IMPLEMENTATION FROM ORIGINAL
    pub fn new(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        tx_type: TransactionType,
        economic_model: &mut super::EconomicModel,
        tx_size: u64,
        priority: Priority,
    ) -> Result<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Calculate fees based on transaction size and priority
        let base_fee = Self::calculate_base_fee(tx_size, priority);
        let dao_fee = base_fee / 10; // 10% to DAO
        let total_fee = base_fee + dao_fee;

        // Generate transaction ID
        let mut tx_id_data = Vec::new();
        tx_id_data.extend_from_slice(&from);
        tx_id_data.extend_from_slice(&to);
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&amount.to_le_bytes()));
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&timestamp.to_le_bytes()));
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&serde_json::to_vec(&tx_type).unwrap_or_default()));
        
        let tx_id = Hash::from_bytes(&lib_crypto::hash_blake3(&tx_id_data));

        // Generate DAO fee proof
        let dao_fee_proof = if dao_fee > 0 {
            let mut proof_data = Vec::new();
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(&dao_fee.to_le_bytes()));
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(&timestamp.to_le_bytes()));
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(b"dao_fee_proof"));
            Some(lib_crypto::hash_blake3(&proof_data))
        } else {
            None
        };

        Ok(Transaction {
            tx_id,
            from,
            to,
            amount,
            base_fee,
            dao_fee,
            total_fee,
            tx_type,
            timestamp,
            block_height: economic_model.current_block,
            dao_fee_proof,
        })
    }

    /// Calculate base fee based on transaction size and priority
    fn calculate_base_fee(tx_size: u64, priority: Priority) -> u64 {
        let base_rate = match priority {
            Priority::Low => 1,
            Priority::Normal => 5,
            Priority::High => 15,
            Priority::Urgent => 50,
        };
        
        // Minimum fee is 1 SOV, scales with transaction size
        std::cmp::max(1, (tx_size * base_rate) / 1000)
    }

    /// Verify transaction integrity
    pub fn verify(&self) -> Result<bool> {
        // Verify transaction ID
        let mut tx_id_data = Vec::new();
        tx_id_data.extend_from_slice(&self.from);
        tx_id_data.extend_from_slice(&self.to);
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&self.amount.to_le_bytes()));
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&self.timestamp.to_le_bytes()));
        tx_id_data.extend_from_slice(&lib_crypto::hash_blake3(&serde_json::to_vec(&self.tx_type).unwrap_or_default()));
        
        let expected_tx_id = Hash::from_bytes(&lib_crypto::hash_blake3(&tx_id_data));
        
        if self.tx_id != expected_tx_id {
            return Ok(false);
        }

        // Verify fee calculation
        if self.total_fee != self.base_fee + self.dao_fee {
            return Ok(false);
        }

        // Verify DAO fee proof if present
        if let Some(dao_fee_proof) = self.dao_fee_proof {
            let mut proof_data = Vec::new();
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(&self.dao_fee.to_le_bytes()));
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(&self.timestamp.to_le_bytes()));
            proof_data.extend_from_slice(&lib_crypto::hash_blake3(b"dao_fee_proof"));
            let expected_proof = lib_crypto::hash_blake3(&proof_data);
            
            if dao_fee_proof != expected_proof {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get transaction age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp)
    }

    /// Check if transaction is recent (within 24 hours)
    pub fn is_recent(&self) -> bool {
        self.age_seconds() < 24 * 3600
    }

    /// Get transaction summary
    pub fn get_summary(&self) -> TransactionSummary {
        TransactionSummary {
            tx_id: self.tx_id.clone(),
            from: self.from,
            to: self.to,
            amount: self.amount,
            total_fee: self.total_fee,
            tx_type: self.tx_type.clone(),
            timestamp: self.timestamp,
            age_seconds: self.age_seconds(),
            is_verified: self.verify().unwrap_or(false),
        }
    }
}

/// Transaction summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub tx_id: Hash,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub total_fee: u64,
    pub tx_type: TransactionType,
    pub timestamp: u64,
    pub age_seconds: u64,
    pub is_verified: bool,
}
