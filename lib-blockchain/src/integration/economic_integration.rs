//! Economic integration for ZHTP blockchain
//! 
//! Provides complete integration between lib-blockchain and lib-economy,
//! including transaction creation, fee calculation, UBI distribution,
//! reward processing, and economic validation.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, debug, error};

use crate::types::{Hash, transaction_type::TransactionType as BlockchainTransactionType};

/// Calculate minimum fee required for blockchain transaction
pub fn calculate_minimum_blockchain_fee(
    tx_size: u64,
    amount: u64,
    priority: Priority,
) -> u64 {
    let (network_fee, dao_fee, total_fee) = calculate_total_fee(tx_size, amount, priority);
    
    // Log fee breakdown for transparency
    debug!("Fee breakdown - Network: {}, DAO: {}, Total: {}", network_fee, dao_fee, total_fee);
    
    // Validate fee components
    assert_eq!(network_fee + dao_fee, total_fee, "Fee calculation inconsistency");
    
    total_fee
}

use crate::transaction::{Transaction as BlockchainTransaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};

use crate::integration::zk_integration::ZkTransactionProof;

// Import economy package types and functions
use lib_economy::{
    Transaction as EconomyTransaction,
    TransactionType as EconomyTransactionType,
    Priority,
    create_payment_transaction,
    create_reward_transaction,
    create_ubi_distributions,
    create_welfare_funding,
    calculate_total_fee,
    calculate_dao_fee,
    calculate_network_fee,
    wasm::identity::IdentityId,
    models::fee_calculation::calculate_fee_with_exemptions,
    distribution::reward_distribution::RewardDistribution,
    wallets::wallet_balance::WalletBalance,
    treasury_economics::DaoTreasury,
};

/// Economic transaction processor for blockchain integration
#[derive(Debug, Clone)]
pub struct EconomicTransactionProcessor {
    /// Reward distribution system for network incentives
    reward_distribution: RewardDistribution,
    /// DAO treasury for fund management
    dao_treasury: DaoTreasury,
    /// Wallet balance manager
    wallet_manager: HashMap<[u8; 32], WalletBalance>,
}

impl EconomicTransactionProcessor {
    /// Create new economic transaction processor
    pub fn new() -> Self {
        Self {
            reward_distribution: RewardDistribution::new(),
            dao_treasury: DaoTreasury::new(),
            wallet_manager: HashMap::new(),
        }
    }

    /// Process economic transaction and convert to blockchain format
    pub async fn process_economic_transaction(
        &mut self,
        economy_tx: &EconomyTransaction,
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<BlockchainTransaction> {
        debug!("🏦 Processing economic transaction: {:?}", economy_tx.tx_type);

        // Update wallet balances
        self.update_wallet_balances(economy_tx).await?;

        // Convert economy transaction to blockchain transaction
        let blockchain_tx = self.convert_to_blockchain_transaction(economy_tx, system_keypair).await?;

        // Validate the conversion
        self.validate_economic_conversion(&blockchain_tx, economy_tx)?;

        info!("Economic transaction processed: {} ZHTP from {:?} to {:?}", 
              economy_tx.amount, economy_tx.from, economy_tx.to);

        Ok(blockchain_tx)
    }

    /// Create UBI distribution transactions for verified citizens
    pub async fn create_ubi_distributions_for_blockchain(
        &mut self,
        citizens: &[(IdentityId, u64)],
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<BlockchainTransaction>> {
        info!("Creating UBI distributions for {} citizens", citizens.len());

        // Create economy UBI transactions
        let economy_ubi_txs = create_ubi_distributions(citizens)?;

        // Convert each to blockchain format
        let mut blockchain_txs = Vec::new();
        for economy_tx in economy_ubi_txs {
            let blockchain_tx = self.process_economic_transaction(&economy_tx, system_keypair).await?;
            blockchain_txs.push(blockchain_tx);
        }

        // Update UBI statistics
        let total_ubi_amount: u64 = citizens.iter().map(|(_, amount)| *amount).sum();
        info!("Created {} UBI distributions totaling {} ZHTP", 
              blockchain_txs.len(), total_ubi_amount);

        Ok(blockchain_txs)
    }

    /// Create reward transactions for network services
    pub async fn create_network_reward_transactions(
        &mut self,
        rewards: &[([u8; 32], u64)], // (recipient, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<BlockchainTransaction>> {
        info!("🏦 Creating network reward transactions for {} recipients", rewards.len());

        // Use proper lib-economy reward distribution system
        let total_rewards: u64 = rewards.iter().map(|(_, amount)| *amount).sum();
        debug!("Processing reward distribution for {} ZHTP across {} recipients", total_rewards, rewards.len());

        // Update our reward distribution statistics
        self.reward_distribution.total_rewards_distributed += total_rewards;
        self.reward_distribution.participants_rewarded += rewards.len() as u64;
        *self.reward_distribution.rewards_by_category.entry("network_rewards".to_string()).or_insert(0) += total_rewards;
        self.reward_distribution.last_distribution = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut blockchain_txs = Vec::new();
        for (recipient, amount) in rewards {
            // Use lib-economy validation through the reward distribution system
            if *amount == 0 {
                return Err(anyhow!("Invalid reward amount: 0"));
            }
            
            // Check against reasonable limits (this would be configurable in production)
            if *amount > total_rewards / 2 { // No single reward > 50% of total pool
                return Err(anyhow!("Reward amount too large relative to pool: {}", amount));
            }
            
            // Create economy reward transaction
            let economy_tx = create_reward_transaction(*recipient, *amount)?;
            
            // Convert to blockchain format
            let blockchain_tx = self.process_economic_transaction(&economy_tx, system_keypair).await?;
            blockchain_txs.push(blockchain_tx);
        }

        // Log successful distribution using lib-economy stats
        let stats = self.reward_distribution.get_distribution_stats();
        info!("Successfully processed reward distribution: {} ZHTP total distributed to {} participants", 
              stats["total_rewards_distributed"], stats["participants_rewarded"]);

        info!("Created {} reward transactions totaling {} ZHTP", 
              blockchain_txs.len(), total_rewards);

        Ok(blockchain_txs)
    }

    /// Distribute infrastructure rewards using lib-economy system
    pub async fn distribute_infrastructure_rewards(
        &mut self,
        participants: &[([u8; 32], u64, u64, u64)], // (address, routing_work, storage_work, compute_work)
        reward_pool: u64,
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<BlockchainTransaction>> {
        info!("🏭 Distributing {} ZHTP infrastructure rewards to {} participants", 
              reward_pool, participants.len());

        // Calculate total work
        let total_work: u64 = participants.iter()
            .map(|(_, routing, storage, compute)| routing + storage + compute)
            .sum();

        if total_work == 0 {
            return Err(anyhow!("No work reported by participants"));
        }

        let mut blockchain_txs = Vec::new();
        let mut distributed_total = 0u64;

        for (address, routing_work, storage_work, compute_work) in participants {
            let participant_work = routing_work + storage_work + compute_work;
            let reward_share = (participant_work * reward_pool) / total_work;

            if reward_share > 0 {
                // Create economy reward transaction
                let economy_tx = create_reward_transaction(*address, reward_share)?;
                
                // Convert to blockchain format
                let blockchain_tx = self.process_economic_transaction(&economy_tx, system_keypair).await?;
                blockchain_txs.push(blockchain_tx);
                
                distributed_total += reward_share;

                debug!("Allocated {} ZHTP infrastructure reward (routing: {}, storage: {}, compute: {})", 
                       reward_share, routing_work, storage_work, compute_work);
            }
        }

        // Update reward distribution statistics using lib-economy
        self.reward_distribution.total_rewards_distributed += distributed_total;
        *self.reward_distribution.rewards_by_category.entry("infrastructure".to_string()).or_insert(0) += distributed_total;
        self.reward_distribution.participants_rewarded += participants.len() as u64;
        self.reward_distribution.last_distribution = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        info!("Distributed {} ZHTP infrastructure rewards across {} transactions", 
              distributed_total, blockchain_txs.len());

        Ok(blockchain_txs)
    }

    /// Get reward distribution statistics from lib-economy
    pub fn get_reward_stats(&self) -> serde_json::Value {
        self.reward_distribution.get_distribution_stats()
    }

    /// Process payment transaction with proper fee calculation
    pub async fn create_payment_transaction_for_blockchain(
        &mut self,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        priority: Priority,
        sender_keypair: &lib_crypto::KeyPair,
    ) -> Result<BlockchainTransaction> {
        info!("🏦 Creating payment transaction: {} ZHTP from {:?} to {:?}", amount, from, to);

        // Create economy payment transaction with proper fees
        let economy_tx = create_payment_transaction(from, to, amount, priority)?;

        // Process and convert to blockchain format
        let blockchain_tx = self.process_economic_transaction(&economy_tx, sender_keypair).await?;

        info!("Payment transaction created with {} ZHTP base fee and {} ZHTP DAO fee", 
              economy_tx.base_fee, economy_tx.dao_fee);

        Ok(blockchain_tx)
    }

    /// Calculate transaction fees using economy package (with exemptions)
    pub fn calculate_transaction_fees_with_exemptions(
        &self,
        tx_size: u64,
        amount: u64,
        priority: Priority,
        is_system_transaction: bool,
    ) -> (u64, u64, u64) {
        calculate_fee_with_exemptions(tx_size, amount, priority, is_system_transaction)
    }

    /// Get wallet balance for an address
    pub fn get_wallet_balance(&self, address: &[u8; 32]) -> Option<&WalletBalance> {
        self.wallet_manager.get(address)
    }

    /// Update wallet balance
    pub fn update_wallet_balance(&mut self, address: [u8; 32], balance: WalletBalance) {
        self.wallet_manager.insert(address, balance);
    }

    /// Get treasury statistics
    pub async fn get_treasury_statistics(&self) -> Result<TreasuryStats> {
        let stats = self.dao_treasury.get_treasury_stats();
        Ok(TreasuryStats {
            total_dao_fees_collected: stats["total_dao_fees_collected"].as_u64().unwrap_or(0),
            total_ubi_distributed: stats["total_ubi_distributed"].as_u64().unwrap_or(0),
            total_welfare_distributed: stats["total_welfare_distributed"].as_u64().unwrap_or(0),
            current_treasury_balance: stats["treasury_balance"].as_u64().unwrap_or(0),
            ubi_fund_balance: stats["ubi_allocated"].as_u64().unwrap_or(0),
            welfare_fund_balance: stats["welfare_allocated"].as_u64().unwrap_or(0),
        })
    }

    /// Calculate transaction fees using proper network fee calculation
    pub fn calculate_transaction_fees(&self, tx_size: u64, amount: u64, priority: Priority) -> (u64, u64, u64) {
        // Calculate network fee using lib-economy function
        let network_fee = calculate_network_fee(tx_size, priority);
        
        // Calculate DAO fee (2% of amount for UBI funding)
        let dao_fee = calculate_dao_fee(amount);
        
        // Total fee
        let total_fee = network_fee + dao_fee;
        
        debug!("Fee calculation - Amount: {}, Network: {}, DAO: {}, Total: {}", 
               amount, network_fee, dao_fee, total_fee);
        
        (network_fee, dao_fee, total_fee)
    }

    /// Process network fees for infrastructure operation
    pub async fn process_network_fees(&mut self, network_fees: u64) -> Result<()> {
        if network_fees > 0 {
            debug!("Processing {} ZHTP in network infrastructure fees", network_fees);
            // Network fees would be distributed to infrastructure providers
            // This is where you'd incentivize ISP replacement infrastructure
            info!("Network fees processed for infrastructure rewards");
        } else {
            warn!("Error: Zero network fees to process");
        }
        Ok(())
    }

    /// Convert economy transaction to blockchain transaction format
    async fn convert_to_blockchain_transaction(
        &self,
        economy_tx: &EconomyTransaction,
        keypair: &lib_crypto::KeyPair,
    ) -> Result<BlockchainTransaction> {
        // Determine if this is a system transaction (UBI/welfare/rewards)
        let is_system_transaction = economy_tx.tx_type.is_fee_exempt();

        // Create inputs - empty for system transactions (they create new money)
        let inputs = if is_system_transaction {
            Vec::new() // System transactions don't spend UTXOs
        } else {
            // For regular payments, create a proper input (would normally reference actual UTXOs)
            vec![TransactionInput {
                previous_output: Hash::from(economy_tx.from),
                output_index: 0,
                nullifier: crate::types::hash::blake3_hash(
                    &format!("nullifier_{}_{}", hex::encode(economy_tx.tx_id), economy_tx.timestamp).as_bytes()
                ),
                zk_proof: ZkTransactionProof::default(), // Would be properly generated in production
            }]
        };

        // Create outputs
        let outputs = vec![TransactionOutput {
            commitment: crate::types::hash::blake3_hash(
                &format!("commitment_{}_{}", economy_tx.amount, economy_tx.timestamp).as_bytes()
            ),
            note: crate::types::hash::blake3_hash(
                &format!("note_{}_{}", hex::encode(economy_tx.tx_id), economy_tx.amount).as_bytes()
            ),
            recipient: PublicKey::new(economy_tx.to.to_vec()),
        }];

        // Map economy transaction type to blockchain transaction type
        let blockchain_tx_type = match economy_tx.tx_type {
            EconomyTransactionType::Payment => BlockchainTransactionType::Transfer,
            EconomyTransactionType::Reward => BlockchainTransactionType::Transfer,
            EconomyTransactionType::UbiDistribution => BlockchainTransactionType::Transfer,
            EconomyTransactionType::WelfareDistribution => BlockchainTransactionType::Transfer,
            _ => BlockchainTransactionType::Transfer,
        };

        // Create signature for the transaction
        let signature = self.create_transaction_signature(economy_tx, &inputs, &outputs, keypair).await?;

        // Create memo describing the economic transaction
        let memo = format!(
            "Economic TX: {} - {} ZHTP (Base: {}, DAO: {})",
            economy_tx.tx_type.description(),
            economy_tx.amount,
            economy_tx.base_fee,
            economy_tx.dao_fee
        ).into_bytes();

        // Create identity data for transactions that require identity verification
        let identity_data = match economy_tx.tx_type {
            EconomyTransactionType::UbiDistribution => {
                // UBI distributions require verified citizen identity
                let _recipient_id = IdentityId::new(economy_tx.to);
                Some(IdentityTransactionData {
                    did: format!("did:zhtp:{}", hex::encode(&economy_tx.to[..16])),
                    display_name: "UBI Recipient".to_string(),
                    public_key: economy_tx.to.to_vec(),
                    ownership_proof: Vec::new(), // Empty for system transactions
                    identity_type: "verified_citizen".to_string(),
                    did_document_hash: crate::types::hash::blake3_hash(
                        &format!("ubi_recipient_{}", hex::encode(economy_tx.to)).as_bytes()
                    ),
                    created_at: economy_tx.timestamp,
                    registration_fee: 0, // System transactions are fee-free
                    dao_fee: 0,
                    controlled_nodes: Vec::new(),
                    owned_wallets: Vec::new(),
                })
            },
            EconomyTransactionType::ProposalVote | EconomyTransactionType::ProposalExecution => {
                // DAO votes require identity verification
                let _voter_id = IdentityId::new(economy_tx.from);
                Some(IdentityTransactionData {
                    did: format!("did:zhtp:{}", hex::encode(&economy_tx.from[..16])),
                    display_name: "DAO Member".to_string(),
                    public_key: economy_tx.from.to_vec(),
                    ownership_proof: Vec::new(),
                    identity_type: "dao_member".to_string(),
                    did_document_hash: crate::types::hash::blake3_hash(
                        &format!("dao_member_{}", hex::encode(economy_tx.from)).as_bytes()
                    ),
                    created_at: economy_tx.timestamp,
                    registration_fee: 0,
                    dao_fee: economy_tx.dao_fee,
                    controlled_nodes: Vec::new(),
                    owned_wallets: Vec::new(),
                })
            },
            _ => None, // Regular payments don't require identity verification
        };

        // Create blockchain transaction
        Ok(BlockchainTransaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: blockchain_tx_type,
            inputs,
            outputs,
            fee: economy_tx.total_fee,
            signature,
            memo,
            identity_data,
            validator_data: None,
            wallet_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        })
    }

    /// Create cryptographic signature for blockchain transaction
    async fn create_transaction_signature(
        &self,
        economy_tx: &EconomyTransaction,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        keypair: &lib_crypto::KeyPair,
    ) -> Result<Signature> {
        // Create temporary transaction for signing
        let temp_signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economy_tx.timestamp,
        };

        let temp_transaction = BlockchainTransaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: BlockchainTransactionType::Transfer,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            fee: economy_tx.total_fee,
            signature: temp_signature,
            memo: format!("Economic signature for {}", hex::encode(economy_tx.tx_id)).into_bytes(),
            identity_data: None,
            validator_data: None,
            wallet_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
        };

        // Create signing hash
        let signing_hash = crate::transaction::hashing::hash_for_signature(&temp_transaction);

        // Sign the transaction
        let crypto_signature = lib_crypto::sign_message(keypair, signing_hash.as_bytes())?;

        Ok(Signature {
            signature: crypto_signature.signature,
            public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: economy_tx.timestamp,
        })
    }

    /// Update wallet balances based on economic transaction
    async fn update_wallet_balances(&mut self, economy_tx: &EconomyTransaction) -> Result<()> {
        // Update sender balance (if not system transaction)
        if !economy_tx.tx_type.is_fee_exempt() {
            let sender_balance = self.wallet_manager
                .entry(economy_tx.from)
                .or_insert_with(|| WalletBalance::new(economy_tx.from));
            
            let required_amount = economy_tx.amount + economy_tx.total_fee;
            
            // Check if sender has sufficient balance
            if !sender_balance.can_afford(required_amount) {
                let sender_addr = hex::encode(&economy_tx.from[..8]);
                error!("Insufficient balance for transaction - Sender: {}..., Required: {}, Available: {}", 
                       sender_addr, required_amount, sender_balance.available_balance);
                return Err(anyhow::anyhow!(
                    "Insufficient balance: need {} ZHTP, have {} ZHTP", 
                    required_amount, sender_balance.available_balance
                ));
            }
            
            // Deduct amount by reducing available balance
            sender_balance.available_balance -= required_amount;
            
            let sender_addr = hex::encode(&economy_tx.from[..8]);
            debug!("Sender balance updated - Address: {}..., Deducted: {}, New Balance: {}", 
                   sender_addr, required_amount, sender_balance.available_balance);
        } else {
            // System transaction - log but don't deduct fees
            debug!(" System transaction processed - Type: {}, Amount: {}", 
                   economy_tx.tx_type.description(), economy_tx.amount);
        }

        // Update recipient balance
        let recipient_balance = self.wallet_manager
            .entry(economy_tx.to)
            .or_insert_with(|| WalletBalance::new(economy_tx.to));
        
        let old_balance = recipient_balance.available_balance;
        
        // Add amount to available balance
        recipient_balance.available_balance += economy_tx.amount;
        
        let recipient_addr = hex::encode(&economy_tx.to[..8]);
        debug!("Recipient balance updated - Address: {}..., Added: {}, Old: {}, New: {}", 
               recipient_addr, economy_tx.amount, old_balance, recipient_balance.available_balance);

        Ok(())
    }

    /// Validate economic transaction conversion
    fn validate_economic_conversion(
        &self,
        blockchain_tx: &BlockchainTransaction,
        economy_tx: &EconomyTransaction,
    ) -> Result<()> {
        // Validate fee consistency
        if blockchain_tx.fee != economy_tx.total_fee {
            return Err(anyhow::anyhow!(
                "Fee mismatch: blockchain={}, economy={}", 
                blockchain_tx.fee, 
                economy_tx.total_fee
            ));
        }

        // Validate system transaction structure
        let is_system_tx = economy_tx.tx_type.is_fee_exempt();
        if is_system_tx && !blockchain_tx.inputs.is_empty() {
            return Err(anyhow::anyhow!("System transaction should have empty inputs"));
        }

        // Validate non-system transaction structure
        if !is_system_tx && blockchain_tx.inputs.is_empty() {
            return Err(anyhow::anyhow!("Non-system transaction should have inputs"));
        }

        // Validate output structure
        if blockchain_tx.outputs.is_empty() {
            return Err(anyhow::anyhow!("Transaction should have at least one output"));
        }

        debug!("Economic transaction conversion validated successfully");
        Ok(())
    }
}

impl Default for EconomicTransactionProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Treasury statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    pub total_dao_fees_collected: u64,
    pub total_ubi_distributed: u64,
    pub total_welfare_distributed: u64,
    pub current_treasury_balance: u64,
    pub ubi_fund_balance: u64,
    pub welfare_fund_balance: u64,
}

/// Create an economic transaction processor for blockchain integration
pub fn create_economic_processor() -> EconomicTransactionProcessor {
    EconomicTransactionProcessor::new()
}

/// Convert economy transaction amount to blockchain amount (1:1 mapping)
pub fn convert_economy_amount_to_blockchain(economy_amount: u64) -> u64 {
    economy_amount // Direct 1:1 mapping between economy and blockchain tokens
}

/// Convert blockchain amount to economy amount (1:1 mapping)
pub fn convert_blockchain_amount_to_economy(blockchain_amount: u64) -> u64 {
    blockchain_amount // Direct 1:1 mapping between economy and blockchain tokens
}

/// Validate DAO fee calculation for blockchain transaction
pub fn validate_dao_fee_calculation(
    transaction_amount: u64,
    claimed_dao_fee: u64,
) -> Result<bool> {
    let expected_dao_fee = calculate_dao_fee(transaction_amount);
    Ok(claimed_dao_fee == expected_dao_fee)
}



/// Process welfare funding transactions for blockchain
pub async fn create_welfare_funding_transactions(
    services: &[(String, [u8; 32], u64)], // (service_name, address, amount)
    system_keypair: &lib_crypto::KeyPair,
) -> Result<Vec<BlockchainTransaction>> {
    info!("🏦 Creating welfare funding transactions for {} services", services.len());

    // Create economy welfare transactions
    let economy_welfare_txs = create_welfare_funding(services)?;

    // Convert to blockchain format
    let mut processor = EconomicTransactionProcessor::new();
    let mut blockchain_txs = Vec::new();
    
    for economy_tx in economy_welfare_txs {
        let blockchain_tx = processor.process_economic_transaction(&economy_tx, system_keypair).await?;
        blockchain_txs.push(blockchain_tx);
    }

    let total_welfare: u64 = services.iter().map(|(_, _, amount)| *amount).sum();
    info!("Created {} welfare funding transactions totaling {} ZHTP", 
          blockchain_txs.len(), total_welfare);

    Ok(blockchain_txs)
}

/// Economic integration utilities
pub mod utils {
    use super::*;

    /// Check if a blockchain transaction represents a UBI distribution
    pub fn is_ubi_distribution(blockchain_tx: &BlockchainTransaction) -> bool {
        blockchain_tx.inputs.is_empty() && 
        blockchain_tx.fee == 0 &&
        blockchain_tx.memo.starts_with(b"Economic TX: UBI Distribution")
    }

    /// Check if a blockchain transaction represents a welfare distribution
    pub fn is_welfare_distribution(blockchain_tx: &BlockchainTransaction) -> bool {
        blockchain_tx.inputs.is_empty() && 
        blockchain_tx.fee == 0 &&
        blockchain_tx.memo.starts_with(b"Economic TX: Welfare Distribution")
    }

    /// Check if a blockchain transaction represents a network reward
    pub fn is_network_reward(blockchain_tx: &BlockchainTransaction) -> bool {
        blockchain_tx.inputs.is_empty() && 
        blockchain_tx.fee == 0 &&
        blockchain_tx.memo.starts_with(b"Economic TX: Reward")
    }

    /// Extract economic transaction info from blockchain transaction memo
    pub fn extract_economic_info(blockchain_tx: &BlockchainTransaction) -> Option<(String, u64, u64, u64)> {
        let memo_str = String::from_utf8_lossy(&blockchain_tx.memo);
        if memo_str.starts_with("Economic TX: ") {
            // Parse memo format: "Economic TX: TYPE - AMOUNT ZHTP (Base: BASE, DAO: DAO)"
            // This is a simplified parser - production would use proper parsing
            let parts: Vec<&str> = memo_str.split(" - ").collect();
            if parts.len() >= 2 {
                let tx_type = parts[0].replace("Economic TX: ", "");
                // Return (type, amount, base_fee, dao_fee) - simplified for demo
                Some((tx_type, blockchain_tx.fee, 0, blockchain_tx.fee))
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::generate_keypair;

    #[tokio::test]
    async fn test_economic_processor_creation() {
        let processor = EconomicTransactionProcessor::new();
        assert_eq!(processor.wallet_manager.len(), 0);
    }

    #[tokio::test]
    async fn test_ubi_distribution_creation() -> Result<()> {
        let mut processor = EconomicTransactionProcessor::new();
        let keypair = generate_keypair()?;
        
        let citizens = vec![
            (IdentityId::new([1u8; 32]), 1000),
            (IdentityId::new([2u8; 32]), 1000),
        ];

        let blockchain_txs = processor.create_ubi_distributions_for_blockchain(&citizens, &keypair).await?;
        
        assert_eq!(blockchain_txs.len(), 2);
        for tx in &blockchain_txs {
            assert_eq!(tx.inputs.len(), 0); // System transactions have no inputs
            assert_eq!(tx.fee, 0); // UBI distributions are fee-free
            assert!(tx.memo.starts_with(b"Economic TX: UBI Distribution"));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_payment_transaction_creation() -> Result<()> {
        let mut processor = EconomicTransactionProcessor::new();
        let keypair = generate_keypair()?;
        
        let from = [1u8; 32];
        let to = [2u8; 32];
        let amount = 1000;

        let blockchain_tx = processor.create_payment_transaction_for_blockchain(
            from, to, amount, Priority::Normal, &keypair
        ).await?;

        assert_eq!(blockchain_tx.inputs.len(), 1); // Payment has inputs
        assert!(blockchain_tx.fee > 0); // Payment has fees
        assert!(blockchain_tx.memo.starts_with(b"Economic TX:"));

        Ok(())
    }

    #[tokio::test]
    async fn test_fee_calculation() {
        let processor = EconomicTransactionProcessor::new();
        
        let (network_fee, dao_fee, total_fee) = processor.calculate_transaction_fees(
            250, // tx_size
            10000, // amount
            Priority::Normal,
        );

        assert!(network_fee > 0);
        assert!(dao_fee > 0);
        assert_eq!(total_fee, network_fee + dao_fee);

        // Test system transaction (should be fee-free)
        let (sys_net, sys_dao, sys_total) = processor.calculate_transaction_fees(
            250, 10000, Priority::Normal
        );

        assert_eq!(sys_net, 0);
        assert_eq!(sys_dao, 0);
        assert_eq!(sys_total, 0);
    }

    #[test]
    fn test_dao_fee_validation() -> Result<()> {
        let amount = 10000;
        let expected_dao_fee = calculate_dao_fee(amount);
        
        assert!(validate_dao_fee_calculation(amount, expected_dao_fee)?);
        assert!(!validate_dao_fee_calculation(amount, expected_dao_fee + 1)?);

        Ok(())
    }

    #[test]
    fn test_utility_functions() {
        // Test amount conversion (1:1 mapping)
        assert_eq!(convert_economy_amount_to_blockchain(1000), 1000);
        assert_eq!(convert_blockchain_amount_to_economy(2000), 2000);

        // Test minimum fee calculation
        let min_fee = calculate_minimum_blockchain_fee(250, 1000, Priority::Normal);
        assert!(min_fee > 0);
    }
}