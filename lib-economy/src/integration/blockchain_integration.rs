//! Blockchain integration interfaces for ZHTP Economics
//! 
//! Provides standardized interfaces for integrating the economics engine
//! with the ZHTP blockchain layer, handling transactions, fees, and rewards.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::models::EconomicModel;
use crate::transactions::Transaction;
use crate::treasury_economics::DaoTreasury;
use crate::wasm::logging::info;

/// Interface for blockchain economic events
pub trait BlockchainEconomics {
    /// Process transaction fees from blockchain
    fn process_transaction_fees(&mut self, transaction_id: &str, fees: u64) -> Result<()>;
    
    /// Handle block rewards for validators
    fn handle_block_rewards(&mut self, validator_id: &str, reward: u64) -> Result<()>;
    
    /// Process DAO fee distribution
    fn process_dao_fees(&mut self, dao_fees: u64) -> Result<()>;
    
    /// Handle infrastructure rewards
    fn handle_infrastructure_rewards(&mut self, provider_id: &str, reward: u64) -> Result<()>;
    
    /// Process  incentives
    fn process_isp_bypass_rewards(&mut self, participant_id: &str, reward: u64) -> Result<()>;
}

/// Economic data that flows to blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicBlockchainData {
    /// Network transaction fees
    pub transaction_fees: u64,
    /// DAO fees for UBI/welfare
    pub dao_fees: u64,
    /// Infrastructure provider rewards
    pub infrastructure_rewards: u64,
    /// Validator rewards
    pub validator_rewards: u64,
    ///  incentive rewards
    pub isp_bypass_rewards: u64,
    /// Total tokens minted
    pub tokens_minted: u64,
    /// Block height for this data
    pub block_height: u64,
    /// Timestamp of economic data
    pub timestamp: u64,
}

impl EconomicBlockchainData {
    /// Create new economic blockchain data
    pub fn new() -> Self {
        Self {
            transaction_fees: 0,
            dao_fees: 0,
            infrastructure_rewards: 0,
            validator_rewards: 0,
            isp_bypass_rewards: 0,
            tokens_minted: 0,
            block_height: 0,
            timestamp: crate::wasm::compatibility::current_timestamp().unwrap_or(0),
        }
    }
    
    /// Calculate total economic value
    pub fn total_value(&self) -> u64 {
        self.transaction_fees + self.dao_fees + self.infrastructure_rewards + 
        self.validator_rewards + self.isp_bypass_rewards
    }
    
    /// Get economic data as JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "transaction_fees": self.transaction_fees,
            "dao_fees": self.dao_fees,
            "infrastructure_rewards": self.infrastructure_rewards,
            "validator_rewards": self.validator_rewards,
            "isp_bypass_rewards": self.isp_bypass_rewards,
            "tokens_minted": self.tokens_minted,
            "block_height": self.block_height,
            "timestamp": self.timestamp,
            "total_value": self.total_value()
        })
    }
}

/// Blockchain integration implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainIntegration {
    /// Economic model interface
    economic_model: EconomicModel,
    /// DAO treasury interface
    dao_treasury: DaoTreasury,
    /// Pending economic transactions
    pending_transactions: Vec<EconomicBlockchainData>,
    /// Total economic data processed
    total_processed: u64,
}

impl BlockchainIntegration {
    /// Create new blockchain integration
    pub fn new() -> Self {
        Self {
            economic_model: EconomicModel::new(),
            dao_treasury: DaoTreasury::new(),
            pending_transactions: Vec::new(),
            total_processed: 0,
        }
    }
    
    /// Submit economic data to blockchain layer
    pub fn submit_economic_data(&mut self, data: &EconomicBlockchainData) -> Result<String> {
        // Add to pending transactions
        self.pending_transactions.push(data.clone());
        
        // Generate transaction hash
        let data_json = data.to_json().to_string();
        let tx_hash = hex::encode(crate::wasm::hash_blake3(data_json.as_bytes()));
        
        info!(
            " Submitted economic data to blockchain: {} ZHTP total value, hash: {}",
            data.total_value(),
            &tx_hash[..8]
        );
        
        Ok(tx_hash)
    }
    
    /// Process confirmed economic transaction from blockchain
    pub fn process_confirmed_transaction(&mut self, tx_hash: &str, block_height: u64) -> Result<()> {
        // Find and remove from pending
        if let Some(pos) = self.pending_transactions.iter().position(|tx| {
            let data_json = tx.to_json().to_string();
            let hash = hex::encode(crate::wasm::hash_blake3(data_json.as_bytes()));
            hash.starts_with(&tx_hash[..8])
        }) {
            let confirmed_data = self.pending_transactions.remove(pos);
            
            // Process the economic effects
            self.economic_model.process_network_fees(confirmed_data.transaction_fees)?;
            self.dao_treasury.add_dao_fees(confirmed_data.dao_fees)?;
            self.economic_model.mint_operational_tokens(confirmed_data.tokens_minted, "blockchain confirmation")?;
            
            self.total_processed += 1;
            
            info!(
                "Confirmed economic transaction at block {}: {} ZHTP value",
                block_height,
                confirmed_data.total_value()
            );
        }
        
        Ok(())
    }
    
    /// Create economic data from transaction
    pub fn create_economic_data_from_transaction(&self, transaction: &Transaction) -> EconomicBlockchainData {
        let mut data = EconomicBlockchainData::new();
        
        // Split fees between network and DAO
        data.transaction_fees = transaction.base_fee;
        data.dao_fees = transaction.dao_fee;
        data.block_height = transaction.block_height;
        data.timestamp = transaction.timestamp;
        
        data
    }
    
    /// Batch process multiple transactions
    pub fn batch_process_transactions(&mut self, transactions: &[Transaction]) -> Result<String> {
        let mut batch_data = EconomicBlockchainData::new();
        
        for transaction in transactions {
            let tx_data = self.create_economic_data_from_transaction(transaction);
            batch_data.transaction_fees += tx_data.transaction_fees;
            batch_data.dao_fees += tx_data.dao_fees;
        }
        
        batch_data.block_height = transactions.last().map(|tx| tx.block_height).unwrap_or(0);
        
        self.submit_economic_data(&batch_data)
    }
    
    /// Get integration statistics
    pub fn get_integration_stats(&self) -> serde_json::Value {
        let pending_value: u64 = self.pending_transactions.iter()
            .map(|tx| tx.total_value())
            .sum();
            
        serde_json::json!({
            "pending_transactions": self.pending_transactions.len(),
            "total_processed": self.total_processed,
            "pending_total_value": pending_value,
            "economic_model_supply": self.economic_model.current_supply,
            "dao_treasury_balance": self.dao_treasury.treasury_balance
        })
    }
    
    /// Get economic model reference
    pub fn get_economic_model(&self) -> &EconomicModel {
        &self.economic_model
    }
    
    /// Get mutable economic model reference
    pub fn get_economic_model_mut(&mut self) -> &mut EconomicModel {
        &mut self.economic_model
    }
    
    /// Get DAO treasury reference
    pub fn get_dao_treasury(&self) -> &DaoTreasury {
        &self.dao_treasury
    }
    
    /// Get mutable DAO treasury reference
    pub fn get_dao_treasury_mut(&mut self) -> &mut DaoTreasury {
        &mut self.dao_treasury
    }
}

impl BlockchainEconomics for BlockchainIntegration {
    fn process_transaction_fees(&mut self, transaction_id: &str, fees: u64) -> Result<()> {
        self.economic_model.process_network_fees(fees)?;
        
        info!(
            "💳 Processed {} ZHTP transaction fees for tx: {}",
            fees, transaction_id
        );
        
        Ok(())
    }
    
    fn handle_block_rewards(&mut self, validator_id: &str, reward: u64) -> Result<()> {
        self.economic_model.mint_operational_tokens(reward, "validator reward")?;
        
        info!(
            " Handled {} ZHTP block reward for validator: {}",
            reward, validator_id
        );
        
        Ok(())
    }
    
    fn process_dao_fees(&mut self, dao_fees: u64) -> Result<()> {
        self.dao_treasury.add_dao_fees(dao_fees)?;
        
        info!(
            " Processed {} ZHTP DAO fees for UBI/welfare",
            dao_fees
        );
        
        Ok(())
    }
    
    fn handle_infrastructure_rewards(&mut self, provider_id: &str, reward: u64) -> Result<()> {
        self.economic_model.mint_operational_tokens(reward, "infrastructure reward")?;
        
        info!(
            "🏭 Handled {} ZHTP infrastructure reward for provider: {}",
            reward, provider_id
        );
        
        Ok(())
    }
    
    fn process_isp_bypass_rewards(&mut self, participant_id: &str, reward: u64) -> Result<()> {
        self.economic_model.mint_operational_tokens(reward, " reward")?;
        
        info!(
            "Processed {} ZHTP  reward for participant: {}",
            reward, participant_id
        );
        
        Ok(())
    }
}

impl Default for BlockchainIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for blockchain integration

/// Create blockchain integration with economic model
pub fn create_blockchain_integration_with_model(model: EconomicModel) -> BlockchainIntegration {
    let mut integration = BlockchainIntegration::new();
    integration.economic_model = model;
    integration
}

/// Create blockchain integration with treasury
pub fn create_blockchain_integration_with_treasury(treasury: DaoTreasury) -> BlockchainIntegration {
    let mut integration = BlockchainIntegration::new();
    integration.dao_treasury = treasury;
    integration
}

/// Process economic events from blockchain
pub fn process_blockchain_economic_events(
    integration: &mut BlockchainIntegration,
    events: &[(String, String, u64)], // (event_type, entity_id, amount)
) -> Result<()> {
    for (event_type, entity_id, amount) in events {
        match event_type.as_str() {
            "transaction_fee" => integration.process_transaction_fees(entity_id, *amount)?,
            "block_reward" => integration.handle_block_rewards(entity_id, *amount)?,
            "dao_fee" => integration.process_dao_fees(*amount)?,
            "infrastructure_reward" => integration.handle_infrastructure_rewards(entity_id, *amount)?,
            "isp_bypass_reward" => integration.process_isp_bypass_rewards(entity_id, *amount)?,
            _ => {
                info!("Unknown economic event type: {}", event_type);
            }
        }
    }
    
    Ok(())
}
