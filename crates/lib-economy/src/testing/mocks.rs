//! Mock implementations for testing

use anyhow::Result;
use crate::integration::{BlockchainEconomics, NetworkEconomics};

/// Mock blockchain for testing economic flows
pub struct MockBlockchain {
    pub processed_fees: Vec<(String, u64)>,
    pub block_rewards: Vec<(String, u64)>,
    pub dao_fees: Vec<u64>,
    pub infrastructure_rewards: Vec<(String, u64)>,
    pub isp_bypass_rewards: Vec<(String, u64)>,
}

impl MockBlockchain {
    pub fn new() -> Self {
        Self {
            processed_fees: Vec::new(),
            block_rewards: Vec::new(),
            dao_fees: Vec::new(),
            infrastructure_rewards: Vec::new(),
            isp_bypass_rewards: Vec::new(),
        }
    }
    
    pub fn total_fees(&self) -> u64 {
        self.processed_fees.iter().map(|(_, fee)| *fee).sum()
    }
    
    pub fn total_rewards(&self) -> u64 {
        self.block_rewards.iter().map(|(_, reward)| *reward).sum()
    }
    
    pub fn total_dao_fees(&self) -> u64 {
        self.dao_fees.iter().sum()
    }
    
    pub fn total_infrastructure_rewards(&self) -> u64 {
        self.infrastructure_rewards.iter().map(|(_, reward)| *reward).sum()
    }
    
    pub fn total_isp_bypass_rewards(&self) -> u64 {
        self.isp_bypass_rewards.iter().map(|(_, reward)| *reward).sum()
    }
}

impl BlockchainEconomics for MockBlockchain {
    fn process_transaction_fees(&mut self, transaction_id: &str, fees: u64) -> Result<()> {
        self.processed_fees.push((transaction_id.to_string(), fees));
        Ok(())
    }
    
    fn handle_block_rewards(&mut self, validator_id: &str, reward: u64) -> Result<()> {
        self.block_rewards.push((validator_id.to_string(), reward));
        Ok(())
    }
    
    fn process_dao_fees(&mut self, dao_fees: u64) -> Result<()> {
        self.dao_fees.push(dao_fees);
        Ok(())
    }
    
    fn handle_infrastructure_rewards(&mut self, provider_id: &str, reward: u64) -> Result<()> {
        self.infrastructure_rewards.push((provider_id.to_string(), reward));
        Ok(())
    }
    
    fn process_isp_bypass_rewards(&mut self, participant_id: &str, reward: u64) -> Result<()> {
        self.isp_bypass_rewards.push((participant_id.to_string(), reward));
        Ok(())
    }
}

/// Mock network for testing economic incentives
pub struct MockNetwork {
    pub bandwidth_rewards: Vec<(String, u64)>,
    pub isp_bypasses: Vec<(String, u64)>,
    pub quality_bonuses: Vec<(String, f64)>,
}

impl MockNetwork {
    pub fn new() -> Self {
        Self {
            bandwidth_rewards: Vec::new(),
            isp_bypasses: Vec::new(),
            quality_bonuses: Vec::new(),
        }
    }
    
    pub fn total_bandwidth_rewards(&self) -> u64 {
        self.bandwidth_rewards.iter().map(|(_, reward)| *reward).sum()
    }
    
    pub fn total_isp_bypass_value(&self) -> u64 {
        self.isp_bypasses.iter().map(|(_, value)| *value).sum()
    }
}

impl NetworkEconomics for MockNetwork {
    fn handle_bandwidth_reward(&mut self, node_id: &str, bytes_shared: u64) -> Result<(), String> {
        self.bandwidth_rewards.push((node_id.to_string(), bytes_shared));
        Ok(())
    }
    
    fn process_isp_bypass(&mut self, node_id: &str, bypass_amount: u64) -> Result<(), String> {
        self.isp_bypasses.push((node_id.to_string(), bypass_amount));
        Ok(())
    }
    
    fn handle_quality_bonus(&mut self, node_id: &str, quality_score: f64) -> Result<(), String> {
        self.quality_bonuses.push((node_id.to_string(), quality_score));
        Ok(())
    }
}
