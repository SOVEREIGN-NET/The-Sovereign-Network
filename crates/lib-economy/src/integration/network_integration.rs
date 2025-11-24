//! Network integration for economic incentives

/// Network economic event handler
pub trait NetworkEconomics {
    /// Handle bandwidth sharing rewards
    fn handle_bandwidth_reward(&mut self, node_id: &str, bytes_shared: u64) -> Result<(), String>;
    
    /// Process  incentives
    fn process_isp_bypass(&mut self, node_id: &str, bypass_amount: u64) -> Result<(), String>;
    
    /// Handle network quality bonuses
    fn handle_quality_bonus(&mut self, node_id: &str, quality_score: f64) -> Result<(), String>;
}

/// Network economic metrics
pub struct NetworkEconomicMetrics {
    pub total_bandwidth_shared: u64,
    pub total_isp_bypass_value: u64,
    pub average_quality_score: f64,
    pub active_nodes: u32,
    pub total_rewards_distributed: u64,
}

impl NetworkEconomicMetrics {
    pub fn new() -> Self {
        Self {
            total_bandwidth_shared: 0,
            total_isp_bypass_value: 0,
            average_quality_score: 0.0,
            active_nodes: 0,
            total_rewards_distributed: 0,
        }
    }
    
    pub fn calculate_efficiency(&self) -> f64 {
        if self.active_nodes == 0 {
            return 0.0;
        }
        
        self.total_rewards_distributed as f64 / self.active_nodes as f64
    }
}

/// Network integration implementation
pub struct NetworkIntegration {
    pub metrics: NetworkEconomicMetrics,
}

impl NetworkIntegration {
    pub fn new() -> Self {
        Self {
            metrics: NetworkEconomicMetrics::new(),
        }
    }
    
    pub fn update_bandwidth_metrics(&mut self, bytes_shared: u64) {
        self.metrics.total_bandwidth_shared += bytes_shared;
    }
    
    pub fn update_quality_metrics(&mut self, quality_score: f64) {
        // Simple moving average for now
        let weight = 0.1;
        self.metrics.average_quality_score = 
            (1.0 - weight) * self.metrics.average_quality_score + weight * quality_score;
    }
    
    pub fn get_network_stats(&self) -> &NetworkEconomicMetrics {
        &self.metrics
    }
}
