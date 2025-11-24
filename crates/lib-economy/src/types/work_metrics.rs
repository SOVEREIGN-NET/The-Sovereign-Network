//! Work metrics for measuring network contributions
//! 
//! Defines structures for tracking different types of work performed
//! in the network, including  activities and infrastructure services.

use serde::{Serialize, Deserialize};

/// General work metrics for network services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkMetrics {
    /// Amount of routing work performed (bytes routed)
    pub routing_work: u64,
    /// Amount of storage work performed (bytes stored)
    pub storage_work: u64,
    /// Amount of computational work performed (operations executed)
    pub compute_work: u64,
    /// Quality score of services provided (0.0-1.0)
    pub quality_score: f64,
    /// Hours of uptime provided
    pub uptime_hours: u64,
}

impl WorkMetrics {
    /// Create new work metrics
    pub fn new() -> Self {
        WorkMetrics {
            routing_work: 0,
            storage_work: 0,
            compute_work: 0,
            quality_score: 0.0,
            uptime_hours: 0,
        }
    }
    
    /// Add routing work
    pub fn add_routing_work(&mut self, bytes: u64) {
        self.routing_work += bytes;
    }
    
    /// Add storage work
    pub fn add_storage_work(&mut self, bytes: u64) {
        self.storage_work += bytes;
    }
    
    /// Add compute work
    pub fn add_compute_work(&mut self, operations: u64) {
        self.compute_work += operations;
    }
    
    /// Update quality score
    pub fn update_quality_score(&mut self, score: f64) {
        if score.is_nan() {
            // Preserve NaN for debugging purposes
            self.quality_score = score;
        } else {
            // Clamp valid values between 0.0 and 1.0
            self.quality_score = score.max(0.0).min(1.0);
        }
    }
    
    /// Add uptime hours
    pub fn add_uptime_hours(&mut self, hours: u64) {
        self.uptime_hours += hours;
    }
    
    /// Check if quality meets bonus threshold
    pub fn qualifies_for_quality_bonus(&self) -> bool {
        self.quality_score > crate::QUALITY_BONUS_THRESHOLD
    }
    
    /// Check if uptime meets bonus threshold
    pub fn qualifies_for_uptime_bonus(&self) -> bool {
        self.uptime_hours >= crate::UPTIME_BONUS_THRESHOLD
    }
}

impl Default for WorkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

///  Work Metrics - measures work done to replace ISPs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspBypassWork {
    /// Internet bandwidth shared with other users (GB)
    pub bandwidth_shared_gb: u64,
    /// Packets routed through mesh network (MB)
    pub packets_routed_mb: u64,
    /// Hours of connectivity uptime provided
    pub uptime_hours: u64,
    /// Connection quality score (0.0-1.0)
    pub connection_quality: f64,
    /// Number of users served through shared connection
    pub users_served: u64,
    /// Cost savings provided to community (USD equivalent)
    pub cost_savings_provided: u64,
}

impl IspBypassWork {
    /// Create new  work metrics
    pub fn new() -> Self {
        IspBypassWork {
            bandwidth_shared_gb: 0,
            packets_routed_mb: 0,
            uptime_hours: 0,
            connection_quality: 0.0,
            users_served: 0,
            cost_savings_provided: 0,
        }
    }
    
    /// Add bandwidth sharing
    pub fn add_bandwidth_shared(&mut self, gb: u64) {
        self.bandwidth_shared_gb += gb;
    }
    
    /// Add packet routing
    pub fn add_packets_routed(&mut self, mb: u64) {
        self.packets_routed_mb += mb;
    }
    
    /// Update connection quality
    pub fn update_connection_quality(&mut self, quality: f64) {
        self.connection_quality = quality.max(0.0).min(1.0);
    }
    
    /// Add users served
    pub fn add_users_served(&mut self, count: u64) {
        self.users_served += count;
    }
    
    /// Add cost savings
    pub fn add_cost_savings(&mut self, usd_equivalent: u64) {
        self.cost_savings_provided += usd_equivalent;
    }
    
    /// Calculate total  value
    pub fn total_isp_bypass_value(&self) -> u64 {
        // Bandwidth sharing reward
        let bandwidth_reward = self.bandwidth_shared_gb * crate::ISP_BYPASS_CONNECTIVITY_RATE;
        
        // Packet routing reward
        let routing_reward = self.packets_routed_mb * crate::ISP_BYPASS_MESH_RATE;
        
        // Uptime bonus
        let uptime_bonus = self.uptime_hours * crate::ISP_BYPASS_UPTIME_BONUS;
        
        // Quality multiplier
        let base_reward = bandwidth_reward + routing_reward + uptime_bonus;
        let quality_multiplied = if self.connection_quality > 0.9 {
            ((base_reward as f64) * 1.5) as u64
        } else {
            base_reward
        };
        
        quality_multiplied
    }
}

impl Default for IspBypassWork {
    fn default() -> Self {
        Self::new()
    }
}
