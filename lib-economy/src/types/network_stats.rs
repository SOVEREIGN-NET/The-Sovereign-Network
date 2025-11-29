//! Network statistics for economic parameter adjustment
//! 
//! Defines structures for tracking network performance and utilization
//! to enable dynamic economic parameter adjustments.

use serde::{Serialize, Deserialize};

/// Network statistics for economic parameter adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Network utilization percentage (0.0-1.0)
    pub utilization: f64,
    /// Average service quality across the network (0.0-1.0)
    pub avg_quality: f64,
    /// Total number of active nodes
    pub total_nodes: u64,
    /// Total number of transactions processed
    pub total_transactions: u64,
}

impl NetworkStats {
    /// Create new network statistics
    pub fn new() -> Self {
        NetworkStats {
            utilization: 0.0,
            avg_quality: 0.0,
            total_nodes: 0,
            total_transactions: 0,
        }
    }
    
    /// Update utilization percentage
    pub fn update_utilization(&mut self, utilization: f64) {
        if utilization.is_nan() {
            // Preserve NaN for debugging purposes
            self.utilization = utilization;
        } else if utilization.is_infinite() {
            // Handle infinity cases
            if utilization.is_sign_positive() {
                self.utilization = 1.0; // Positive infinity -> max utilization
            } else {
                self.utilization = 0.0; // Negative infinity -> min utilization
            }
        } else {
            // Clamp valid values between 0.0 and 1.0
            self.utilization = utilization.max(0.0).min(1.0);
        }
    }
    
    /// Update average quality
    pub fn update_avg_quality(&mut self, quality: f64) {
        self.avg_quality = quality.max(0.0).min(1.0);
    }
    
    /// Set total nodes
    pub fn set_total_nodes(&mut self, nodes: u64) {
        self.total_nodes = nodes;
    }
    
    /// Add transactions
    pub fn add_transactions(&mut self, count: u64) {
        self.total_transactions += count;
    }
    
    /// Check if network is highly utilized
    pub fn is_high_utilization(&self) -> bool {
        self.utilization > crate::HIGH_UTILIZATION_THRESHOLD
    }
    
    /// Check if network is under-utilized
    pub fn is_low_utilization(&self) -> bool {
        self.utilization < crate::LOW_UTILIZATION_THRESHOLD
    }
    
    /// Get recommended adjustment multiplier for rewards
    pub fn get_reward_adjustment_multiplier(&self) -> u64 {
        if self.is_high_utilization() {
            crate::HIGH_UTILIZATION_ADJUSTMENT // +5%
        } else if self.is_low_utilization() {
            crate::LOW_UTILIZATION_ADJUSTMENT // -2%
        } else {
            100 // No adjustment
        }
    }
    
    /// Calculate network health score (0.0-1.0)
    pub fn network_health_score(&self) -> f64 {
        // Handle NaN values
        if self.utilization.is_nan() || self.avg_quality.is_nan() {
            return 0.0; // Conservative default for invalid data
        }
        
        // Combine utilization and quality for health score
        let utilization_factor = if self.utilization > 0.8 {
            1.0 - (self.utilization - 0.8) / 0.2 // Penalty for over-utilization
        } else {
            self.utilization / 0.8 // Reward for good utilization
        };
        
        let quality_factor = self.avg_quality;
        
        let health = (utilization_factor + quality_factor) / 2.0;
        
        // Ensure result is in valid range
        health.max(0.0).min(1.0)
    }
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self::new()
    }
}
