//! Priority levels for transaction processing (QoS)
//! 
//! Defines quality-of-service levels for network transactions with corresponding
//! fee multipliers to manage network congestion and provide premium services.

use serde::{Serialize, Deserialize};

/// Priority levels for transaction processing with QoS-style pricing
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Priority {
    /// Background processing - 50% discount for non-urgent transactions
    Low,
    /// Standard priority - normal network processing
    Normal,
    /// Premium service - 50% premium for faster processing
    High,
    /// Emergency priority - 100% premium for critical transactions
    Urgent,
}

impl Priority {
    /// Get the fee multiplier for this priority level
    pub fn fee_multiplier(&self) -> f64 {
        match self {
            Priority::Low => 0.5,    // 50% discount for background traffic
            Priority::Normal => 1.0, // Standard network priority
            Priority::High => 1.5,   // Premium traffic (50% premium)
            Priority::Urgent => 2.0, // Emergency traffic (100% premium)
        }
    }
    
    /// Get the processing order (lower number = higher priority)
    pub fn processing_order(&self) -> u8 {
        match self {
            Priority::Urgent => 0,
            Priority::High => 1,
            Priority::Normal => 2,
            Priority::Low => 3,
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Priority::Low => "Background processing",
            Priority::Normal => "Standard priority",
            Priority::High => "Premium service",
            Priority::Urgent => "Emergency priority",
        }
    }
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}
