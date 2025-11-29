//! ISP cost savings calculation and tracking
//! 
//! Tracks and calculates the economic value created by replacing traditional
//! ISP services with the ZHTP mesh network.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::IspBypassWork;
use crate::wasm::logging::info;

/// Cost savings tracking structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSavings {
    /// Total USD equivalent savings from 
    pub total_usd_savings: u64,
    /// Average monthly savings per user
    pub avg_monthly_savings_per_user: u64,
    /// Number of users benefiting from cost savings
    pub users_benefiting: u64,
    /// Bandwidth cost savings ($/GB)
    pub bandwidth_cost_savings: f64,
    /// Infrastructure cost savings ($/month)
    pub infrastructure_cost_savings: u64,
}

impl CostSavings {
    /// Create new cost savings tracker
    pub fn new() -> Self {
        CostSavings {
            total_usd_savings: 0,
            avg_monthly_savings_per_user: 50, // Estimated $50/month ISP cost
            users_benefiting: 0,
            bandwidth_cost_savings: 0.10, // $0.10 per GB (typical ISP overage cost)
            infrastructure_cost_savings: 0,
        }
    }
    
    /// Update cost savings from  work
    pub fn update_from_work(&mut self, work: &IspBypassWork) -> Result<()> {
        // Calculate bandwidth cost savings (cost per GB avoided by users)
        let bandwidth_savings = (work.bandwidth_shared_gb as f64) * self.bandwidth_cost_savings;
        
        // Calculate infrastructure cost savings (estimated ISP profit margin avoided)
        let infrastructure_savings = work.users_served * 30; // $30/month ISP profit per user
        
        // Update totals including calculated bandwidth savings
        self.total_usd_savings += work.cost_savings_provided + bandwidth_savings as u64;
        self.users_benefiting = work.users_served;
        self.infrastructure_cost_savings += infrastructure_savings;
        
        // Update average savings per user
        if self.users_benefiting > 0 {
            self.avg_monthly_savings_per_user = self.total_usd_savings / self.users_benefiting;
        }
        
        info!(
            "Cost savings updated: {} users save avg ${}/month, total ${} saved",
            self.users_benefiting, self.avg_monthly_savings_per_user, self.total_usd_savings
        );
        
        Ok(())
    }
    
    /// Calculate potential cost savings for a region
    pub fn calculate_regional_impact(
        population: u64,
        avg_isp_cost: u64,
        adoption_rate: f64,
    ) -> RegionalImpact {
        let users_adopting = ((population as f64) * adoption_rate) as u64;
        let monthly_savings = users_adopting * avg_isp_cost;
        let annual_savings = monthly_savings * 12;
        
        RegionalImpact {
            population,
            users_adopting,
            avg_isp_cost,
            adoption_rate,
            monthly_savings,
            annual_savings,
        }
    }
    
    /// Get cost savings statistics
    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_usd_savings": self.total_usd_savings,
            "avg_monthly_savings_per_user": self.avg_monthly_savings_per_user,
            "users_benefiting": self.users_benefiting,
            "bandwidth_cost_savings_per_gb": self.bandwidth_cost_savings,
            "infrastructure_cost_savings": self.infrastructure_cost_savings,
            "economic_impact": {
                "description": "Cost savings from ISP replacement",
                "methodology": "Based on typical ISP pricing and profit margins"
            }
        })
    }
}

/// Regional economic impact calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalImpact {
    /// Total population in region
    pub population: u64,
    /// Number of users adopting ZHTP
    pub users_adopting: u64,
    /// Average ISP cost in region ($/month)
    pub avg_isp_cost: u64,
    /// Adoption rate (0.0-1.0)
    pub adoption_rate: f64,
    /// Monthly cost savings for region
    pub monthly_savings: u64,
    /// Annual cost savings for region
    pub annual_savings: u64,
}

impl RegionalImpact {
    /// Get regional impact summary
    pub fn get_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "population": self.population,
            "users_adopting": self.users_adopting,
            "adoption_percentage": self.adoption_rate * 100.0,
            "avg_isp_cost_monthly": self.avg_isp_cost,
            "total_monthly_savings": self.monthly_savings,
            "total_annual_savings": self.annual_savings,
            "savings_per_capita": if self.population > 0 { 
                self.annual_savings / self.population 
            } else { 0 }
        })
    }
}

impl Default for CostSavings {
    fn default() -> Self {
        Self::new()
    }
}
