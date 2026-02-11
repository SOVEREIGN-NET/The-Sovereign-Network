//! Quality bonus calculation for exceptional service provision
//! 
//! Implements quality-based bonuses for infrastructure providers who
//! maintain high service quality, similar to SLA bonuses in enterprise contracts.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::WorkMetrics;
use crate::models::EconomicModel;
use crate::wasm::logging::info;

/// Quality bonus structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityBonus {
    /// Quality score that earned the bonus (0.0-1.0)
    pub quality_score: f64,
    /// Uptime percentage that earned the bonus
    pub uptime_percentage: f64,
    /// Quality bonus amount in SOV
    pub quality_bonus_amount: u64,
    /// Uptime bonus amount in SOV
    pub uptime_bonus_amount: u64,
    /// Total bonus amount
    pub total_bonus: u64,
}

impl QualityBonus {
    /// Calculate quality and uptime bonuses based on work metrics
    pub fn calculate(work: &WorkMetrics, base_reward: u64, model: &EconomicModel) -> Result<Self> {
        // MINIMAL BONUSES (infrastructure is expected to be reliable)
        let quality_bonus_amount = if work.quality_score > crate::QUALITY_BONUS_THRESHOLD {
            // 10% bonus for exceptional quality (>95%)
            ((base_reward as f64) * model.quality_multiplier) as u64
        } else {
            0 // No bonus unless exceptional
        };
        
        let uptime_bonus_amount = if work.uptime_hours >= crate::UPTIME_BONUS_THRESHOLD { // 99%+ uptime (23+ hours)
            // 5% bonus for near-perfect uptime
            ((base_reward as f64) * model.uptime_multiplier) as u64
        } else {
            0 // No bonus unless near-perfect uptime
        };
        
        let total_bonus = quality_bonus_amount + uptime_bonus_amount;
        
        // Calculate uptime percentage for display
        let uptime_percentage = if work.uptime_hours >= 24 {
            100.0 // Cap at 100%
        } else {
            (work.uptime_hours as f64 / 24.0) * 100.0
        };
        
        if total_bonus > 0 {
            info!(
                "⭐ Quality bonus earned: quality={:.1}% ({}SOV), uptime={:.1}% ({}SOV), total={}SOV",
                work.quality_score * 100.0, quality_bonus_amount,
                uptime_percentage, uptime_bonus_amount,
                total_bonus
            );
        }
        
        Ok(QualityBonus {
            quality_score: work.quality_score,
            uptime_percentage,
            quality_bonus_amount,
            uptime_bonus_amount,
            total_bonus,
        })
    }
    
    /// Calculate quality bonus for  work
    pub fn calculate_isp_bypass_quality(
        connection_quality: f64,
        uptime_hours: u64,
        base_reward: u64,
    ) -> Result<Self> {
        //  quality bonuses (like premium ISP service tiers)
        let quality_bonus_amount = if connection_quality > 0.95 {
            // 15% bonus for excellent connection quality
            (base_reward * 15) / 100
        } else if connection_quality > 0.90 {
            // 10% bonus for very good connection quality
            (base_reward * 10) / 100
        } else if connection_quality > 0.80 {
            // 5% bonus for good connection quality
            (base_reward * 5) / 100
        } else {
            0 // No bonus for basic quality
        };
        
        let uptime_bonus_amount = if uptime_hours >= 23 { // 95%+ uptime
            // 10% bonus for excellent uptime
            (base_reward * 10) / 100
        } else if uptime_hours >= 20 { // 83%+ uptime
            // 5% bonus for good uptime
            (base_reward * 5) / 100
        } else {
            0 // No bonus for poor uptime
        };
        
        let total_bonus = quality_bonus_amount + uptime_bonus_amount;
        let uptime_percentage = (uptime_hours as f64 / 24.0) * 100.0;
        
        if total_bonus > 0 {
            info!(
                " quality bonus: connection={:.1}% ({}SOV), uptime={:.1}% ({}SOV), total={}SOV",
                connection_quality * 100.0, quality_bonus_amount,
                uptime_percentage, uptime_bonus_amount,
                total_bonus
            );
        }
        
        Ok(QualityBonus {
            quality_score: connection_quality,
            uptime_percentage,
            quality_bonus_amount,
            uptime_bonus_amount,
            total_bonus,
        })
    }
    
    /// Check if quality meets minimum standards
    pub fn meets_minimum_standards(quality_score: f64, uptime_hours: u64) -> bool {
        // Minimum standards for infrastructure services
        quality_score >= 0.8 && uptime_hours >= 12 // 50% uptime minimum
    }
    
    /// Get quality tier description
    pub fn get_quality_tier(&self) -> &'static str {
        if self.quality_score >= 0.95 {
            "Exceptional"
        } else if self.quality_score >= 0.90 {
            "Excellent" 
        } else if self.quality_score >= 0.85 {
            "Very Good"
        } else if self.quality_score >= 0.80 {
            "Good"
        } else {
            "Basic"
        }
    }
    
    /// Get uptime tier description
    pub fn get_uptime_tier(&self) -> &'static str {
        if self.uptime_percentage >= 99.0 {
            "Enterprise Grade"
        } else if self.uptime_percentage >= 95.0 {
            "High Availability"
        } else if self.uptime_percentage >= 90.0 {
            "Standard"
        } else if self.uptime_percentage >= 80.0 {
            "Basic"
        } else {
            "Poor"
        }
    }
    
    /// Get detailed bonus breakdown
    pub fn get_breakdown(&self) -> serde_json::Value {
        serde_json::json!({
            "quality_score": self.quality_score,
            "quality_percentage": self.quality_score * 100.0,
            "quality_tier": self.get_quality_tier(),
            "quality_bonus_zhtp": self.quality_bonus_amount,
            "uptime_percentage": self.uptime_percentage,
            "uptime_tier": self.get_uptime_tier(),
            "uptime_bonus_zhtp": self.uptime_bonus_amount,
            "total_bonus_zhtp": self.total_bonus,
            "bonus_earned": self.total_bonus > 0
        })
    }
}
