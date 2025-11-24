//! Treasury balance calculations and fund allocation algorithms
//! 
//! Provides calculation interfaces for DAO treasury operations including
//! UBI distribution calculations, welfare fund allocation, and efficiency metrics.

use anyhow::Result;
use crate::treasury_economics::DaoTreasury;

/// Calculate optimal UBI distribution amount per citizen
pub fn calculate_optimal_ubi_per_citizen(treasury: &DaoTreasury, total_citizens: u64, target_monthly_ubi: u64) -> (u64, bool) {
    if total_citizens == 0 {
        return (0, false);
    }
    
    let required_total = target_monthly_ubi * total_citizens;
    let actual_per_citizen = treasury.calculate_ubi_per_citizen(total_citizens);
    let can_meet_target = treasury.ubi_allocated >= required_total;
    
    if can_meet_target {
        (target_monthly_ubi, true)
    } else {
        (actual_per_citizen, false)
    }
}

/// Calculate welfare funding efficiency score
pub fn calculate_welfare_efficiency(treasury: &DaoTreasury) -> f64 {
    if treasury.total_dao_fees_collected == 0 {
        return 1.0; // Perfect efficiency when no fees collected yet
    }
    
    let expected_welfare_distributed = (treasury.total_dao_fees_collected * crate::WELFARE_ALLOCATION_PERCENTAGE) / 100;
    
    if expected_welfare_distributed == 0 {
        return 1.0;
    }
    
    (treasury.total_welfare_distributed as f64 / expected_welfare_distributed as f64).min(1.0)
}

/// Calculate UBI distribution efficiency score  
pub fn calculate_ubi_efficiency(treasury: &DaoTreasury) -> f64 {
    if treasury.total_dao_fees_collected == 0 {
        return 1.0; // Perfect efficiency when no fees collected yet
    }
    
    let expected_ubi_distributed = (treasury.total_dao_fees_collected * crate::UBI_ALLOCATION_PERCENTAGE) / 100;
    
    if expected_ubi_distributed == 0 {
        return 1.0;
    }
    
    (treasury.total_ubi_distributed as f64 / expected_ubi_distributed as f64).min(1.0)
}

/// Calculate treasury sustainability metrics
pub fn calculate_treasury_sustainability(treasury: &DaoTreasury, monthly_burn_rate: u64) -> serde_json::Value {
    let total_allocated = treasury.ubi_allocated + treasury.welfare_allocated;
    
    let months_sustainable = if monthly_burn_rate > 0 {
        total_allocated / monthly_burn_rate
    } else {
        u64::MAX // Infinite sustainability with no burn
    };
    
    let allocation_ratio = if treasury.treasury_balance > 0 {
        (total_allocated as f64 / treasury.treasury_balance as f64) * 100.0
    } else {
        0.0
    };
    
    serde_json::json!({
        "months_sustainable": months_sustainable,
        "allocation_ratio_percent": allocation_ratio,
        "total_allocated": total_allocated,
        "monthly_burn_rate": monthly_burn_rate,
        "sustainability_status": if months_sustainable >= 12 { "healthy" } else if months_sustainable >= 6 { "moderate" } else { "concerning" }
    })
}

/// Calculate funding gap for target UBI amount
pub fn calculate_ubi_funding_gap(treasury: &DaoTreasury, total_citizens: u64, target_monthly_ubi: u64) -> Result<serde_json::Value> {
    if total_citizens == 0 {
        return Ok(serde_json::json!({
            "funding_gap": 0,
            "months_to_close_gap": 0,
            "current_coverage_percent": 100.0,
            "status": "no_citizens"
        }));
    }
    
    let required_total = target_monthly_ubi * total_citizens;
    let current_available = treasury.ubi_allocated;
    
    let funding_gap = if required_total > current_available {
        required_total - current_available
    } else {
        0
    };
    
    let coverage_percent = if required_total > 0 {
        (current_available as f64 / required_total as f64) * 100.0
    } else {
        100.0
    };
    
    // Estimate time to close gap based on recent fee collection rate
    let estimated_monthly_fees = if treasury.total_dao_fees_collected > 0 {
        treasury.total_dao_fees_collected / 12 // Rough monthly estimate
    } else {
        0
    };
    
    let estimated_monthly_ubi_allocation = (estimated_monthly_fees * crate::UBI_ALLOCATION_PERCENTAGE) / 100;
    
    let months_to_close_gap = if funding_gap > 0 && estimated_monthly_ubi_allocation > 0 {
        funding_gap / estimated_monthly_ubi_allocation
    } else {
        0
    };
    
    Ok(serde_json::json!({
        "funding_gap": funding_gap,
        "months_to_close_gap": months_to_close_gap,
        "current_coverage_percent": coverage_percent,
        "target_monthly_total": required_total,
        "current_available": current_available,
        "estimated_monthly_allocation": estimated_monthly_ubi_allocation,
        "status": if funding_gap == 0 { "fully_funded" } else if coverage_percent >= 50.0 { "partially_funded" } else { "underfunded" }
    }))
}

/// Calculate treasury balance projections
pub fn calculate_treasury_projections(treasury: &DaoTreasury, projected_monthly_fees: u64, months: u64) -> serde_json::Value {
    let mut projected_balance = treasury.treasury_balance;
    let mut projected_ubi_allocated = treasury.ubi_allocated;
    let mut projected_welfare_allocated = treasury.welfare_allocated;
    
    for _ in 0..months {
        let monthly_ubi_allocation = (projected_monthly_fees * crate::UBI_ALLOCATION_PERCENTAGE) / 100;
        let monthly_welfare_allocation = (projected_monthly_fees * crate::WELFARE_ALLOCATION_PERCENTAGE) / 100;
        
        projected_balance += projected_monthly_fees;
        projected_ubi_allocated += monthly_ubi_allocation;
        projected_welfare_allocated += monthly_welfare_allocation;
    }
    
    serde_json::json!({
        "projected_balance": projected_balance,
        "projected_ubi_allocated": projected_ubi_allocated,
        "projected_welfare_allocated": projected_welfare_allocated,
        "projection_months": months,
        "monthly_fee_assumption": projected_monthly_fees,
        "total_projected_fees": projected_monthly_fees * months
    })
}
