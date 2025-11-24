//! Priority-based fee calculation with QoS multipliers
//! 
//! Implements quality-of-service style pricing for network transactions.

use crate::types::Priority;

/// Calculate priority-based fee multiplier
pub fn get_priority_multiplier(priority: Priority) -> f64 {
    priority.fee_multiplier()
}

/// Calculate priority-adjusted fee
pub fn calculate_priority_fee(base_fee: u64, priority: Priority) -> u64 {
    let multiplier = get_priority_multiplier(priority);
    ((base_fee as f64) * multiplier) as u64
}

/// Get priority description and cost impact
pub fn get_priority_info(priority: Priority) -> serde_json::Value {
    let multiplier = get_priority_multiplier(priority);
    let cost_impact = if multiplier > 1.0 {
        format!("+{}% cost", ((multiplier - 1.0) * 100.0) as u64)
    } else if multiplier < 1.0 {
        format!("-{}% cost", ((1.0 - multiplier) * 100.0) as u64)
    } else {
        "Standard cost".to_string()
    };
    
    serde_json::json!({
        "priority": format!("{:?}", priority),
        "description": priority.description(),
        "multiplier": multiplier,
        "cost_impact": cost_impact,
        "processing_order": priority.processing_order()
    })
}

/// Calculate total fees with priority adjustment
pub fn calculate_priority_total_fees(
    base_network_fee: u64,
    dao_fee: u64,
    priority: Priority,
) -> (u64, u64, u64) {
    let adjusted_network_fee = calculate_priority_fee(base_network_fee, priority);
    let total_fee = adjusted_network_fee + dao_fee; // DAO fee not affected by priority
    
    (adjusted_network_fee, dao_fee, total_fee)
}
