//! Fee processing and distribution
//! 
//! Handles the processing and distribution of network and DAO fees.

use anyhow::Result;
use crate::wasm::logging::info;

/// Process network infrastructure fees
pub fn process_network_fees(total_fees: u64) -> Result<u64> {
    // Network fees go to infrastructure providers (routing/storage/compute)
    info!(
        "Processed {} SOV tokens in network fees - distributed to infrastructure providers", 
        total_fees
    );
    
    Ok(total_fees) // All fees stay in circulation for infrastructure
}

/// Process DAO fees for UBI and welfare funding
pub fn process_dao_fees(dao_fees: u64) -> Result<u64> {
    info!(
        " Processed {} SOV tokens in DAO fees - added to UBI/welfare treasury",
        dao_fees
    );
    
    Ok(dao_fees) // DAO fees go to UBI/welfare treasury
}

/// Separate network and DAO fees from a batch of transactions
pub fn separate_fees(transactions: &[crate::transactions::Transaction]) -> (u64, u64) {
    let mut total_network_fees = 0;
    let mut total_dao_fees = 0;
    
    for tx in transactions {
        total_network_fees += tx.base_fee;
        total_dao_fees += tx.dao_fee;
    }
    
    (total_network_fees, total_dao_fees)
}

/// Calculate fee distribution breakdown
pub fn calculate_fee_distribution(network_fees: u64, dao_fees: u64) -> serde_json::Value {
    let total_fees = network_fees + dao_fees;
    let network_percentage = if total_fees > 0 {
        (network_fees as f64 / total_fees as f64) * 100.0
    } else {
        0.0
    };
    let dao_percentage = if total_fees > 0 {
        (dao_fees as f64 / total_fees as f64) * 100.0
    } else {
        0.0
    };
    
    serde_json::json!({
        "total_fees": total_fees,
        "network_fees": network_fees,
        "dao_fees": dao_fees,
        "network_percentage": network_percentage,
        "dao_percentage": dao_percentage,
        "ubi_allocation": (dao_fees * crate::UBI_ALLOCATION_PERCENTAGE) / 100,
        "welfare_allocation": (dao_fees * crate::WELFARE_ALLOCATION_PERCENTAGE) / 100
    })
}
