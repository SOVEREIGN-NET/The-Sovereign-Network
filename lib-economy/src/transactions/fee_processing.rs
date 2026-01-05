//! Fee processing and distribution
//! 
//! Handles the processing and distribution of network and DAO fees.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::wasm::logging::info;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DaoFeeDistribution {
    pub ubi: u64,
    pub sector_daos: u64,
    pub emergency_reserve: u64,
    pub dev_grants: u64,
}

impl DaoFeeDistribution {
    pub fn total(&self) -> u64 {
        self.ubi
            .saturating_add(self.sector_daos)
            .saturating_add(self.emergency_reserve)
            .saturating_add(self.dev_grants)
    }
}

/// Process network infrastructure fees
pub fn process_network_fees(total_fees: u64) -> Result<u64> {
    // Network fees go to infrastructure providers (routing/storage/compute)
    info!(
        "Processed {} SOV tokens in network fees - distributed to infrastructure providers", 
        total_fees
    );
    
    Ok(total_fees) // All fees stay in circulation for infrastructure
}

/// Process DAO fees for UBI and DAO allocations
pub fn process_dao_fees(dao_fees: u64) -> Result<u64> {
    info!(
        " Processed {} SOV tokens in DAO fees - added to treasury allocations",
        dao_fees
    );
    
    Ok(dao_fees) // DAO fees go to UBI/welfare treasury
}

/// Calculate DAO fee distribution breakdown (single source of truth for allocation)
pub fn calculate_dao_fee_distribution(dao_fees: u64) -> DaoFeeDistribution {
    let ubi_allocation = (dao_fees * crate::UBI_ALLOCATION_PERCENTAGE) / 100;
    let dao_allocation = (dao_fees * crate::DAO_ALLOCATION_PERCENTAGE) / 100;
    let emergency_allocation = (dao_fees * crate::EMERGENCY_ALLOCATION_PERCENTAGE) / 100;
    let dev_grant_allocation = (dao_fees * crate::DEV_GRANT_ALLOCATION_PERCENTAGE) / 100;

    let allocated = ubi_allocation
        .saturating_add(dao_allocation)
        .saturating_add(emergency_allocation)
        .saturating_add(dev_grant_allocation);
    let remainder = dao_fees.saturating_sub(allocated);

    DaoFeeDistribution {
        ubi: ubi_allocation,
        sector_daos: dao_allocation,
        emergency_reserve: emergency_allocation,
        dev_grants: dev_grant_allocation.saturating_add(remainder),
    }
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

    let dao_allocation = calculate_dao_fee_distribution(dao_fees);

    serde_json::json!({
        "total_fees": total_fees,
        "network_fees": network_fees,
        "dao_fees": dao_fees,
        "network_percentage": network_percentage,
        "dao_percentage": dao_percentage,
        "allocation": {
            "ubi": dao_allocation.ubi,
            "sector_daos": dao_allocation.sector_daos,
            "emergency_reserve": dao_allocation.emergency_reserve,
            "dev_grants": dao_allocation.dev_grants
        },
        "allocation_percentages": {
            "ubi": crate::UBI_ALLOCATION_PERCENTAGE,
            "sector_daos": crate::DAO_ALLOCATION_PERCENTAGE,
            "emergency_reserve": crate::EMERGENCY_ALLOCATION_PERCENTAGE,
            "dev_grants": crate::DEV_GRANT_ALLOCATION_PERCENTAGE
        }
    })
}
