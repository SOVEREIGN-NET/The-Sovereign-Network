//! Dynamic pricing based on network conditions
use crate::types::Priority;

/// Calculate dynamic price based on network congestion and priority
pub fn calculate_dynamic_price(base_price: u64, network_congestion: f64, priority: Priority) -> u64 {
    let congestion_multiplier = 1.0 + network_congestion;
    
    let priority_multiplier = match priority {
        Priority::Low => 0.5,      // 50% discount for low priority
        Priority::Normal => 1.0,   // Standard pricing
        Priority::High => 2.0,     // 2x for high priority
        Priority::Urgent => 5.0,   // 5x for urgent priority
    };
    
    let final_price = base_price as f64 * congestion_multiplier * priority_multiplier;
    final_price as u64
}

/// Calculate price adjustment based on supply and demand
pub fn calculate_price_adjustment(supply: u64, demand: u64) -> f64 {
    if supply == 0 {
        return 10.0; // Maximum adjustment when no supply
    }
    
    let ratio = demand as f64 / supply as f64;
    
    // Logarithmic adjustment to prevent extreme price swings
    if ratio > 1.0 {
        (ratio.ln() + 1.0).min(10.0) // Cap at 10x
    } else {
        (1.0 / (ratio.ln() + 1.0)).max(0.1) // Floor at 0.1x
    }
}

/// Get pricing for infrastructure services
pub fn get_infrastructure_pricing() -> (u64, u64, u64) {
    (
        1,   // 1 SOV per MB routing
        10,  // 10 SOV per GB storage  
        100, // 100 SOV per GB bandwidth
    )
}
