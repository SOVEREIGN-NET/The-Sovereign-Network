//! Dynamic economic parameter adjustment based on network conditions
//! 
//! Implements algorithms to adjust economic parameters in response to
//! network utilization and performance metrics.

use anyhow::Result;
use crate::types::{NetworkStats, NetworkStatsExt};
use crate::wasm::logging::info;

/// Adjust base rates based on network utilization
pub fn adjust_rates_for_utilization(
    current_routing_rate: u64,
    current_storage_rate: u64,
    current_compute_rate: u64,
    network_stats: &NetworkStats,
) -> Result<(u64, u64, u64)> {
    let adjustment_multiplier = network_stats.get_reward_adjustment_multiplier();
    
    if adjustment_multiplier == 100 {
        // No adjustment needed
        return Ok((current_routing_rate, current_storage_rate, current_compute_rate));
    }
    
    let new_routing_rate = (current_routing_rate * adjustment_multiplier) / 100;
    let new_storage_rate = (current_storage_rate * adjustment_multiplier) / 100;
    let new_compute_rate = (current_compute_rate * adjustment_multiplier) / 100;
    
    info!(
        "Network utilization adjustment: {}% -> rates: routing={}, storage={}, compute={}",
        adjustment_multiplier, new_routing_rate, new_storage_rate, new_compute_rate
    );
    
    Ok((new_routing_rate, new_storage_rate, new_compute_rate))
}

/// Apply quality-based adjustments to economic parameters
pub fn adjust_for_network_quality(
    base_multiplier: f64,
    quality_multiplier: f64,
    network_stats: &NetworkStats,
) -> (f64, f64) {
    let quality_factor = network_stats.avg_quality;
    
    // Adjust quality multiplier based on network performance
    let adjusted_quality_multiplier = if quality_factor > 0.95 {
        quality_multiplier * 1.1 // Increase bonus for excellent network quality
    } else if quality_factor < 0.80 {
        quality_multiplier * 0.9 // Reduce bonus for poor network quality
    } else {
        quality_multiplier // No change for adequate quality
    };
    
    (base_multiplier, adjusted_quality_multiplier)
}

/// Calculate optimal reward rates based on network health
pub fn calculate_optimal_rates(
    base_routing_rate: u64,
    base_storage_rate: u64,
    base_compute_rate: u64,
    network_stats: &NetworkStats,
) -> Result<(u64, u64, u64)> {
    // Start with utilization-based adjustment
    let (mut routing_rate, mut storage_rate, mut compute_rate) = 
        adjust_rates_for_utilization(base_routing_rate, base_storage_rate, base_compute_rate, network_stats)?;
    
    // Apply additional health-based adjustments
    let health_score = network_stats.network_health_score();
    
    if health_score < 0.5 {
        // Poor network health - increase incentives to attract more participants
        routing_rate = (routing_rate * 110) / 100; // +10%
        storage_rate = (storage_rate * 110) / 100;
        compute_rate = (compute_rate * 110) / 100;
        
        info!("🏥 Poor network health ({:.2}), increasing incentives by 10%", health_score);
    } else if health_score > 0.9 {
        // Excellent network health - can reduce incentives slightly
        routing_rate = (routing_rate * 95) / 100; // -5%
        storage_rate = (storage_rate * 95) / 100;
        compute_rate = (compute_rate * 95) / 100;
        
        info!("✨ Excellent network health ({:.2}), optimizing incentives", health_score);
    }
    
    // Ensure minimum rates for network operation
    routing_rate = routing_rate.max(1);
    storage_rate = storage_rate.max(5);
    compute_rate = compute_rate.max(1);
    
    Ok((routing_rate, storage_rate, compute_rate))
}

/// Calculate parameter adjustment recommendations
pub fn get_adjustment_recommendations(network_stats: &NetworkStats) -> serde_json::Value {
    let utilization_status = if network_stats.is_high_utilization() {
        "high"
    } else if network_stats.is_low_utilization() {
        "low"
    } else {
        "optimal"
    };
    
    let quality_status = if network_stats.avg_quality > 0.95 {
        "excellent"
    } else if network_stats.avg_quality > 0.80 {
        "good"
    } else {
        "needs_improvement"
    };
    
    let health_score = network_stats.network_health_score();
    let adjustment_multiplier = network_stats.get_reward_adjustment_multiplier();
    
    serde_json::json!({
        "utilization_status": utilization_status,
        "utilization_percentage": network_stats.utilization * 100.0,
        "quality_status": quality_status,
        "quality_score": network_stats.avg_quality * 100.0,
        "health_score": health_score * 100.0,
        "recommended_adjustment": adjustment_multiplier,
        "adjustment_reason": format!(
            "Network utilization: {:.1}%, Quality: {:.1}%, Health: {:.1}%",
            network_stats.utilization * 100.0,
            network_stats.avg_quality * 100.0,
            health_score * 100.0
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NetworkStats;

    #[test]
    fn test_utilization_adjustment() {
        let mut stats = NetworkStats::new();
        stats.update_utilization(0.95); // High utilization
        
        let (new_routing, new_storage, new_compute) = 
            adjust_rates_for_utilization(100, 1000, 500, &stats).unwrap(); // Use larger base values
        
        // Should increase rates for high utilization
        assert!(new_routing > 100);
        assert!(new_storage > 1000);
        assert!(new_compute > 500);
    }

    #[test]
    fn test_quality_adjustment() {
        let mut stats = NetworkStats::new();
        stats.update_avg_quality(0.98); // Excellent quality
        
        let (base, quality) = adjust_for_network_quality(1.0, 0.1, &stats);
        assert_eq!(base, 1.0);
        assert!(quality > 0.1); // Should increase quality multiplier
    }

    #[test]
    fn test_optimal_rates_calculation() {
        let mut stats = NetworkStats::new();
        stats.update_utilization(0.7); // Normal utilization
        stats.update_avg_quality(0.9); // Good quality
        
        let (routing, storage, compute) = 
            calculate_optimal_rates(1, 10, 5, &stats).unwrap();
        
        assert!(routing >= 1);
        assert!(storage >= 5);
        assert!(compute >= 1);
    }
}
