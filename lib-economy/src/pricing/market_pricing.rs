//! Market-based pricing mechanisms

/// Calculate market price based on trading activity
pub fn calculate_market_price(recent_trades: &[(u64, u64)]) -> Option<u64> {
    if recent_trades.is_empty() {
        return None;
    }
    
    let total_value: u64 = recent_trades.iter().map(|(price, amount)| price * amount).sum();
    let total_amount: u64 = recent_trades.iter().map(|(_, amount)| amount).sum();
    
    if total_amount == 0 {
        None
    } else {
        Some(total_value / total_amount)
    }
}

/// Calculate price volatility
pub fn calculate_volatility(prices: &[u64]) -> f64 {
    if prices.len() < 2 {
        return 0.0;
    }
    
    let mean = prices.iter().sum::<u64>() as f64 / prices.len() as f64;
    let variance = prices.iter()
        .map(|&price| {
            let diff = price as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / prices.len() as f64;
    
    variance.sqrt()
}

/// Anti-speculation pricing adjustment
pub fn apply_anti_speculation_adjustment(base_price: u64, speculation_factor: f64) -> u64 {
    // Reduce price impact of speculation
    let adjusted_factor = speculation_factor * 0.1; // Limit speculation impact to 10%
    let adjustment = 1.0 + adjusted_factor;
    (base_price as f64 * adjustment) as u64
}
