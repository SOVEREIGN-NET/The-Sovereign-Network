//! Testing utilities and helpers

use crate::types::*;

/// Create test transaction with specified parameters
pub fn create_test_transaction(
    amount: u64,
    transaction_type: TransactionType,
    priority: Priority,
) -> crate::transactions::Transaction {
    let from = [1u8; 32]; // Test address
    let to = [2u8; 32];   // Test address
    
    crate::transactions::Transaction::new(from, to, amount, transaction_type.clone(), 250, priority)
        .unwrap_or_else(|_| {
            // Fallback: create transaction manually if new() fails
            crate::transactions::Transaction {
                tx_id: [0u8; 32],
                from,
                to,
                amount,
                base_fee: 100,
                dao_fee: calculate_dao_fee(amount),
                total_fee: 100 + calculate_dao_fee(amount),
                tx_type: transaction_type,
                timestamp: current_timestamp(),
                block_height: 0,
                dao_fee_proof: None,
            }
        })
}

/// Generate random u64 for testing
pub fn rand_u64() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let timestamp = current_timestamp();
    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    hasher.finish()
}

/// Get current timestamp for testing
pub fn current_timestamp() -> u64 {
    #[cfg(feature = "wasm")]
    {
        crate::wasm::compatibility::current_timestamp().unwrap_or(0)
    }
    #[cfg(not(feature = "wasm"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Calculate DAO fee for testing
pub fn calculate_dao_fee(amount: u64) -> u64 {
    (amount as f64 * 0.02) as u64 // 2% DAO fee
}

/// Generate DAO proof for testing
pub fn generate_dao_proof(amount: u64) -> String {
    format!("dao_proof_{}", calculate_dao_fee(amount))
}

/// Create test work metrics
pub fn create_test_work_metrics() -> WorkMetrics {
    WorkMetrics {
        routing_work: 1000,
        storage_work: 500,
        compute_work: 200,
        quality_score: 0.95,
        uptime_hours: 24,
    }
}

/// Create test network stats
pub fn create_test_network_stats() -> NetworkStats {
    NetworkStats {
        utilization: 0.75,
        avg_quality: 0.85,
        total_nodes: 1000,
        total_transactions: 50000,
    }
}

/// Assert economic values are within acceptable range
pub fn assert_economic_range(value: u64, min: u64, max: u64, description: &str) {
    assert!(
        value >= min && value <= max,
        "{} value {} is outside acceptable range [{}, {}]",
        description, value, min, max
    );
}

/// Assert percentage values are valid
pub fn assert_valid_percentage(value: f64, description: &str) {
    assert!(
        value >= 0.0 && value <= 1.0,
        "{} percentage {} is outside valid range [0.0, 1.0]",
        description, value
    );
}
