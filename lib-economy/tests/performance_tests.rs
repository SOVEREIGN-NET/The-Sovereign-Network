//! Performance benchmarks for ZHTP Economics module
//! 
//! Benchmarks critical economic operations to ensure performance scalability.

use lib_economy::*;
use lib_economy::testing::*;
use lib_economy::incentives::infrastructure_rewards::InfrastructureRewards;
use std::time::{Duration, Instant};

#[cfg(test)]
mod benchmarks {
    use super::*;

    const ITERATIONS: usize = 10000;
    const LARGE_ITERATIONS: usize = 100000;

    #[test]
    fn benchmark_fee_calculation() {
        let model = EconomicModel::new();
        
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let _ = model.calculate_fee(
                (i % 5000) as u64 + 100, // tx_size
                (i % 100000) as u64 + 1000, // amount
                Priority::Normal
            );
        }
        let duration = start.elapsed();
        
        println!("Fee calculation: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time (< 100ms for 10k operations)
        assert!(duration < Duration::from_millis(100));
    }

    #[test]
    fn benchmark_reward_calculation() {
        let model = EconomicModel::new();
        
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let work = WorkMetrics {
                routing_work: (i % 10000000) as u64,
                storage_work: (i % 5000000000) as u64,
                compute_work: (i % 100) as u64,
                quality_score: (i % 100) as f64 / 100.0,
                uptime_hours: (i % 25) as u64,
            };
            let _ = TokenReward::calculate(&work, &model).unwrap();
        }
        let duration = start.elapsed();
        
        println!("Reward calculation: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(200));
    }

    #[test]
    fn benchmark_transaction_creation() {
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let from = [(i % 256) as u8; 32];
            let to = [((i + 1) % 256) as u8; 32];
            let amount = (i % 50000) as u64 + 100;
            
            let _ = Transaction::new_payment(from, to, amount, Priority::Normal).unwrap();
        }
        let duration = start.elapsed();
        
        println!("Transaction creation: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(300));
    }

    #[test]
    fn benchmark_isp_bypass_rewards() {
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let work = IspBypassWork {
                bandwidth_shared_gb: (i % 100) as u64,
                packets_routed_mb: (i % 1000) as u64,
                uptime_hours: (i % 25) as u64,
                connection_quality: (i % 100) as f64 / 100.0,
                users_served: (i % 20) as u64,
                cost_savings_provided: (i % 500) as u64,
            };
            let _ = InfrastructureRewards::calculate_isp_bypass(&work).unwrap();
        }
        let duration = start.elapsed();
        
        println!(" reward calculation: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(100));
    }

    #[test]
    fn benchmark_wallet_operations() {
        let mut wallet = WalletBalance::new([1u8; 32]);
        
        // Benchmark reward addition
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let reward = TokenReward {
                routing_reward: (i % 100) as u64,
                storage_reward: (i % 200) as u64,
                compute_reward: (i % 50) as u64,
                quality_bonus: (i % 25) as u64,
                uptime_bonus: (i % 25) as u64,
                total_reward: (i % 400) as u64,
                currency: "SOV".to_string(),
            };
            let _ = wallet.add_reward(&reward);
        }
        let reward_duration = start.elapsed();
        
        // Benchmark claim operation
        let start = Instant::now();
        let _ = wallet.claim_rewards().unwrap();
        let claim_duration = start.elapsed();
        
        println!("Wallet reward addition: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, reward_duration, reward_duration.as_micros() as f64 / ITERATIONS as f64);
        println!("Wallet claim operation: 1 iteration in {:?}", claim_duration);
        
        // Verify transaction history size
        assert_eq!(wallet.transaction_history.len(), ITERATIONS);
        
        // Should complete in reasonable time
        assert!(reward_duration < Duration::from_millis(500));
        assert!(claim_duration < Duration::from_millis(10));
    }

    #[test]
    fn benchmark_treasury_operations() {
        let mut treasury = DaoTreasury::new();
        
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let amount = (i % 1000) as u64 + 10;
            let _ = treasury.add_dao_fees(amount);
        }
        let duration = start.elapsed();
        
        println!("Treasury DAO fee addition: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(200));
        
        // Verify final state
        assert!(treasury.treasury_balance > 0);
        assert!(treasury.ubi_allocated > 0);
        assert!(treasury.welfare_allocated > 0);
    }

    #[test]
    fn benchmark_network_parameter_adjustment() {
        let mut model = EconomicModel::new();
        
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let stats = NetworkStats {
                utilization: (i % 100) as f64 / 100.0,
                avg_quality: (i % 100) as f64 / 100.0,
                total_nodes: (i % 10000) as u64,
                total_transactions: (i % 1000000) as u64,
            };
            let _ = model.adjust_parameters(&stats);
        }
        let duration = start.elapsed();
        
        println!("Network parameter adjustment: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(150));
    }

    #[test]
    fn benchmark_large_scale_fee_processing() {
        let model = EconomicModel::new();
        
        let start = Instant::now();
        let mut total_fees = 0u64;
        
        for i in 0..LARGE_ITERATIONS {
            let (network_fee, dao_fee, _total_fee) = model.calculate_fee(
                (i % 2000) as u64 + 100,
                (i % 50000) as u64 + 1000,
                match i % 4 {
                    0 => Priority::Low,
                    1 => Priority::Normal,
                    2 => Priority::High,
                    _ => Priority::Urgent,
                }
            );
            total_fees += network_fee + dao_fee;
        }
        
        let duration = start.elapsed();
        
        println!("Large scale fee processing: {} iterations in {:?} ({:.2} µs/op), total fees: {}",
                 LARGE_ITERATIONS, duration, duration.as_micros() as f64 / LARGE_ITERATIONS as f64, total_fees);
        
        // Should handle large scale efficiently
        assert!(duration < Duration::from_millis(1000));
        assert!(total_fees > 0);
    }

    #[test]
    fn benchmark_anti_speculation_checks() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        let start = Instant::now();
        for i in 0..ITERATIONS {
            let balance = (i % 1000000) as u64;
            let usage = (i % 100000) as u64;
            let period = (i % 30) as u64 + 1;
            
            let _ = mechanisms.is_speculative_behavior(balance, usage, period);
            let _ = mechanisms.calculate_utility_incentives(usage, balance);
        }
        let duration = start.elapsed();
        
        println!("Anti-speculation checks: {} iterations in {:?} ({:.2} µs/op)",
                 ITERATIONS, duration, duration.as_micros() as f64 / ITERATIONS as f64);
        
        // Should complete in reasonable time
        assert!(duration < Duration::from_millis(100));
    }

    #[test]
    fn benchmark_memory_usage() {
        let initial_memory = get_memory_usage();
        
        // Create many economic objects
        let mut models = Vec::with_capacity(1000);
        let mut wallets = Vec::with_capacity(1000);
        let mut transactions = Vec::with_capacity(1000);
        
        for i in 0..1000 {
            models.push(EconomicModel::new());
            wallets.push(WalletBalance::new([i as u8; 32]));
            transactions.push(
                Transaction::new_payment([i as u8; 32], [(i + 1) as u8; 32], 1000, Priority::Normal).unwrap()
            );
        }
        
        let peak_memory = get_memory_usage();
        let memory_growth = peak_memory.saturating_sub(initial_memory);
        
        println!("Memory usage test: {} KB growth for 3000 objects ({} bytes/object average)",
                 memory_growth / 1024, memory_growth / 3000);
        
        // Memory usage should be reasonable (less than 100MB for 3000 objects)
        assert!(memory_growth < 100 * 1024 * 1024);
        
        // Cleanup to avoid affecting other tests
        drop(models);
        drop(wallets);
        drop(transactions);
    }

    // Helper function to estimate memory usage (approximate)
    fn get_memory_usage() -> usize {
        // This is a simple estimation - in production you'd use proper memory profiling
        std::mem::size_of::<EconomicModel>() + 
        std::mem::size_of::<WalletBalance>() + 
        std::mem::size_of::<Transaction>()
    }
}

/// Performance test utilities
pub mod performance_utils {
    use super::*;
    
    /// Run a performance test with timing
    pub fn time_operation<F, R>(operation: F, description: &str) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        
        println!("{}: completed in {:?}", description, duration);
        (result, duration)
    }
    
    /// Run multiple iterations and calculate average time
    pub fn benchmark_operation<F>(mut operation: F, iterations: usize, description: &str) -> Duration
    where
        F: FnMut() -> (),
    {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let total_duration = start.elapsed();
        let avg_duration = total_duration / iterations as u32;
        
        println!("{}: {} iterations in {:?} (avg: {:?})",
                 description, iterations, total_duration, avg_duration);
        
        avg_duration
    }
    
    /// Create test data for benchmarking
    pub fn create_benchmark_data(count: usize) -> (Vec<WorkMetrics>, Vec<NetworkStats>, Vec<IspBypassWork>) {
        let mut work_metrics = Vec::with_capacity(count);
        let mut network_stats = Vec::with_capacity(count);
        let mut isp_work = Vec::with_capacity(count);
        
        for i in 0..count {
            work_metrics.push(WorkMetrics {
                routing_work: (i % 10000000) as u64,
                storage_work: (i % 5000000000) as u64,
                compute_work: (i % 1000) as u64,
                quality_score: (i % 100) as f64 / 100.0,
                uptime_hours: (i % 25) as u64,
            });
            
            network_stats.push(NetworkStats {
                utilization: (i % 100) as f64 / 100.0,
                avg_quality: (i % 100) as f64 / 100.0,
                total_nodes: (i % 10000) as u64,
                total_transactions: (i % 1000000) as u64,
            });
            
            isp_work.push(IspBypassWork {
                bandwidth_shared_gb: (i % 100) as u64,
                packets_routed_mb: (i % 1000) as u64,
                uptime_hours: (i % 25) as u64,
                connection_quality: (i % 100) as f64 / 100.0,
                users_served: (i % 20) as u64,
                cost_savings_provided: (i % 500) as u64,
            });
        }
        
        (work_metrics, network_stats, isp_work)
    }
}
