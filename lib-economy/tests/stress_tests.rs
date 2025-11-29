//! Stress tests for ZHTP Economics module
//! 
//! Tests system behavior under high load, extreme conditions,
//! and resource constraints.

use lib_economy::*;
use lib_economy::testing::*;
use std::thread;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_high_transaction_volume() {
        let _model = EconomicModel::new();
        
        // Simulate 100,000 transactions
        let transaction_count = 100_000;
        let mut total_fees = 0u64;
        let mut transactions = Vec::with_capacity(transaction_count);
        
        for i in 0..transaction_count {
            let from = [((i / 256) % 256) as u8; 32];
            let to = [((i * 7) % 256) as u8; 32];
            let amount = ((i * 123) % 50000) as u64 + 1; // 1-50,000 tokens
            let priority = match i % 4 {
                0 => Priority::Low,
                1 => Priority::Normal,
                2 => Priority::High,
                _ => Priority::Urgent,
            };
            
            let tx = Transaction::new_payment(from, to, amount, priority).unwrap();
            total_fees += tx.total_fee;
            transactions.push(tx);
        }
        
        // Verify all transactions have unique IDs
        let mut tx_ids = std::collections::HashSet::new();
        for tx in &transactions {
            assert!(tx_ids.insert(tx.tx_id)); // Should be unique
        }
        
        // Verify fee consistency
        assert!(total_fees > transaction_count as u64); // Should have reasonable fees
        println!("Processed {} transactions with total fees: {}", transaction_count, total_fees);
    }

    #[test]
    fn test_massive_reward_distribution() {
        let model = EconomicModel::new();
        
        // Simulate reward calculation for 50,000 nodes
        let node_count = 50_000;
        let mut total_rewards = 0u64;
        
        for i in 0..node_count {
            let work = WorkMetrics {
                routing_work: ((i * 31) % 10000) as u64,
                storage_work: ((i * 37) % 20000) as u64,
                compute_work: ((i * 41) % 5000) as u64,
                quality_score: ((i % 100) as f64) / 100.0,
                uptime_hours: ((i * 13) % 8760) as u64, // Up to 1 year
            };
            
            let reward = TokenReward::calculate(&work, &model).unwrap();
            total_rewards += reward.total_reward;
        }
        
        assert!(total_rewards > node_count); // Should have meaningful rewards
        println!("Distributed {} tokens to {} nodes", total_rewards, node_count);
    }

    #[test]
    fn test_treasury_stress() {
        let mut treasury = DaoTreasury::new();
        
        // Add fees from 1 million transactions
        let transaction_count = 1_000_000;
        let mut total_fees_added = 0u64;
        
        for i in 0..transaction_count {
            let fee = ((i % 10000) + 1) as u64; // 1-10,000 tokens per transaction
            treasury.add_dao_fees(fee).unwrap();
            total_fees_added += fee;
            
            // Periodically distribute UBI
            if i % 10000 == 0 && i > 0 {
                let citizens = ((i / 1000) + 1000) as u64; // Growing population
                let ubi_per_citizen = treasury.calculate_ubi_per_citizen(citizens);
                
                if ubi_per_citizen > 0 {
                    let total_distributed = ubi_per_citizen * citizens;
                    let timestamp = current_timestamp() + i as u64;
                    treasury.record_ubi_distribution(total_distributed, timestamp).unwrap();
                }
            }
        }
        
        assert_eq!(treasury.total_dao_fees_collected, total_fees_added);
        assert!(treasury.total_ubi_distributed > 0 || treasury.ubi_allocated > 0); // Should have distributions or allocations
        println!("Treasury processed {} in fees from {} transactions", 
                total_fees_added, transaction_count);
    }

    #[test]
    fn test_network_scaling() {
        let mut stats = NetworkStats::new();
        
        // Simulate network growing from 1,000 to 10 million nodes
        let growth_phases = vec![
            (1_000, 0.1),      // Small network, low utilization
            (10_000, 0.3),     // Growing network
            (100_000, 0.5),    // Medium network
            (1_000_000, 0.7),  // Large network
            (10_000_000, 0.9), // Massive network, high utilization
        ];
        
        for (nodes, utilization) in growth_phases {
            stats.set_total_nodes(nodes);
            stats.update_utilization(utilization);
            stats.update_avg_quality(0.8); // Set reasonable network quality
            stats.total_transactions = nodes * 100; // 100 tx per node on average
            
            let health = stats.network_health_score();
            assert!(health >= 0.0 && health <= 1.0);
            
            // Network should maintain health even at scale
            if utilization < 0.95 {
                assert!(health > 0.3); // Reasonable health threshold
            }
        }
    }

    #[test]
    fn test_isp_bypass_massive_mesh() {
        let mut incentives = IspBypassIncentives::new();
        
        // Simulate 100,000 mesh participants
        let participant_count = 100_000;
        let mut total_rewards = 0u64;
        
        for i in 0..participant_count {
            let work = IspBypassWork {
                bandwidth_shared_gb: ((i % 1000) + 1) as u64,
                packets_routed_mb: ((i % 10000) + 100) as u64,
                uptime_hours: ((i % 720) + 1) as u64, // Up to 30 days
                connection_quality: ((i % 100) as f64) / 100.0,
                users_served: ((i % 100) + 1) as u64,
                cost_savings_provided: ((i % 50000) + 1000) as u64,
            };
            
            let reward = incentives.calculate_rewards(&work);
            total_rewards += reward;
            
            incentives.update_stats(&work).unwrap();
        }
        
        assert_eq!(incentives.mesh_participants, participant_count);
        assert!(total_rewards > participant_count); // Should be meaningful rewards
        assert!(incentives.total_bandwidth_shared > 0);
        
        println!(" mesh: {} participants, {} total rewards", 
                participant_count, total_rewards);
    }

    #[test]
    fn test_wallet_stress() {
        // Test 10,000 wallets with heavy activity
        let wallet_count = 10_000;
        let mut wallets: Vec<WalletBalance> = (0..wallet_count)
            .map(|i| WalletBalance::new([(i % 256) as u8; 32]))
            .collect();
        
        // Each wallet processes 1,000 operations
        let operations_per_wallet = 1_000;
        
        for wallet_idx in 0..wallet_count {
            for op in 0..operations_per_wallet {
                let operation_type = (wallet_idx + op) % 5;
                
                match operation_type {
                    0 => {
                        // Add reward
                        let reward = TokenReward {
                            routing_reward: (op % 100) as u64,
                            storage_reward: (op % 200) as u64,
                            compute_reward: (op % 50) as u64,
                            quality_bonus: (op % 25) as u64,
                            uptime_bonus: (op % 75) as u64,
                            total_reward: (op % 450) as u64 + 1,
                            currency: "SOV".to_string(),
                        };
                        wallets[wallet_idx].add_reward(&reward).unwrap();
                    }
                    1 => {
                        // Claim rewards
                        wallets[wallet_idx].claim_rewards().unwrap();
                    }
                    2 => {
                        // Stake tokens (simulate by moving from available to staked)
                        let stake_amount = (op % 1000) as u64;
                        if wallets[wallet_idx].can_afford(stake_amount) {
                            wallets[wallet_idx].available_balance -= stake_amount;
                            wallets[wallet_idx].staked_balance += stake_amount;
                        }
                    }
                    3 => {
                        // Unstake tokens (simulate by moving from staked to available)
                        let unstake_amount = (op % 500) as u64;
                        if wallets[wallet_idx].staked_balance >= unstake_amount {
                            wallets[wallet_idx].staked_balance -= unstake_amount;
                            wallets[wallet_idx].available_balance += unstake_amount;
                        }
                    }
                    _ => {
                        // Update balance directly (simulating transaction processing)
                        let amount = (op % 10000) as u64;
                        wallets[wallet_idx].available_balance = 
                            wallets[wallet_idx].available_balance.saturating_add(amount);
                    }
                }
            }
        }
        
        // Verify all wallets are in consistent state
        for wallet in &wallets {
            let total = wallet.total_balance();
            assert!(total >= wallet.available_balance);
            assert!(total >= wallet.staked_balance);
            assert!(total >= wallet.pending_rewards);
        }
        
        println!("Processed {} operations across {} wallets", 
                wallet_count * operations_per_wallet, wallet_count);
    }

    #[test]
    fn test_economic_model_parameter_stress() {
        let mut model = EconomicModel::new();
        
        // Rapidly adjust parameters 10,000 times
        let adjustment_count = 10_000;
        
        for i in 0..adjustment_count {
            // Create varying network conditions
            let utilization = ((i % 100) as f64) / 100.0;
            let quality = ((i % 80 + 20) as f64) / 100.0; // 0.2 to 1.0
            let nodes = ((i % 1000) + 1000) as u64; // 1,000 to 2,000 nodes
            let transactions = nodes * ((i % 100) + 50) as u64; // Variable tx per node
            
            let stats = NetworkStats {
                utilization,
                avg_quality: quality,
                total_nodes: nodes,
                total_transactions: transactions,
            };
            
            model.adjust_parameters(&stats).unwrap();
            
            // Verify parameters remain reasonable
            assert!(model.base_routing_rate > 0);
            assert!(model.base_storage_rate > 0);
            assert!(model.base_compute_rate > 0);
            
            // Test minting with adjusted parameters
            let mint_amount = ((i % 10000) + 1) as u64;
            model.mint_operational_tokens(mint_amount, "stress test").unwrap();
        }
        
        assert!(model.current_supply > 0);
        println!("Economic model survived {} parameter adjustments", adjustment_count);
    }

    #[test]
    fn test_concurrent_economic_operations() {
        // This test simulates concurrent access patterns
        let model = Arc::new(Mutex::new(EconomicModel::new()));
        let handles: Vec<_> = (0..10).map(|thread_id| {
            let model_clone = Arc::clone(&model);
            
            thread::spawn(move || {
                let operations_per_thread = 1_000;
                
                for i in 0..operations_per_thread {
                    let mut model = model_clone.lock().unwrap();
                    
                    // Different threads do different operations
                    match thread_id % 3 {
                        0 => {
                            // Mint tokens
                            let amount = ((thread_id * 100 + i) % 10000 + 1) as u64;
                            model.mint_operational_tokens(amount, "concurrent test").unwrap();
                        }
                        1 => {
                            // Process DAO fees
                            let fees = ((thread_id * 50 + i) % 5000 + 1) as u64;
                            model.process_dao_fees(fees).unwrap();
                        }
                        _ => {
                            // Adjust parameters
                            let utilization = ((thread_id * 10 + i) % 100) as f64 / 100.0;
                            let stats = NetworkStats {
                                utilization,
                                avg_quality: 0.8,
                                total_nodes: 10000,
                                total_transactions: 100000,
                            };
                            model.adjust_parameters(&stats).unwrap();
                        }
                    }
                }
            })
        }).collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
        
        let final_model = model.lock().unwrap();
        assert!(final_model.current_supply > 0);
        assert!(final_model.dao_treasury.treasury_balance > 0);
        
        println!("Concurrent operations completed successfully");
    }

    #[test]
    fn test_memory_efficiency() {
        // Test that the system doesn't consume excessive memory
        let initial_memory = std::process::Command::new("powershell")
            .args(&["-Command", "(Get-Process -Id $PID).WorkingSet64"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        
        // Create many economic objects
        let mut models = Vec::new();
        let mut treasuries = Vec::new();
        let mut wallets = Vec::new();
        
        for i in 0..1000 {
            models.push(EconomicModel::new());
            treasuries.push(DaoTreasury::new());
            wallets.push(WalletBalance::new([i as u8; 32]));
        }
        
        // Process some operations
        for i in 0..1000 {
            let model_idx = i % models.len();
            let treasury_idx = i % treasuries.len();
            let wallet_idx = i % wallets.len();
            
            // Add some load
            let _ = models[model_idx].mint_operational_tokens(1000, "memory test");
            let _ = treasuries[treasury_idx].add_dao_fees(100);
            
            let reward = TokenReward {
                routing_reward: 10,
                storage_reward: 20,
                compute_reward: 5,
                quality_bonus: 2,
                uptime_bonus: 3,
                total_reward: 40,
                currency: "SOV".to_string(),
            };
            let _ = wallets[wallet_idx].add_reward(&reward);
        }
        
        let final_memory = std::process::Command::new("powershell")
            .args(&["-Command", "(Get-Process -Id $PID).WorkingSet64"])
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        
        if initial_memory > 0 && final_memory > 0 {
            let memory_increase = final_memory.saturating_sub(initial_memory);
            println!("Memory usage increased by {} bytes", memory_increase);
            
            // Memory increase should be reasonable (less than 100MB for this test)
            assert!(memory_increase < 100_000_000);
        }
        
        // Clean up
        drop(models);
        drop(treasuries);
        drop(wallets);
    }

    #[test]
    fn test_anti_speculation_at_scale() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        // Test with 100,000 different account scenarios
        let account_count = 100_000;
        let mut speculative_count = 0;
        let mut legitimate_count = 0;
        
        for i in 0..account_count {
            let balance = ((i * 123) % 1_000_000) as u64 + 1000; // 1K to 1M tokens
            let usage = ((i * 456) % 500_000) as u64; // Variable usage
            let days_held = ((i * 789) % 365) as u64 + 1; // 1-365 days
            
            let is_speculative = mechanisms.is_speculative_behavior(balance, usage, days_held);
            
            if is_speculative {
                speculative_count += 1;
            } else {
                legitimate_count += 1;
            }
            
            // Calculate incentives for all accounts
            let incentive = mechanisms.calculate_utility_incentives(usage, balance);
            assert!(incentive >= 0); // Should never be negative
        }
        
        println!("Anti-speculation analysis: {} speculative, {} legitimate accounts", 
                speculative_count, legitimate_count);
        
        // In a post-scarcity economy, most should be legitimate
        assert!(legitimate_count > speculative_count);
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_transaction_processing_speed() {
        let model = EconomicModel::new();
        let start = Instant::now();
        
        // Process 50,000 transactions and measure time
        let transaction_count = 50_000;
        
        for i in 0..transaction_count {
            let from = [(i % 256) as u8; 32];
            let to = [((i + 1) % 256) as u8; 32];
            let amount = (i % 10000 + 1) as u64;
            let priority = Priority::Normal;
            
            let _tx = Transaction::new_payment(from, to, amount, priority).unwrap();
        }
        
        let duration = start.elapsed();
        let tx_per_second = transaction_count as f64 / duration.as_secs_f64();
        
        println!("Transaction processing: {:.0} tx/second", tx_per_second);
        
        // Should process at least 1000 transactions per second
        assert!(tx_per_second > 1000.0);
    }

    #[test]
    fn test_reward_calculation_speed() {
        let model = EconomicModel::new();
        let start = Instant::now();
        
        // Calculate rewards for 25,000 nodes
        let node_count = 25_000;
        
        for i in 0..node_count {
            let work = WorkMetrics {
                routing_work: (i % 10000) as u64,
                storage_work: (i % 20000) as u64,
                compute_work: (i % 5000) as u64,
                quality_score: 0.8,
                uptime_hours: (i % 8760) as u64,
            };
            
            let _reward = TokenReward::calculate(&work, &model).unwrap();
        }
        
        let duration = start.elapsed();
        let rewards_per_second = node_count as f64 / duration.as_secs_f64();
        
        println!("Reward calculation: {:.0} rewards/second", rewards_per_second);
        
        // Should calculate at least 5000 rewards per second
        assert!(rewards_per_second > 5000.0);
    }

    #[test]
    fn test_memory_stability_over_time() {
        // Run economic operations for extended period
        let mut model = EconomicModel::new();
        let mut treasury = DaoTreasury::new();
        let iterations = 100_000;
        
        let start = Instant::now();
        
        for i in 0..iterations {
            // Cycle through different operations
            match i % 10 {
                0..=3 => {
                    // Mint tokens
                    let amount = (i % 10000 + 1) as u64;
                    model.mint_operational_tokens(amount, "stability test").unwrap();
                }
                4..=6 => {
                    // Process fees
                    let fees = (i % 5000 + 1) as u64;
                    treasury.add_dao_fees(fees).unwrap();
                }
                7..=8 => {
                    // Calculate rewards
                    let work = WorkMetrics {
                        routing_work: (i % 1000) as u64,
                        storage_work: (i % 2000) as u64,
                        compute_work: (i % 500) as u64,
                        quality_score: 0.75,
                        uptime_hours: (i % 720) as u64,
                    };
                    let _reward = TokenReward::calculate(&work, &model).unwrap();
                }
                _ => {
                    // Adjust parameters
                    let stats = NetworkStats {
                        utilization: ((i % 100) as f64) / 100.0,
                        avg_quality: 0.8,
                        total_nodes: 10000,
                        total_transactions: 50000,
                    };
                    model.adjust_parameters(&stats).unwrap();
                }
            }
        }
        
        let duration = start.elapsed();
        let ops_per_second = iterations as f64 / duration.as_secs_f64();
        
        println!("Long-running stability: {:.0} operations/second over {} iterations", 
                ops_per_second, iterations);
        
        // System should maintain reasonable performance
        assert!(ops_per_second > 1000.0);
        
        // Verify system state is still consistent
        assert!(model.current_supply > 0);
        assert!(treasury.treasury_balance > 0);
    }
}
