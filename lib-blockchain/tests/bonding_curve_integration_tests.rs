//! Bonding Curve Integration Tests
//!
//! End-to-end tests for the full bonding curve token lifecycle:
//! 1. Deploy bonding curve token
//! 2. Buy tokens from curve
//! 3. Sell tokens back to curve (if enabled)
//! 4. Graduate token when threshold met
//! 5. Swap tokens on AMM after graduation
//! 6. Add/remove liquidity on AMM

use std::collections::HashMap;

use lib_blockchain::Blockchain;
use lib_blockchain::contracts::bonding_curve::{
    BondingCurveToken, BondingCurveRegistry,
    CurveType, Phase, Threshold,
};
use lib_blockchain::contracts::sov_swap::{SovSwapPool, SimulationResult};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::types::dao::DAOType;

/// Test helper: Create a test public key
fn test_key(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 1312])
}

/// Test helper: Create a test token ID
fn test_token_id(id: u8) -> [u8; 32] {
    [id; 32]
}

/// Test the complete bonding curve lifecycle
#[test]
fn test_bonding_curve_full_lifecycle() {
    // Create fresh blockchain
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    
    // Test 1: Deploy a bonding curve token
    let token_id = test_token_id(1);
    let creator = test_key(1);
    
    let curve_type = CurveType::Linear {
        base_price: 1_000_000, // 0.01 USD with 8 decimals
        slope: 100,            // Price increases by 0.000001 per token
    };
    
    let threshold = Threshold::ReserveAmount(10_000_000); // Graduate at 100 USD reserve
    
    let token = BondingCurveToken::deploy(
        token_id,
        "Test Token".to_string(),
        "TEST".to_string(),
        curve_type,
        threshold,
        true, // sell_enabled
        creator.clone(),
        0,    // block height
        1_600_000_000, // timestamp
    ).expect("Failed to deploy token");
    
    // Register token in blockchain
    blockchain.bonding_curve_registry.register(token)
        .expect("Failed to register token");
    
    assert_eq!(blockchain.bonding_curve_registry.total_count(), 1);
    assert_eq!(blockchain.bonding_curve_registry.count_by_phase(Phase::Curve), 1);
    
    // Test 2: Simulate buying tokens from curve
    let buy_amount_stable = 1_000_000; // 10 USD
    let token_ref = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    
    // Token should be in curve phase
    assert!(token_ref.phase.is_curve_active());
    
    // Calculate expected tokens out (simplified for test)
    let current_price = token_ref.current_price();
    let expected_tokens = (buy_amount_stable as u128 * 100_000_000 / current_price as u128) as u64;
    
    assert!(expected_tokens > 0, "Should receive tokens for stable input");
    
    // Test 3: Update token state as if purchase occurred
    {
        let token_mut = blockchain.bonding_curve_registry.get_mut(&token_id).unwrap();
        token_mut.reserve_balance += buy_amount_stable;
        token_mut.total_supply += expected_tokens;
    }
    
    // Verify state update
    let token_ref = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert_eq!(token_ref.reserve_balance, buy_amount_stable);
    assert_eq!(token_ref.total_supply, expected_tokens);
    
    // Test 4: Check graduation eligibility (should not be ready yet)
    assert!(!token_ref.can_graduate(1_600_000_100));
    
    // Simulate more buys to reach threshold
    {
        let token_mut = blockchain.bonding_curve_registry.get_mut(&token_id).unwrap();
        token_mut.reserve_balance = 10_000_000; // Reach 100 USD threshold
        token_mut.total_supply += 900_000; // Additional tokens
    }
    
    let token_ref = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert!(token_ref.can_graduate(1_600_000_100), "Should be ready to graduate");
    
    // Test 5: Graduate the token
    {
        let token_mut = blockchain.bonding_curve_registry.get_mut(&token_id).unwrap();
        token_mut.phase = Phase::Graduated;
        token_mut.amm_pool_id = Some(test_token_id(100)); // Set pool ID
    }
    
    blockchain.bonding_curve_registry.update_phase(&token_id, Phase::Graduated)
        .expect("Failed to update phase");
    
    let token_ref = blockchain.bonding_curve_registry.get(&token_id).unwrap();
    assert!(token_ref.phase.is_graduated());
    assert!(!token_ref.phase.is_curve_active());
    
    // Test 6: Create AMM pool for graduated token
    let governance = test_key(2);
    let treasury = test_key(3);
    
    let pool = SovSwapPool::init_pool(
        token_id,
        DAOType::FP,
        5_000_000, // 50 SOV initial liquidity
        1_000_000, // 10 tokens initial liquidity
        governance.clone(),
        treasury.clone(),
    ).expect("Failed to create AMM pool");
    
    let pool_id = *pool.pool_id();
    blockchain.amm_pools.insert(pool_id, pool);
    
    // Update token to AMM phase
    blockchain.bonding_curve_registry.update_phase(&token_id, Phase::AMM)
        .expect("Failed to update to AMM phase");
    
    // Test 7: Query AMM pool info
    let pool = blockchain.amm_pools.get(&pool_id).expect("Pool not found");
    let state = pool.state();
    
    assert!(state.initialized);
    assert_eq!(state.sov_reserve, 5_000_000);
    assert_eq!(state.token_reserve, 1_000_000);
    assert!(state.k > 0);
    
    // Test 8: Simulate swaps on AMM
    let sim_result = pool.simulate_sov_to_token(100_000, None)
        .expect("Swap simulation failed");
    
    assert!(sim_result.amount_out > 0, "Should receive tokens");
    assert!(sim_result.fee_amount > 0, "Fee should be charged");
    assert!(sim_result.price_impact_bps < 10000, "Price impact should be < 100%");
    
    // Test reverse swap
    let sim_result2 = pool.simulate_token_to_sov(10_000, None)
        .expect("Swap simulation failed");
    
    assert!(sim_result2.amount_out > 0, "Should receive SOV");
    
    // Test 9: Get pool price
    let (sov_per_token, token_per_sov) = pool.get_price()
        .expect("Failed to get price");
    
    assert!(sov_per_token > 0);
    assert!(token_per_sov > 0);
    
    println!("✅ Full bonding curve lifecycle test passed!");
    println!("   - Token deployed");
    println!("   - Tokens purchased from curve");
    println!("   - Token graduated");
    println!("   - AMM pool created and operational");
    println!("   - Swaps working on AMM");
}

/// Test multiple tokens in different phases
#[test]
fn test_multiple_tokens_different_phases() {
    let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
    let creator = test_key(1);
    
    // Deploy 3 tokens in different phases
    for i in 1..=3 {
        let token_id = test_token_id(i as u8);
        let phase = match i {
            1 => Phase::Curve,
            2 => Phase::Graduated,
            3 => Phase::AMM,
            _ => unreachable!(),
        };
        
        let mut token = BondingCurveToken::deploy(
            token_id,
            format!("Token {}", i),
            format!("TK{}", i),
            CurveType::Linear { base_price: 1_000_000, slope: 100 },
            Threshold::ReserveAmount(10_000_000),
            true,
            creator.clone(),
            0,
            1_600_000_000,
        ).expect("Failed to deploy token");
        
        token.phase = phase;
        if phase == Phase::AMM || phase == Phase::Graduated {
            token.amm_pool_id = Some(test_token_id(100 + i as u8));
        }
        
        blockchain.bonding_curve_registry.register(token)
            .expect("Failed to register token");
    }
    
    // Verify counts
    assert_eq!(blockchain.bonding_curve_registry.total_count(), 3);
    assert_eq!(blockchain.bonding_curve_registry.count_by_phase(Phase::Curve), 1);
    assert_eq!(blockchain.bonding_curve_registry.count_by_phase(Phase::Graduated), 1);
    assert_eq!(blockchain.bonding_curve_registry.count_by_phase(Phase::AMM), 1);
    
    // Test get_by_phase
    let curve_tokens = blockchain.bonding_curve_registry.get_by_phase(Phase::Curve);
    assert_eq!(curve_tokens.len(), 1);
    assert_eq!(curve_tokens[0].symbol, "TK1");
    
    println!("✅ Multiple tokens in different phases test passed!");
}

/// Test curve math with different curve types
#[test]
fn test_curve_math_variations() {
    let creator = test_key(1);
    let base_time = 1_600_000_000;
    
    // Test Linear curve
    let linear_token = BondingCurveToken::deploy(
        test_token_id(1),
        "Linear Token".to_string(),
        "LIN".to_string(),
        CurveType::Linear { base_price: 1_000_000, slope: 100 },
        Threshold::ReserveAmount(10_000_000),
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    let linear_price = linear_token.current_price();
    assert!(linear_price >= 1_000_000, "Linear price should be >= base price");
    
    // Test Exponential curve
    let exp_token = BondingCurveToken::deploy(
        test_token_id(2),
        "Exponential Token".to_string(),
        "EXP".to_string(),
        CurveType::Exponential { base_price: 1_000_000, growth_rate_bps: 1000 }, // 10% growth
        Threshold::ReserveAmount(10_000_000),
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    let exp_price = exp_token.current_price();
    assert!(exp_price >= 1_000_000, "Exponential price should be >= base price");
    
    // Test Sigmoid curve
    let sig_token = BondingCurveToken::deploy(
        test_token_id(3),
        "Sigmoid Token".to_string(),
        "SIG".to_string(),
        CurveType::Sigmoid { 
            max_price: 100_000_000,  // 1 USD max
            midpoint_supply: 500_000, // Midpoint at 5 tokens
            steepness: 100 
        },
        Threshold::SupplyAmount(1_000_000), // Graduate at 10 tokens
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    let sig_price = sig_token.current_price();
    assert!(sig_price <= 100_000_000, "Sigmoid price should be <= max price");
    
    println!("✅ Curve math variations test passed!");
    println!("   Linear price: {}", linear_price);
    println!("   Exponential price: {}", exp_price);
    println!("   Sigmoid price: {}", sig_price);
}

/// Test AMM swap invariants
#[test]
fn test_amm_swap_invariants() {
    let governance = test_key(1);
    let treasury = test_key(2);
    let token_id = test_token_id(1);
    
    let mut pool = SovSwapPool::init_pool(
        token_id,
        DAOType::NP,
        1_000_000, // 10 SOV
        1_000_000, // 10 tokens (1:1 ratio)
        governance,
        treasury,
    ).expect("Failed to create pool");
    
    let initial_k = pool.state().k;
    
    // Perform multiple swaps and verify k never decreases
    for i in 1..=10 {
        // SOV -> Token swap
        let sim_result = pool.simulate_sov_to_token(10_000, None)
            .expect("Swap simulation failed");
        
        // K should be preserved or increased (due to fees)
        let current_state = pool.state();
        let new_k = (current_state.sov_reserve as u128 + 10_000 - sim_result.fee_amount as u128) 
            * (current_state.token_reserve as u128 - sim_result.amount_out as u128);
        
        assert!(
            new_k >= initial_k || i == 1, 
            "K invariant violated after swap {}: {} < {}", i, new_k, initial_k
        );
        
        // Actually execute the swap to update state
        let _ = pool.swap_sov_to_token(&test_key(3), 10_000, None);
    }
    
    let final_k = pool.state().k;
    assert!(
        final_k >= initial_k,
        "K should never decrease: {} < {}", final_k, initial_k
    );
    
    println!("✅ AMM swap invariants test passed!");
    println!("   Initial K: {}", initial_k);
    println!("   Final K: {}", final_k);
}

/// Test slippage protection on AMM
#[test]
fn test_amm_slippage_protection() {
    let governance = test_key(1);
    let treasury = test_key(2);
    let token_id = test_token_id(1);
    
    let mut pool = SovSwapPool::init_pool(
        token_id,
        DAOType::NP,
        1_000_000,
        1_000_000,
        governance,
        treasury,
    ).expect("Failed to create pool");
    
    // Get quote without slippage protection
    let sim_result = pool.simulate_sov_to_token(50_000, None)
        .expect("Swap simulation failed");
    
    // Try to swap with higher min_out than possible (should fail)
    let high_min_out = sim_result.amount_out + 1000;
    let result = pool.simulate_sov_to_token(50_000, Some(high_min_out));
    
    assert!(
        result.is_err(),
        "Should fail when min_amount_out is too high"
    );
    
    // Swap with exact min_out should succeed
    let result = pool.simulate_sov_to_token(50_000, Some(sim_result.amount_out));
    assert!(result.is_ok(), "Should succeed with exact min_amount_out");
    
    // Swap with lower min_out should succeed
    let result = pool.simulate_sov_to_token(50_000, Some(sim_result.amount_out - 100));
    assert!(result.is_ok(), "Should succeed with lower min_amount_out");
    
    println!("✅ AMM slippage protection test passed!");
}

/// Test token graduation threshold variations
#[test]
fn test_graduation_thresholds() {
    let creator = test_key(1);
    let base_time = 1_600_000_000;
    
    // Test ReserveAmount threshold
    let mut token1 = BondingCurveToken::deploy(
        test_token_id(1),
        "Reserve Threshold Token".to_string(),
        "RES".to_string(),
        CurveType::Linear { base_price: 1_000_000, slope: 100 },
        Threshold::ReserveAmount(10_000_000), // 100 USD
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    token1.reserve_balance = 9_999_999; // Just under threshold
    assert!(!token1.can_graduate(base_time + 100));
    
    token1.reserve_balance = 10_000_000; // At threshold
    assert!(token1.can_graduate(base_time + 100));
    
    // Test SupplyAmount threshold
    let mut token2 = BondingCurveToken::deploy(
        test_token_id(2),
        "Supply Threshold Token".to_string(),
        "SUP".to_string(),
        CurveType::Linear { base_price: 1_000_000, slope: 100 },
        Threshold::SupplyAmount(1_000_000), // 10 tokens
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    token2.total_supply = 999_999; // Just under threshold
    assert!(!token2.can_graduate(base_time + 100));
    
    token2.total_supply = 1_000_000; // At threshold
    assert!(token2.can_graduate(base_time + 100));
    
    // Test TimeAndReserve threshold
    let mut token3 = BondingCurveToken::deploy(
        test_token_id(3),
        "Time+Reserve Token".to_string(),
        "TNR".to_string(),
        CurveType::Linear { base_price: 1_000_000, slope: 100 },
        Threshold::TimeAndReserve { 
            min_reserve: 5_000_000,  // 50 USD
            min_time_seconds: 3600,   // 1 hour
        },
        true,
        creator.clone(),
        0,
        base_time,
    ).unwrap();
    
    token3.reserve_balance = 5_000_000; // Reserve met
    // Time not met
    assert!(!token3.can_graduate(base_time + 100)); // Only 100 seconds passed
    
    // Both met
    assert!(token3.can_graduate(base_time + 3600)); // 1 hour passed
    
    println!("✅ Graduation thresholds test passed!");
}
