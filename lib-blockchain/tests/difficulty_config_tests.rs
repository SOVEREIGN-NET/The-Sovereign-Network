//! Tests for difficulty adjustment using DifficultyConfig
//!
//! These tests verify that the adjust_difficulty() method correctly uses
//! DifficultyConfig parameters instead of hardcoded constants.
//!
//! ## Test Categories (Issue #605)
//!
//! 1. **Determinism Tests** - Verify difficulty adjustment is identical when replayed
//!    from same chain data, no dependency on wall-clock time, reproducible from any height.
//!
//! 2. **Parameter Update Tests** - Create difficulty parameter update proposals,
//!    vote on proposals, apply updates, verify config changes.
//!
//! 3. **Validation Tests** - Reject invalid parameters (zeros, out-of-range),
//!    accept valid boundary combinations.
//!
//! 4. **Clamping Tests** - Verify max increase/decrease factors, custom factors,
//!    extreme timespans are properly clamped.
//!
//! 5. **State Persistence Tests** - DifficultyConfig serializes/deserializes correctly,
//!    survives blockchain save/load cycle, parameter update history preserved.
//!
//! 6. **Integration Tests** - Full governance flow from proposal to adjustment.

use lib_blockchain::types::{DifficultyConfig, DifficultyParameterUpdateData};
use lib_blockchain::types::difficulty::adjust_difficulty_with_config;
use lib_blockchain::Blockchain;

/// Test that default DifficultyConfig matches legacy constants for backward compatibility
#[test]
fn test_backward_compatibility_defaults() {
    let default_config = DifficultyConfig::default();
    
    // These must match the legacy constants for backward compatibility
    assert_eq!(
        default_config.adjustment_interval,
        lib_blockchain::DIFFICULTY_ADJUSTMENT_INTERVAL,
        "Default adjustment_interval must match legacy constant"
    );
    assert_eq!(
        default_config.target_timespan,
        lib_blockchain::TARGET_TIMESPAN,
        "Default target_timespan must match legacy constant"
    );
    assert_eq!(
        default_config.max_difficulty_increase_factor, 4,
        "Legacy used hardcoded 4x for increase"
    );
    assert_eq!(
        default_config.max_difficulty_decrease_factor, 4,
        "Legacy used hardcoded 4x for decrease"
    );
}

/// Test that new Blockchain instances have default DifficultyConfig
#[test]
fn test_difficulty_adjustment_with_default_config() {
    let blockchain = Blockchain::new().unwrap();
    
    // Default config should match legacy constants
    assert_eq!(blockchain.difficulty_config.adjustment_interval, 2016);
    assert_eq!(blockchain.difficulty_config.target_timespan, 14 * 24 * 60 * 60);
    assert_eq!(blockchain.difficulty_config.max_difficulty_increase_factor, 4);
    assert_eq!(blockchain.difficulty_config.max_difficulty_decrease_factor, 4);
}

/// Test that custom DifficultyConfig can be set and is used
#[test]
fn test_difficulty_adjustment_with_custom_config() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Set custom config
    let custom_config = DifficultyConfig {
        target_timespan: 7 * 24 * 60 * 60,  // 1 week
        adjustment_interval: 1008,           // Half the blocks
        max_difficulty_increase_factor: 2,   // Max 2x increase
        max_difficulty_decrease_factor: 2,   // Max 2x decrease
        last_updated_at_height: 0,
    };
    blockchain.set_difficulty_config(custom_config.clone()).unwrap();
    
    assert_eq!(blockchain.difficulty_config.adjustment_interval, 1008);
    assert_eq!(blockchain.difficulty_config.target_timespan, 7 * 24 * 60 * 60);
    assert_eq!(blockchain.difficulty_config.max_difficulty_increase_factor, 2);
    assert_eq!(blockchain.difficulty_config.max_difficulty_decrease_factor, 2);
}

/// Test that clamping works correctly with default 4x factors
#[test]
fn test_clamping_with_default_factors() {
    let config = DifficultyConfig::default();
    let target = config.target_timespan;
    
    // With default 4x factors:
    // - min_timespan = target / 4
    // - max_timespan = target * 4
    
    // Very fast blocks should be clamped to min (target/4)
    let clamped = config.clamp_timespan(1000); // Much faster than target
    assert_eq!(clamped, target / 4, "Very fast blocks should clamp to target/4");
    
    // Very slow blocks should be clamped to max (target*4)
    let clamped = config.clamp_timespan(target * 10); // Much slower than target
    assert_eq!(clamped, target * 4, "Very slow blocks should clamp to target*4");
    
    // On-target timing should not be clamped
    let clamped = config.clamp_timespan(target);
    assert_eq!(clamped, target, "On-target timing should not be clamped");
}

/// Test that clamping works correctly with custom 2x factors
#[test]
fn test_clamping_with_2x_factors() {
    let config = DifficultyConfig {
        target_timespan: 1000,
        adjustment_interval: 100,
        max_difficulty_increase_factor: 2,
        max_difficulty_decrease_factor: 2,
        last_updated_at_height: 0,
    };
    
    // With 2x factors:
    // - min_timespan = 1000 / 2 = 500
    // - max_timespan = 1000 * 2 = 2000
    
    let clamped = config.clamp_timespan(100);  // Very fast blocks
    assert_eq!(clamped, 500, "Should clamp to min (target/2)");
    
    let clamped = config.clamp_timespan(5000);  // Very slow blocks
    assert_eq!(clamped, 2000, "Should clamp to max (target*2)");
    
    // Within range should not be clamped
    let clamped = config.clamp_timespan(1500);
    assert_eq!(clamped, 1500, "Within range should not be clamped");
}

/// Test that clamping works correctly with asymmetric factors
#[test]
fn test_clamping_with_asymmetric_factors() {
    let config = DifficultyConfig {
        target_timespan: 1000,
        adjustment_interval: 100,
        max_difficulty_increase_factor: 8,  // Allow 8x increase
        max_difficulty_decrease_factor: 2,  // Only allow 2x decrease
        last_updated_at_height: 0,
    };
    
    // - min_timespan = 1000 / 8 = 125 (allows more difficulty increase)
    // - max_timespan = 1000 * 2 = 2000 (limits difficulty decrease)
    
    let clamped = config.clamp_timespan(50);  // Very fast - allows big difficulty jump
    assert_eq!(clamped, 125, "Should clamp to min (target/8)");
    
    let clamped = config.clamp_timespan(5000);  // Very slow - limits decrease
    assert_eq!(clamped, 2000, "Should clamp to max (target*2)");
}

/// Test clamping with large factors (8x)
#[test]
fn test_clamping_with_8x_factors() {
    let config = DifficultyConfig {
        target_timespan: 1000,
        adjustment_interval: 100,
        max_difficulty_increase_factor: 8,
        max_difficulty_decrease_factor: 8,
        last_updated_at_height: 0,
    };
    
    // With 8x factors:
    // - min_timespan = 1000 / 8 = 125
    // - max_timespan = 1000 * 8 = 8000
    
    let clamped = config.clamp_timespan(100);
    assert_eq!(clamped, 125, "Should clamp to min (target/8)");
    
    let clamped = config.clamp_timespan(10000);
    assert_eq!(clamped, 8000, "Should clamp to max (target*8)");
}

/// Test that config validation rejects invalid values
#[test]
fn test_config_validation() {
    // Invalid: target_timespan = 0
    assert!(DifficultyConfig::with_params(0, 1008, 2, 2, 0).is_err());
    
    // Invalid: adjustment_interval = 0
    assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 0, 2, 2, 0).is_err());
    
    // Invalid: max_difficulty_decrease_factor = 0
    assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 1008, 0, 2, 0).is_err());
    
    // Invalid: max_difficulty_increase_factor = 0
    assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 1008, 2, 0, 0).is_err());
    
    // Valid config should succeed
    assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 1008, 2, 2, 0).is_ok());
}

/// Test that set_difficulty_config validates before applying
#[test]
fn test_set_difficulty_config_validates() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Invalid config with zero target_timespan
    let invalid_config = DifficultyConfig {
        target_timespan: 0,  // Invalid!
        adjustment_interval: 1008,
        max_difficulty_increase_factor: 2,
        max_difficulty_decrease_factor: 2,
        last_updated_at_height: 0,
    };
    
    let result = blockchain.set_difficulty_config(invalid_config);
    assert!(result.is_err(), "Should reject invalid config");
    
    // Original config should be unchanged
    assert_eq!(blockchain.difficulty_config.adjustment_interval, 2016);
}

/// Test that set_difficulty_config updates last_updated_at_height
#[test]
fn test_set_difficulty_config_updates_height() {
    let mut blockchain = Blockchain::new().unwrap();
    
    let custom_config = DifficultyConfig {
        target_timespan: 7 * 24 * 60 * 60,
        adjustment_interval: 1008,
        max_difficulty_increase_factor: 2,
        max_difficulty_decrease_factor: 2,
        last_updated_at_height: 999,  // Will be overwritten
    };
    
    blockchain.set_difficulty_config(custom_config).unwrap();
    
    // last_updated_at_height should be set to current blockchain height
    assert_eq!(
        blockchain.difficulty_config.last_updated_at_height,
        blockchain.height,
        "last_updated_at_height should be set to current blockchain height"
    );
}

// ============================================================================
// DETERMINISM TESTS
// Verify difficulty adjustment is identical when replayed from same chain data.
// ============================================================================

/// Test that difficulty adjustment is deterministic given the same inputs
#[test]
fn test_difficulty_adjustment_determinism_same_inputs() {
    let config = DifficultyConfig::default();
    let current_difficulty = 1000u32;
    let actual_timespan = 604800u64; // 1 week (half of target)
    
    // Calculate difficulty multiple times with identical inputs
    let result1 = adjust_difficulty_with_config(current_difficulty, actual_timespan, &config);
    let result2 = adjust_difficulty_with_config(current_difficulty, actual_timespan, &config);
    let result3 = adjust_difficulty_with_config(current_difficulty, actual_timespan, &config);
    
    // All results must be identical
    assert_eq!(result1, result2, "Difficulty adjustment must be deterministic");
    assert_eq!(result2, result3, "Difficulty adjustment must be deterministic");
}

/// Test that difficulty adjustment produces consistent results when replayed
/// from the same chain data (simulated blocks with timestamps)
#[test]
fn test_difficulty_adjustment_replay_consistency() {
    let config = DifficultyConfig::default();
    
    // Simulate a series of adjustment intervals with fixed timestamps
    let initial_difficulty = 1000u32;
    let adjustment_scenarios = [
        // (actual_timespan, expected_to_be_deterministic)
        (config.target_timespan, true),        // On target
        (config.target_timespan / 2, true),    // Blocks came fast
        (config.target_timespan * 2, true),    // Blocks came slow
        (config.target_timespan / 10, true),   // Very fast (will be clamped)
        (config.target_timespan * 10, true),   // Very slow (will be clamped)
    ];
    
    for (actual_timespan, _) in adjustment_scenarios {
        // Replay the same calculation multiple times
        let first_run = adjust_difficulty_with_config(initial_difficulty, actual_timespan, &config);
        let replay_run = adjust_difficulty_with_config(initial_difficulty, actual_timespan, &config);
        
        assert_eq!(
            first_run, replay_run,
            "Replaying adjustment with timespan {} must produce identical result",
            actual_timespan
        );
    }
}

/// Test that difficulty adjustment has no dependency on wall-clock time
#[test]
fn test_difficulty_adjustment_no_wall_clock_dependency() {
    let config = DifficultyConfig::default();
    let current_difficulty = 1000u32;
    
    // These timespans represent historical intervals, not current time
    let historical_timespan_1 = 604800u64; // 1 week ago
    let historical_timespan_2 = 604800u64; // Same value, different "wall clock"
    
    // The function only uses the timespan value, not system time
    let result1 = adjust_difficulty_with_config(current_difficulty, historical_timespan_1, &config);
    
    // Simulate "waiting" would not affect result (not actually waiting, just proving point)
    let result2 = adjust_difficulty_with_config(current_difficulty, historical_timespan_2, &config);
    
    assert_eq!(
        result1, result2,
        "Difficulty adjustment must not depend on wall-clock time"
    );
}

/// Test that difficulty adjustment is reproducible from any block height
#[test]
fn test_difficulty_adjustment_reproducible_from_any_height() {
    // Different configs representing different blockchain states
    let config_at_genesis = DifficultyConfig {
        target_timespan: 14 * 24 * 60 * 60,
        adjustment_interval: 2016,
        max_difficulty_increase_factor: 4,
        max_difficulty_decrease_factor: 4,
        last_updated_at_height: 0,
    };
    
    let config_at_height_10000 = DifficultyConfig {
        target_timespan: 14 * 24 * 60 * 60,
        adjustment_interval: 2016,
        max_difficulty_increase_factor: 4,
        max_difficulty_decrease_factor: 4,
        last_updated_at_height: 10000,
    };
    
    let current_difficulty = 1000u32;
    let actual_timespan = 1_000_000u64;
    
    // The last_updated_at_height should not affect the calculation
    // (it's metadata for governance tracking, not adjustment calculation)
    let result_from_genesis = adjust_difficulty_with_config(current_difficulty, actual_timespan, &config_at_genesis);
    let result_from_height = adjust_difficulty_with_config(current_difficulty, actual_timespan, &config_at_height_10000);
    
    assert_eq!(
        result_from_genesis, result_from_height,
        "Difficulty adjustment must be reproducible regardless of last_updated_at_height"
    );
}

/// Test determinism with sequential adjustments (chain of adjustments)
#[test]
fn test_difficulty_adjustment_chain_determinism() {
    let config = DifficultyConfig::default();
    let initial_difficulty = 1000u32;
    
    // Simulate a chain of 5 adjustment intervals with predetermined timespans
    let interval_timespans = [
        config.target_timespan,            // On target
        config.target_timespan / 2,        // Fast
        config.target_timespan * 2,        // Slow
        config.target_timespan / 4,        // Very fast (clamped)
        config.target_timespan,            // On target again
    ];
    
    // First run through the chain
    let mut first_run_difficulties = vec![initial_difficulty];
    let mut current = initial_difficulty;
    for &timespan in &interval_timespans {
        current = adjust_difficulty_with_config(current, timespan, &config);
        first_run_difficulties.push(current);
    }
    
    // Second run through the same chain (replay)
    let mut replay_difficulties = vec![initial_difficulty];
    let mut current = initial_difficulty;
    for &timespan in &interval_timespans {
        current = adjust_difficulty_with_config(current, timespan, &config);
        replay_difficulties.push(current);
    }
    
    // Both runs must produce identical sequences
    assert_eq!(
        first_run_difficulties, replay_difficulties,
        "Chain of difficulty adjustments must be deterministic when replayed"
    );
}

// ============================================================================
// PARAMETER UPDATE TESTS
// Test DifficultyParameterUpdateData creation, voting, and application.
// ============================================================================

/// Test creating a valid difficulty parameter update proposal data
#[test]
fn test_create_difficulty_parameter_update_data() {
    // Bitcoin-like parameters
    let update = DifficultyParameterUpdateData::new(
        14 * 24 * 60 * 60,  // 2 weeks target timespan
        2016,                // 2016 blocks adjustment interval
    ).expect("Valid parameters should succeed");
    
    assert_eq!(update.target_timespan, 14 * 24 * 60 * 60);
    assert_eq!(update.adjustment_interval, 2016);
    assert!(update.min_adjustment_factor.is_none());
    assert!(update.max_adjustment_factor.is_none());
}

/// Test creating difficulty parameter update with custom factors
#[test]
fn test_create_difficulty_parameter_update_with_factors() {
    let update = DifficultyParameterUpdateData::new_with_factors(
        7 * 24 * 60 * 60,   // 1 week target timespan
        1008,               // 1008 blocks
        Some(2),            // min 2x decrease
        Some(8),            // max 8x increase
    ).expect("Valid parameters with factors should succeed");
    
    assert_eq!(update.target_timespan, 7 * 24 * 60 * 60);
    assert_eq!(update.adjustment_interval, 1008);
    assert_eq!(update.min_adjustment_factor, Some(2));
    assert_eq!(update.max_adjustment_factor, Some(8));
}

/// Test that parameter update validation catches zero target_timespan
#[test]
fn test_parameter_update_rejects_zero_target_timespan() {
    let result = DifficultyParameterUpdateData::new(0, 2016);
    
    assert!(result.is_err(), "Should reject target_timespan = 0");
    let err = result.unwrap_err();
    assert!(
        err.contains("target_timespan"),
        "Error should mention target_timespan: {}",
        err
    );
}

/// Test that parameter update validation catches zero adjustment_interval
#[test]
fn test_parameter_update_rejects_zero_adjustment_interval() {
    let result = DifficultyParameterUpdateData::new(604800, 0);
    
    assert!(result.is_err(), "Should reject adjustment_interval = 0");
    let err = result.unwrap_err();
    assert!(
        err.contains("adjustment_interval"),
        "Error should mention adjustment_interval: {}",
        err
    );
}

/// Test that parameter update validation catches adjustment_factor < 1
#[test]
fn test_parameter_update_rejects_factor_less_than_one() {
    // Test min_adjustment_factor < 1
    let result = DifficultyParameterUpdateData::new_with_factors(
        604800, 1008,
        Some(0),  // Invalid: < 1
        Some(4),
    );
    assert!(result.is_err(), "Should reject min_adjustment_factor = 0");
    
    // Test max_adjustment_factor < 1
    let result = DifficultyParameterUpdateData::new_with_factors(
        604800, 1008,
        Some(4),
        Some(0),  // Invalid: < 1
    );
    assert!(result.is_err(), "Should reject max_adjustment_factor = 0");
}

/// Test that parameter update validation catches max < min factor
#[test]
fn test_parameter_update_rejects_max_less_than_min() {
    let result = DifficultyParameterUpdateData::new_with_factors(
        604800, 1008,
        Some(8),  // min = 8
        Some(4),  // max = 4 (invalid: less than min)
    );
    
    assert!(result.is_err(), "Should reject max_adjustment_factor < min_adjustment_factor");
    let err = result.unwrap_err();
    assert!(
        err.contains("max_adjustment_factor"),
        "Error should mention max_adjustment_factor: {}",
        err
    );
}

/// Test target_block_time_secs calculation
#[test]
fn test_parameter_update_target_block_time() {
    let update = DifficultyParameterUpdateData::new(
        604800,  // 1 week = 604800 seconds
        1008,    // 1008 blocks
    ).unwrap();
    
    // 604800 / 1008 = 600 seconds = 10 minutes
    assert_eq!(
        update.target_block_time_secs(),
        600,
        "Target block time should be 10 minutes (600 seconds)"
    );
}

/// Test multiple parameter updates in sequence
#[test]
fn test_multiple_parameter_updates_sequence() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Initial config
    let initial_config = blockchain.difficulty_config.clone();
    assert_eq!(initial_config.target_timespan, 14 * 24 * 60 * 60);
    
    // First update: reduce to 1 week
    let config1 = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,  // 1 week
        1008,
        4,
        4,
        0,
    ).unwrap();
    blockchain.set_difficulty_config(config1).unwrap();
    assert_eq!(blockchain.difficulty_config.target_timespan, 7 * 24 * 60 * 60);
    
    // Second update: reduce adjustment interval
    let config2 = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,
        504,  // 504 blocks
        4,
        4,
        0,
    ).unwrap();
    blockchain.set_difficulty_config(config2).unwrap();
    assert_eq!(blockchain.difficulty_config.adjustment_interval, 504);
    
    // Third update: change factors
    let config3 = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,
        504,
        2,  // Max 2x decrease
        8,  // Max 8x increase
        0,
    ).unwrap();
    blockchain.set_difficulty_config(config3).unwrap();
    assert_eq!(blockchain.difficulty_config.max_difficulty_decrease_factor, 2);
    assert_eq!(blockchain.difficulty_config.max_difficulty_increase_factor, 8);
}

/// Test that parameter update reflects in next difficulty adjustment
#[test]
fn test_parameter_update_affects_next_adjustment() {
    let initial_difficulty = 1000u32;
    let actual_timespan = 7 * 24 * 60 * 60u64; // 1 week (half of 2-week target)
    
    // With default config (2-week target), 1-week actual = blocks too fast = increase
    let default_config = DifficultyConfig::default();
    let result_default = adjust_difficulty_with_config(initial_difficulty, actual_timespan, &default_config);
    
    // With 1-week target config, 1-week actual = on target = no change
    let custom_config = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,  // 1 week target
        1008,
        4,
        4,
        0,
    ).unwrap();
    let result_custom = adjust_difficulty_with_config(initial_difficulty, actual_timespan, &custom_config);
    
    // Default should increase difficulty, custom should keep it the same
    assert!(
        result_default > initial_difficulty,
        "Default config should increase difficulty for fast blocks"
    );
    assert_eq!(
        result_custom, initial_difficulty,
        "Custom config (matching target) should not change difficulty"
    );
    assert_ne!(
        result_default, result_custom,
        "Different configs should produce different results"
    );
}

// ============================================================================
// VALIDATION TESTS
// Test validation of DifficultyConfig and DifficultyParameterUpdateData.
// ============================================================================

/// Test that DifficultyConfig rejects target_timespan = 0
#[test]
fn test_config_rejects_zero_target_timespan() {
    let result = DifficultyConfig::with_params(
        0,     // Invalid: zero target_timespan
        2016,
        4,
        4,
        0,
    );
    
    assert!(result.is_err(), "Should reject target_timespan = 0");
    let err = result.unwrap_err();
    assert!(
        err.contains("target_timespan"),
        "Error should mention target_timespan: {}",
        err
    );
}

/// Test that DifficultyConfig rejects adjustment_interval = 0
#[test]
fn test_config_rejects_zero_adjustment_interval() {
    let result = DifficultyConfig::with_params(
        604800,
        0,     // Invalid: zero adjustment_interval
        4,
        4,
        0,
    );
    
    assert!(result.is_err(), "Should reject adjustment_interval = 0");
    let err = result.unwrap_err();
    assert!(
        err.contains("adjustment_interval"),
        "Error should mention adjustment_interval: {}",
        err
    );
}

/// Test that DifficultyConfig rejects adjustment factors < 1
#[test]
fn test_config_rejects_zero_adjustment_factors() {
    // Zero decrease factor
    let result = DifficultyConfig::with_params(
        604800, 2016,
        0,  // Invalid: zero max_difficulty_decrease_factor
        4,
        0,
    );
    assert!(result.is_err(), "Should reject max_difficulty_decrease_factor = 0");
    
    // Zero increase factor
    let result = DifficultyConfig::with_params(
        604800, 2016,
        4,
        0,  // Invalid: zero max_difficulty_increase_factor
        0,
    );
    assert!(result.is_err(), "Should reject max_difficulty_increase_factor = 0");
}

/// Test that DifficultyConfig rejects target_timespan > 1 year
#[test]
fn test_config_rejects_excessive_target_timespan() {
    let one_year_plus_one = 365 * 24 * 60 * 60 + 1;
    
    let result = DifficultyConfig::with_params(
        one_year_plus_one,  // Invalid: exceeds 1 year
        2016,
        4,
        4,
        0,
    );
    
    assert!(result.is_err(), "Should reject target_timespan > 1 year");
    let err = result.unwrap_err();
    assert!(
        err.contains("year") || err.contains("exceed"),
        "Error should mention the limit: {}",
        err
    );
}

/// Test that DifficultyConfig rejects adjustment_interval > 1,000,000
#[test]
fn test_config_rejects_excessive_adjustment_interval() {
    let result = DifficultyConfig::with_params(
        604800,
        1_000_001,  // Invalid: exceeds 1,000,000
        4,
        4,
        0,
    );
    
    assert!(result.is_err(), "Should reject adjustment_interval > 1,000,000");
    let err = result.unwrap_err();
    assert!(
        err.contains("1,000,000") || err.contains("exceed"),
        "Error should mention the limit: {}",
        err
    );
}

/// Test that DifficultyConfig rejects adjustment factors > 100
#[test]
fn test_config_rejects_excessive_adjustment_factors() {
    // Excessive decrease factor
    let result = DifficultyConfig::with_params(
        604800, 2016,
        101,  // Invalid: exceeds 100
        4,
        0,
    );
    assert!(result.is_err(), "Should reject max_difficulty_decrease_factor > 100");
    
    // Excessive increase factor
    let result = DifficultyConfig::with_params(
        604800, 2016,
        4,
        101,  // Invalid: exceeds 100
        0,
    );
    assert!(result.is_err(), "Should reject max_difficulty_increase_factor > 100");
}

/// Test that DifficultyConfig accepts valid boundary values
#[test]
fn test_config_accepts_boundary_values() {
    // Minimum valid values
    let min_config = DifficultyConfig::with_params(
        1,       // Minimum target_timespan (1 second)
        1,       // Minimum adjustment_interval (1 block)
        1,       // Minimum factor
        1,       // Minimum factor
        0,
    );
    assert!(min_config.is_ok(), "Should accept minimum valid values");
    
    // Maximum valid values
    let max_config = DifficultyConfig::with_params(
        365 * 24 * 60 * 60,  // Maximum: 1 year
        1_000_000,           // Maximum: 1,000,000 blocks
        100,                 // Maximum factor
        100,                 // Maximum factor
        u64::MAX,            // Any height is valid
    );
    assert!(max_config.is_ok(), "Should accept maximum valid values");
}

/// Test that DifficultyConfig accepts asymmetric factors at boundary
#[test]
fn test_config_accepts_asymmetric_boundary_factors() {
    // Maximum asymmetric: 1 and 100
    let asymmetric_config = DifficultyConfig::with_params(
        604800,
        2016,
        1,    // Minimum decrease (no decrease allowed)
        100,  // Maximum increase
        0,
    );
    assert!(asymmetric_config.is_ok(), "Should accept asymmetric factors");
    
    // Reverse asymmetric: 100 and 1
    let reverse_asymmetric = DifficultyConfig::with_params(
        604800,
        2016,
        100,  // Maximum decrease
        1,    // Minimum increase (no increase allowed)
        0,
    );
    assert!(reverse_asymmetric.is_ok(), "Should accept reverse asymmetric factors");
}

// ============================================================================
// CLAMPING TESTS
// Verify clamping behavior for different factor configurations.
// ============================================================================

/// Test that blocks too fast trigger max increase (4x default)
#[test]
fn test_clamping_fast_blocks_default_4x_max_increase() {
    let config = DifficultyConfig::default();
    let current_difficulty = 1000u32;
    
    // Extremely fast blocks (1/100 of target time)
    let very_fast_timespan = config.target_timespan / 100;
    
    let new_difficulty = adjust_difficulty_with_config(current_difficulty, very_fast_timespan, &config);
    
    // Due to clamping, max increase is 4x
    assert!(
        new_difficulty <= current_difficulty * 4,
        "Difficulty increase should be clamped to 4x max: {} > {}",
        new_difficulty,
        current_difficulty * 4
    );
    
    // But it should still increase
    assert!(
        new_difficulty > current_difficulty,
        "Difficulty should increase for fast blocks"
    );
}

/// Test that blocks too slow trigger max decrease (1/4x default)
#[test]
fn test_clamping_slow_blocks_default_4x_max_decrease() {
    let config = DifficultyConfig::default();
    let current_difficulty = 1000u32;
    
    // Extremely slow blocks (100x target time)
    let very_slow_timespan = config.target_timespan * 100;
    
    let new_difficulty = adjust_difficulty_with_config(current_difficulty, very_slow_timespan, &config);
    
    // Due to clamping, max decrease is 1/4 (difficulty can't go below 1/4)
    // new_difficulty >= current_difficulty / 4
    assert!(
        new_difficulty >= current_difficulty / 4,
        "Difficulty decrease should be clamped: {} < {}",
        new_difficulty,
        current_difficulty / 4
    );
    
    // But it should still decrease
    assert!(
        new_difficulty < current_difficulty,
        "Difficulty should decrease for slow blocks"
    );
}

/// Test custom 2x adjustment factors
#[test]
fn test_clamping_custom_2x_factors() {
    let config = DifficultyConfig::with_params(
        604800,  // 1 week target
        1008,
        2,       // Max 2x decrease
        2,       // Max 2x increase
        0,
    ).unwrap();
    
    let current_difficulty = 1000u32;
    
    // Very fast blocks
    let very_fast = config.target_timespan / 100;
    let new_diff_fast = adjust_difficulty_with_config(current_difficulty, very_fast, &config);
    assert!(
        new_diff_fast <= current_difficulty * 2,
        "With 2x factor, max increase should be 2x: {} > {}",
        new_diff_fast,
        current_difficulty * 2
    );
    
    // Very slow blocks
    let very_slow = config.target_timespan * 100;
    let new_diff_slow = adjust_difficulty_with_config(current_difficulty, very_slow, &config);
    assert!(
        new_diff_slow >= current_difficulty / 2,
        "With 2x factor, max decrease should be 1/2: {} < {}",
        new_diff_slow,
        current_difficulty / 2
    );
}

/// Test custom 8x adjustment factors
#[test]
fn test_clamping_custom_8x_factors() {
    let config = DifficultyConfig::with_params(
        604800,
        1008,
        8,       // Max 8x decrease
        8,       // Max 8x increase
        0,
    ).unwrap();
    
    let current_difficulty = 10000u32;  // Use larger value for precision
    
    // Very fast blocks
    let very_fast = config.target_timespan / 100;
    let new_diff_fast = adjust_difficulty_with_config(current_difficulty, very_fast, &config);
    assert!(
        new_diff_fast <= current_difficulty * 8,
        "With 8x factor, max increase should be 8x"
    );
    
    // Very slow blocks
    let very_slow = config.target_timespan * 100;
    let new_diff_slow = adjust_difficulty_with_config(current_difficulty, very_slow, &config);
    assert!(
        new_diff_slow >= current_difficulty / 8,
        "With 8x factor, max decrease should be 1/8"
    );
}

/// Test asymmetric adjustment factors (different increase vs decrease limits)
#[test]
fn test_clamping_asymmetric_factors() {
    // Allow large increases but limit decreases
    let config = DifficultyConfig::with_params(
        604800,
        1008,
        2,       // Max 2x decrease (conservative)
        8,       // Max 8x increase (aggressive)
        0,
    ).unwrap();
    
    let current_difficulty = 10000u32;
    
    // Fast blocks - should allow up to 8x increase
    let very_fast = config.target_timespan / 100;
    let new_diff_fast = adjust_difficulty_with_config(current_difficulty, very_fast, &config);
    // Clamped timespan = target / 8, so difficulty = current * target / (target/8) = current * 8
    assert!(
        new_diff_fast <= current_difficulty * 8,
        "Asymmetric: max increase should be 8x"
    );
    assert!(
        new_diff_fast > current_difficulty * 2,
        "Asymmetric: increase should be able to exceed 2x"
    );
    
    // Slow blocks - should limit to 2x decrease
    let very_slow = config.target_timespan * 100;
    let new_diff_slow = adjust_difficulty_with_config(current_difficulty, very_slow, &config);
    assert!(
        new_diff_slow >= current_difficulty / 2,
        "Asymmetric: max decrease should be 1/2"
    );
}

/// Test extreme timespans are properly clamped
#[test]
fn test_clamping_extreme_timespans() {
    let config = DifficultyConfig::default();
    let current_difficulty = 1000u32;
    
    // Zero timespan (impossible in practice, but test boundary)
    // Note: clamp_timespan prevents division by zero by clamping to minimum
    let clamped_zero = config.clamp_timespan(0);
    assert!(
        clamped_zero > 0,
        "Zero timespan should be clamped to minimum: {}",
        clamped_zero
    );
    assert_eq!(
        clamped_zero,
        config.target_timespan / config.max_difficulty_increase_factor,
        "Zero should clamp to target/increase_factor"
    );
    
    // u64::MAX timespan (extremely slow)
    let clamped_max = config.clamp_timespan(u64::MAX);
    assert_eq!(
        clamped_max,
        config.target_timespan * config.max_difficulty_decrease_factor,
        "MAX should clamp to target*decrease_factor"
    );
    
    // Verify these clamped values produce valid difficulty adjustments
    let diff_from_zero = adjust_difficulty_with_config(current_difficulty, 0, &config);
    assert!(diff_from_zero > 0, "Should produce valid difficulty from zero timespan");
    
    let diff_from_max = adjust_difficulty_with_config(current_difficulty, u64::MAX, &config);
    assert!(diff_from_max > 0, "Should produce valid difficulty from MAX timespan");
}

/// Test factors of 1 (no adjustment allowed)
#[test]
fn test_clamping_factor_of_one() {
    // Factor of 1 means no adjustment is allowed
    let config = DifficultyConfig::with_params(
        604800,
        1008,
        1,  // No decrease allowed
        1,  // No increase allowed
        0,
    ).unwrap();
    
    let current_difficulty = 1000u32;
    
    // With factor of 1, clamped timespan always equals target timespan
    // So new_difficulty = current * target / target = current
    
    // Fast blocks (should not increase)
    let fast_timespan = config.target_timespan / 10;
    let clamped_fast = config.clamp_timespan(fast_timespan);
    assert_eq!(
        clamped_fast, config.target_timespan,
        "With factor 1, all timespans should clamp to target"
    );
    
    let new_diff_fast = adjust_difficulty_with_config(current_difficulty, fast_timespan, &config);
    assert_eq!(
        new_diff_fast, current_difficulty,
        "With factor 1, difficulty should not change for fast blocks"
    );
    
    // Slow blocks (should not decrease)
    let slow_timespan = config.target_timespan * 10;
    let new_diff_slow = adjust_difficulty_with_config(current_difficulty, slow_timespan, &config);
    assert_eq!(
        new_diff_slow, current_difficulty,
        "With factor 1, difficulty should not change for slow blocks"
    );
}

/// Test clamp_timespan boundary precision
#[test]
fn test_clamp_timespan_boundary_precision() {
    let config = DifficultyConfig::with_params(
        1000,  // Simple target for easy math
        100,
        4,
        4,
        0,
    ).unwrap();
    
    // Exact boundaries
    let min_boundary = 1000 / 4; // 250
    let max_boundary = 1000 * 4; // 4000
    
    // At exact minimum - should not clamp
    assert_eq!(config.clamp_timespan(min_boundary), min_boundary);
    
    // Below minimum - should clamp up
    assert_eq!(config.clamp_timespan(min_boundary - 1), min_boundary);
    assert_eq!(config.clamp_timespan(0), min_boundary);
    
    // At exact maximum - should not clamp
    assert_eq!(config.clamp_timespan(max_boundary), max_boundary);
    
    // Above maximum - should clamp down
    assert_eq!(config.clamp_timespan(max_boundary + 1), max_boundary);
    assert_eq!(config.clamp_timespan(u64::MAX), max_boundary);
    
    // Within range - should not clamp
    assert_eq!(config.clamp_timespan(500), 500);
    assert_eq!(config.clamp_timespan(1000), 1000);
    assert_eq!(config.clamp_timespan(2000), 2000);
}

// ============================================================================
// STATE PERSISTENCE TESTS
// Verify serialization, deserialization, and state preservation.
// ============================================================================

/// Test DifficultyConfig serializes/deserializes correctly with JSON
#[test]
fn test_difficulty_config_json_serialization() {
    let config = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,
        1008,
        2,
        8,
        12345,
    ).unwrap();
    
    // Serialize to JSON
    let json = serde_json::to_string(&config).expect("JSON serialization should succeed");
    
    // Verify JSON contains expected fields
    assert!(json.contains("target_timespan"), "JSON should contain target_timespan");
    assert!(json.contains("adjustment_interval"), "JSON should contain adjustment_interval");
    assert!(json.contains("last_updated_at_height"), "JSON should contain last_updated_at_height");
    
    // Deserialize back
    let deserialized: DifficultyConfig = serde_json::from_str(&json)
        .expect("JSON deserialization should succeed");
    
    // Verify all fields match
    assert_eq!(config, deserialized, "Deserialized config should match original");
}

/// Test DifficultyConfig serializes/deserializes correctly with bincode
#[test]
fn test_difficulty_config_bincode_serialization() {
    let config = DifficultyConfig::with_params(
        14 * 24 * 60 * 60,
        2016,
        4,
        4,
        99999,
    ).unwrap();
    
    // Serialize to bincode
    let bytes = bincode::serialize(&config).expect("Bincode serialization should succeed");
    
    // Deserialize back
    let deserialized: DifficultyConfig = bincode::deserialize(&bytes)
        .expect("Bincode deserialization should succeed");
    
    // Verify all fields match
    assert_eq!(config, deserialized, "Bincode deserialized config should match original");
}

/// Test DifficultyParameterUpdateData serializes/deserializes correctly
#[test]
fn test_parameter_update_data_serialization() {
    let update = DifficultyParameterUpdateData::new_with_factors(
        604800,
        1008,
        Some(2),
        Some(8),
    ).unwrap();
    
    // JSON
    let json = serde_json::to_string(&update).expect("JSON serialization should succeed");
    let from_json: DifficultyParameterUpdateData = serde_json::from_str(&json).unwrap();
    assert_eq!(update, from_json, "JSON round-trip should preserve data");
    
    // Bincode
    let bytes = bincode::serialize(&update).expect("Bincode serialization should succeed");
    let from_bincode: DifficultyParameterUpdateData = bincode::deserialize(&bytes).unwrap();
    assert_eq!(update, from_bincode, "Bincode round-trip should preserve data");
}

/// Test last_updated_at_height is preserved across serialization
#[test]
fn test_last_updated_at_height_preserved() {
    let original_height = 123456789u64;
    
    let config = DifficultyConfig {
        target_timespan: 604800,
        adjustment_interval: 1008,
        max_difficulty_decrease_factor: 4,
        max_difficulty_increase_factor: 4,
        last_updated_at_height: original_height,
    };
    
    // JSON round-trip
    let json = serde_json::to_string(&config).unwrap();
    let from_json: DifficultyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(
        from_json.last_updated_at_height, original_height,
        "last_updated_at_height should survive JSON round-trip"
    );
    
    // Bincode round-trip
    let bytes = bincode::serialize(&config).unwrap();
    let from_bincode: DifficultyConfig = bincode::deserialize(&bytes).unwrap();
    assert_eq!(
        from_bincode.last_updated_at_height, original_height,
        "last_updated_at_height should survive bincode round-trip"
    );
}

/// Test config with extreme values serializes correctly
#[test]
fn test_config_extreme_values_serialization() {
    // Minimum values
    let min_config = DifficultyConfig::with_params(
        1, 1, 1, 1, 0,
    ).unwrap();
    
    let json = serde_json::to_string(&min_config).unwrap();
    let from_json: DifficultyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(min_config, from_json, "Minimum config should serialize correctly");
    
    // Maximum values
    let max_config = DifficultyConfig::with_params(
        365 * 24 * 60 * 60,
        1_000_000,
        100,
        100,
        u64::MAX,
    ).unwrap();
    
    let bytes = bincode::serialize(&max_config).unwrap();
    let from_bincode: DifficultyConfig = bincode::deserialize(&bytes).unwrap();
    assert_eq!(max_config, from_bincode, "Maximum config should serialize correctly");
}

/// Test that default config matches after deserialization
#[test]
fn test_default_config_serialization_stability() {
    let default_config = DifficultyConfig::default();
    
    // Serialize and deserialize
    let json = serde_json::to_string(&default_config).unwrap();
    let deserialized: DifficultyConfig = serde_json::from_str(&json).unwrap();
    
    // Should match the default exactly
    assert_eq!(
        deserialized, default_config,
        "Default config should be stable across serialization"
    );
    
    // Also verify individual fields for backward compatibility
    assert_eq!(deserialized.target_timespan, 14 * 24 * 60 * 60);
    assert_eq!(deserialized.adjustment_interval, 2016);
    assert_eq!(deserialized.max_difficulty_decrease_factor, 4);
    assert_eq!(deserialized.max_difficulty_increase_factor, 4);
    assert_eq!(deserialized.last_updated_at_height, 0);
}

// ============================================================================
// INTEGRATION TESTS
// Full governance flow and integration with blockchain.
// ============================================================================

/// Test full flow: update config -> verify adjustment uses new parameters
#[test]
fn test_integration_config_update_affects_adjustment() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Initial state: default 2-week target
    let initial_difficulty = 1000u32;
    let one_week_timespan = 7 * 24 * 60 * 60u64;
    
    // With default config (2 weeks), 1 week = fast blocks = difficulty increases
    let adjustment_before = adjust_difficulty_with_config(
        initial_difficulty,
        one_week_timespan,
        &blockchain.difficulty_config,
    );
    assert!(
        adjustment_before > initial_difficulty,
        "Before update: 1-week actual with 2-week target should increase difficulty"
    );
    
    // Update config to 1-week target
    let new_config = DifficultyConfig::with_params(
        7 * 24 * 60 * 60,  // 1 week target
        1008,
        4,
        4,
        0,
    ).unwrap();
    blockchain.set_difficulty_config(new_config).unwrap();
    
    // After update: 1 week = on target = no change
    let adjustment_after = adjust_difficulty_with_config(
        initial_difficulty,
        one_week_timespan,
        &blockchain.difficulty_config,
    );
    assert_eq!(
        adjustment_after, initial_difficulty,
        "After update: 1-week actual with 1-week target should not change difficulty"
    );
}

/// Test that validators would use updated parameters
#[test]
fn test_integration_validators_use_updated_parameters() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Simulate a parameter update that changes adjustment behavior
    let custom_config = DifficultyConfig::with_params(
        3600,   // 1 hour target
        10,     // Every 10 blocks
        2,      // Max 2x decrease
        2,      // Max 2x increase
        100,
    ).unwrap();
    blockchain.set_difficulty_config(custom_config).unwrap();
    
    // Verify the config is accessible (validators would read this)
    assert_eq!(blockchain.difficulty_config.target_timespan, 3600);
    assert_eq!(blockchain.difficulty_config.adjustment_interval, 10);
    assert_eq!(blockchain.difficulty_config.max_difficulty_decrease_factor, 2);
    assert_eq!(blockchain.difficulty_config.max_difficulty_increase_factor, 2);
    
    // Verify target_block_time calculation would be correct for validators
    let expected_block_time = 3600 / 10; // 360 seconds = 6 minutes
    assert_eq!(
        blockchain.difficulty_config.target_block_time(),
        expected_block_time,
        "Validators should calculate correct target block time"
    );
}

/// Test that blockchain height is recorded when config updates
#[test]
fn test_integration_height_tracking_on_update() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Initial height should be 0
    assert_eq!(blockchain.height, 0);
    assert_eq!(blockchain.difficulty_config.last_updated_at_height, 0);
    
    // Update config
    let config1 = DifficultyConfig::with_params(
        604800, 1008, 4, 4, 0,
    ).unwrap();
    blockchain.set_difficulty_config(config1).unwrap();
    
    // last_updated_at_height should match blockchain height
    assert_eq!(
        blockchain.difficulty_config.last_updated_at_height,
        blockchain.height,
        "last_updated_at_height should be set to current blockchain height"
    );
}

/// Test DifficultyParameterUpdateData builder pattern
#[test]
fn test_parameter_update_builder_pattern() {
    let update = DifficultyParameterUpdateData::new(604800, 1008)
        .unwrap()
        .with_min_factor(2)
        .with_max_factor(8);
    
    assert_eq!(update.target_timespan, 604800);
    assert_eq!(update.adjustment_interval, 1008);
    assert_eq!(update.min_adjustment_factor, Some(2));
    assert_eq!(update.max_adjustment_factor, Some(8));
    
    // Validation should still pass
    assert!(update.validate().is_ok());
}

/// Test that config update rejection doesn't affect current state
#[test]
fn test_integration_rejected_update_preserves_state() {
    let mut blockchain = Blockchain::new().unwrap();
    
    // Store original config
    let original_config = blockchain.difficulty_config.clone();
    
    // Attempt to set invalid config
    let invalid_config = DifficultyConfig {
        target_timespan: 0,  // Invalid!
        adjustment_interval: 1008,
        max_difficulty_decrease_factor: 4,
        max_difficulty_increase_factor: 4,
        last_updated_at_height: 0,
    };
    
    let result = blockchain.set_difficulty_config(invalid_config);
    assert!(result.is_err(), "Should reject invalid config");
    
    // Original config should be preserved
    assert_eq!(
        blockchain.difficulty_config, original_config,
        "Invalid update should not affect current config"
    );
}

/// Test difficulty adjustment never produces zero
#[test]
fn test_integration_difficulty_never_zero() {
    let config = DifficultyConfig::default();
    
    // Even with extreme scenarios, difficulty should never be zero
    let test_cases = [
        (1u32, 1u64),                    // Minimum difficulty, fast blocks
        (1u32, u64::MAX),                // Minimum difficulty, slow blocks
        (u32::MAX, 1u64),                // Maximum difficulty, fast blocks
        (u32::MAX, u64::MAX),            // Maximum difficulty, slow blocks
        (1000u32, config.target_timespan),  // Normal case
    ];
    
    for (current_diff, timespan) in test_cases {
        let new_diff = adjust_difficulty_with_config(current_diff, timespan, &config);
        assert!(
            new_diff > 0,
            "Difficulty should never be zero: current={}, timespan={}, result={}",
            current_diff, timespan, new_diff
        );
    }
}

/// Test that clamp_timespan handles potential overflow correctly
#[test]
fn test_integration_clamp_timespan_overflow_safety() {
    // Use a config where target_timespan * max_factor could overflow
    let config = DifficultyConfig {
        target_timespan: u64::MAX / 2,  // Large but not max
        adjustment_interval: 2016,
        max_difficulty_decrease_factor: 4,  // 4 * (MAX/2) would overflow
        max_difficulty_increase_factor: 4,
        last_updated_at_height: 0,
    };
    
    // This should use saturating_mul and not panic
    let clamped = config.clamp_timespan(u64::MAX);
    
    // Result should be some large value, not wrapped around
    assert!(
        clamped > config.target_timespan,
        "Clamped value should be larger than target for slow blocks"
    );
}

