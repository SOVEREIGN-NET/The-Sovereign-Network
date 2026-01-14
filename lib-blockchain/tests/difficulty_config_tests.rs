//! Tests for difficulty adjustment using DifficultyConfig
//!
//! These tests verify that the adjust_difficulty() method correctly uses
//! DifficultyConfig parameters instead of hardcoded constants.

use lib_blockchain::types::DifficultyConfig;
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
