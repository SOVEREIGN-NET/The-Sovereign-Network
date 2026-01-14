//! Difficulty calculation and proof-of-work utilities
//!
//! Provides basic difficulty calculation for proof-of-work mining.
//! Advanced consensus mechanisms are handled by lib-consensus package.

use crate::types::Hash;
use serde::{Serialize, Deserialize};
use tracing::warn;

/// Difficulty representation for proof-of-work
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difficulty(u32);

impl Difficulty {
    /// Create a new difficulty from bits
    pub fn from_bits(bits: u32) -> Self {
        Difficulty(bits)
    }

    /// Get the difficulty bits
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Get the target hash for this difficulty
    pub fn target(&self) -> [u8; 32] {
        calculate_target(self.0)
    }

    /// Check if a hash meets this difficulty target
    pub fn check_hash(&self, hash: &Hash) -> bool {
        let target = Hash::from_slice(&self.target());
        hash <= &target
    }

    /// Check if a hash meets this difficulty target (alias for check_hash)
    pub fn meets_target(&self, hash: &Hash) -> bool {
        self.check_hash(hash)
    }

    /// Get minimum difficulty (hardest)
    pub fn minimum() -> Self {
        Difficulty(0x207fffff)
    }

    /// Get maximum difficulty (easiest)
    pub fn maximum() -> Self {
        Difficulty(0x1d00ffff)
    }

    /// Calculate work done for this difficulty
    pub fn work(&self) -> u128 {
        difficulty_to_work(self.0)
    }

    /// Adjust difficulty based on timing
    pub fn adjust(&self, actual_timespan: u64, target_timespan: u64) -> Self {
        let new_bits = adjust_difficulty(self.0, actual_timespan, target_timespan);
        Difficulty(new_bits)
    }
}

impl Default for Difficulty {
    fn default() -> Self {
        Difficulty::maximum()
    }
}

impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Governance-controlled difficulty adjustment parameters for PoUW consensus
///
/// This struct stores configurable parameters that control how mining difficulty
/// adjusts over time. These parameters can be updated through governance proposals
/// to adapt to changing network conditions.
///
/// # Design Principles
///
/// - **Determinism**: All calculations depend only on chain data, not wall-clock time
/// - **Safety**: Clamping prevents extreme difficulty swings (max 4x by default)
/// - **Governance**: Parameters can only be changed through DAO proposals
/// - **Auditability**: `last_updated_at_height` tracks when config was modified
///
/// # Default Values
///
/// | Parameter | Default | Rationale |
/// |-----------|---------|----------|
/// | `target_timespan` | 1,209,600 sec (14 days) | Bitcoin-compatible |
/// | `adjustment_interval` | 2016 blocks | ~2 weeks at 10-min blocks |
/// | `max_difficulty_decrease_factor` | 4 | Prevents >75% difficulty drop |
/// | `max_difficulty_increase_factor` | 4 | Prevents >4x difficulty jump |
///
/// # Example
///
/// ```rust
/// use lib_blockchain::types::DifficultyConfig;
///
/// // Create with defaults (Bitcoin-compatible)
/// let config = DifficultyConfig::default();
/// assert_eq!(config.target_timespan, 14 * 24 * 60 * 60); // 2 weeks
/// assert_eq!(config.adjustment_interval, 2016);
/// assert_eq!(config.target_block_time(), 600); // 10 minutes
///
/// // Create with custom parameters
/// let custom = DifficultyConfig::with_params(
///     7 * 24 * 60 * 60,  // 1 week target
///     1008,              // 1008 blocks
///     4,                 // max 4x decrease
///     4,                 // max 4x increase
///     0,                 // genesis height
/// ).expect("Valid parameters");
/// assert_eq!(custom.target_block_time(), 600); // Still 10 minutes
///
/// // Clamping prevents extreme adjustments
/// let fast_timespan = 1000; // Much faster than target
/// let clamped = config.clamp_timespan(fast_timespan);
/// assert!(clamped >= config.target_timespan / 4); // Clamped to min
/// ```
///
/// # Governance Integration
///
/// To modify difficulty parameters through governance:
///
/// 1. Create a `DifficultyParameterUpdateData` proposal
/// 2. Submit through DAO with `DaoProposalType::DifficultyParameterUpdate`
/// 3. After voting passes and timelock expires, call `apply_difficulty_parameter_update()`
///
/// See [`DifficultyParameterUpdateData`](crate::types::DifficultyParameterUpdateData) for proposal creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifficultyConfig {
    /// Target timespan for difficulty adjustment period (in seconds)
    /// Default: 14 days (1,209,600 seconds)
    pub target_timespan: u64,

    /// Number of blocks between difficulty adjustments
    /// Default: 2016 blocks (Bitcoin-style)
    pub adjustment_interval: u64,

    /// Maximum factor by which difficulty can decrease per adjustment
    /// Value of 4 means difficulty can decrease by at most 4x per adjustment
    /// (i.e., actual_timespan is clamped to at most target_timespan * 4)
    /// Default: 4
    pub max_difficulty_decrease_factor: u64,

    /// Maximum factor by which difficulty can increase per adjustment
    /// Value of 4 means difficulty can increase by at most 4x per adjustment
    /// (i.e., actual_timespan is clamped to at least target_timespan / 4)
    /// Default: 4
    pub max_difficulty_increase_factor: u64,

    /// Block height at which this configuration was last updated
    /// Used for governance tracking and auditability
    pub last_updated_at_height: u64,
}

impl DifficultyConfig {
    /// Create a new DifficultyConfig with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new DifficultyConfig with custom parameters
    ///
    /// Validates all parameters before creating the configuration.
    /// Returns an error if any parameters are invalid.
    ///
    /// # Errors
    /// Returns a string error if validation fails (e.g., zero values, values exceeding limits)
    pub fn with_params(
        target_timespan: u64,
        adjustment_interval: u64,
        max_difficulty_decrease_factor: u64,
        max_difficulty_increase_factor: u64,
        last_updated_at_height: u64,
    ) -> Result<Self, String> {
        let config = Self {
            target_timespan,
            adjustment_interval,
            max_difficulty_decrease_factor,
            max_difficulty_increase_factor,
            last_updated_at_height,
        };
        config.validate()?;
        Ok(config)
    }

    /// Get the target block time in seconds
    /// Calculated as target_timespan / adjustment_interval
    pub fn target_block_time(&self) -> u64 {
        if self.adjustment_interval == 0 {
            warn!("DifficultyConfig has adjustment_interval=0, using default 10 minute block time");
            return 600; // Default to 10 minutes if misconfigured
        }
        self.target_timespan / self.adjustment_interval
    }

    /// Calculate the clamped timespan for difficulty adjustment
    ///
    /// This prevents extreme difficulty changes by clamping the actual timespan
    /// to be within [target_timespan / max_difficulty_increase_factor, target_timespan * max_difficulty_decrease_factor]
    pub fn clamp_timespan(&self, actual_timespan: u64) -> u64 {
        // If blocks came too fast, difficulty increases (timespan clamped to minimum)
        let min_timespan = self.target_timespan / self.max_difficulty_increase_factor.max(1);
        // If blocks came too slow, difficulty decreases (timespan clamped to maximum)
        let max_timespan = self.target_timespan.saturating_mul(self.max_difficulty_decrease_factor);

        actual_timespan.clamp(min_timespan, max_timespan)
    }

    /// Validate the configuration parameters
    ///
    /// Returns an error if any parameters are invalid or would cause issues
    pub fn validate(&self) -> Result<(), String> {
        if self.target_timespan == 0 {
            return Err("target_timespan must be greater than 0".to_string());
        }

        if self.adjustment_interval == 0 {
            return Err("adjustment_interval must be greater than 0".to_string());
        }

        if self.max_difficulty_decrease_factor == 0 {
            return Err("max_difficulty_decrease_factor must be greater than 0".to_string());
        }

        if self.max_difficulty_increase_factor == 0 {
            return Err("max_difficulty_increase_factor must be greater than 0".to_string());
        }

        // Check for reasonable limits
        if self.target_timespan > 365 * 24 * 60 * 60 {
            return Err("target_timespan cannot exceed 1 year".to_string());
        }

        if self.adjustment_interval > 1_000_000 {
            return Err("adjustment_interval cannot exceed 1,000,000 blocks".to_string());
        }

        if self.max_difficulty_decrease_factor > 100 || self.max_difficulty_increase_factor > 100 {
            return Err("difficulty adjustment factors cannot exceed 100".to_string());
        }

        Ok(())
    }
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            // 14 days in seconds (same as Bitcoin)
            target_timespan: 14 * 24 * 60 * 60,

            // 2016 blocks (Bitcoin-style)
            adjustment_interval: 2016,

            // Maximum 4x decrease per adjustment (difficulty can quarter)
            max_difficulty_decrease_factor: 4,

            // Maximum 4x increase per adjustment (difficulty can quadruple)
            max_difficulty_increase_factor: 4,

            // Genesis block
            last_updated_at_height: 0,
        }
    }
}

/// Calculate target from difficulty bits (Bitcoin-style)
pub fn calculate_target(difficulty_bits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = (difficulty_bits >> 24) as usize;
    let mantissa = difficulty_bits & 0x00ffffff;
    
    if exponent <= 3 {
        let mantissa_bytes = mantissa.to_be_bytes();
        target[32 - 3..].copy_from_slice(&mantissa_bytes[1..]);
    } else if exponent < 32 {
        let mantissa_bytes = mantissa.to_be_bytes();
        target[32 - exponent..32 - exponent + 3].copy_from_slice(&mantissa_bytes[1..]);
    }
    
    target
}

/// Check if a hash meets the difficulty target
pub fn meets_difficulty(hash: &Hash, target: &Hash) -> bool {
    hash <= target
}

/// Calculate difficulty from a target hash
pub fn target_to_difficulty(target: &Hash) -> u32 {
    // Find the first non-zero byte
    let mut exponent = 32;
    for (i, &byte) in target.as_bytes().iter().enumerate() {
        if byte != 0 {
            exponent = 32 - i;
            break;
        }
    }
    
    if exponent < 3 {
        return 0; // Invalid target
    }
    
    // Get the first 3 bytes as mantissa
    let start_idx = 32 - exponent;
    let mut mantissa_bytes = [0u8; 4];
    mantissa_bytes[1..4].copy_from_slice(&target.as_bytes()[start_idx..start_idx + 3]);
    let mantissa = u32::from_be_bytes(mantissa_bytes);
    
    ((exponent as u32) << 24) | mantissa
}

/// Get the maximum target (easiest difficulty)
pub fn max_target() -> [u8; 32] {
    let mut target = [0u8; 32];
    target[0] = 0x1d;
    target[1] = 0x00;
    target[2] = 0xff;
    target[3] = 0xff;
    target
}

/// Get the minimum target (hardest difficulty)
pub fn min_target() -> [u8; 32] {
    let mut target = [0u8; 32];
    target[31] = 0x01;
    target
}

/// Difficulty adjustment calculation using DifficultyConfig
///
/// This is the preferred method that uses governance-controlled parameters.
pub fn adjust_difficulty_with_config(
    current_difficulty: u32,
    actual_timespan: u64,
    config: &DifficultyConfig,
) -> u32 {
    let clamped_timespan = config.clamp_timespan(actual_timespan);

    // Calculate new difficulty
    let new_difficulty =
        (current_difficulty as u64 * config.target_timespan / clamped_timespan) as u32;

    // Ensure difficulty doesn't go to zero
    new_difficulty.max(1)
}

/// Difficulty adjustment calculation (legacy function for backward compatibility)
///
/// For new code, prefer using `adjust_difficulty_with_config` with a `DifficultyConfig`.
pub fn adjust_difficulty(
    current_difficulty: u32,
    actual_timespan: u64,
    target_timespan: u64,
) -> u32 {
    // Use default config factors for backward compatibility
    let config = DifficultyConfig {
        target_timespan,
        adjustment_interval: 2016, // Not used in this calculation
        max_difficulty_decrease_factor: 4,
        max_difficulty_increase_factor: 4,
        last_updated_at_height: 0,
    };
    adjust_difficulty_with_config(current_difficulty, actual_timespan, &config)
}

/// Calculate work done for a given difficulty
pub fn difficulty_to_work(difficulty: u32) -> u128 {
    if difficulty == 0 {
        return 0;
    }
    
    // Work is approximately 2^256 / target
    let target = calculate_target(difficulty);
    let target_big = target.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128);
    
    if target_big == 0 {
        return u128::MAX;
    }
    
    // Simplified work calculation
    u128::MAX / target_big.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_calculation() {
        let difficulty = Difficulty::from_bits(0x1d00ffff);
        let target = difficulty.target();
        assert!(!target.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_meets_difficulty() {
        let easy_difficulty = Difficulty::maximum();
        let zero_hash = Hash::zero();
        assert!(easy_difficulty.check_hash(&zero_hash));
    }

    #[test]
    fn test_difficulty_adjustment() {
        let current_difficulty = Difficulty::from_bits(1000);
        let target_timespan = 600; // 10 minutes
        
        // If blocks come too fast, difficulty should increase
        let fast_timespan = 300; // 5 minutes
        let new_difficulty = current_difficulty.adjust(fast_timespan, target_timespan);
        assert!(new_difficulty.bits() > current_difficulty.bits());
        
        // If blocks come too slow, difficulty should decrease
        let slow_timespan = 1200; // 20 minutes
        let new_difficulty = current_difficulty.adjust(slow_timespan, target_timespan);
        assert!(new_difficulty.bits() < current_difficulty.bits());
    }

    #[test]
    fn test_difficulty_range() {
        let min_diff = Difficulty::minimum();
        let max_diff = Difficulty::maximum();
        
        assert!(min_diff.bits() > max_diff.bits()); // Lower bits = higher difficulty
    }

    #[test]
    fn test_difficulty_config_default() {
        let config = DifficultyConfig::default();

        assert_eq!(config.target_timespan, 14 * 24 * 60 * 60); // 14 days
        assert_eq!(config.adjustment_interval, 2016);
        assert_eq!(config.max_difficulty_decrease_factor, 4);
        assert_eq!(config.max_difficulty_increase_factor, 4);
        assert_eq!(config.last_updated_at_height, 0);
    }

    #[test]
    fn test_difficulty_config_target_block_time() {
        let config = DifficultyConfig::default();
        
        // 14 days / 2016 blocks = 600 seconds (10 minutes)
        assert_eq!(config.target_block_time(), 600);
    }

    #[test]
    fn test_difficulty_config_clamp_timespan() {
        let config = DifficultyConfig::default();
        
        // Target timespan is 14 days
        let target = 14 * 24 * 60 * 60;
        
        // Test clamping at minimum (target / 4)
        let too_fast = 1000;
        let clamped = config.clamp_timespan(too_fast);
        assert_eq!(clamped, target / 4);
        
        // Test clamping at maximum (target * 4)
        let too_slow = 100 * 24 * 60 * 60;
        let clamped = config.clamp_timespan(too_slow);
        assert_eq!(clamped, target * 4);
        
        // Test no clamping for normal values
        let normal = target;
        let clamped = config.clamp_timespan(normal);
        assert_eq!(clamped, normal);
    }

    #[test]
    fn test_difficulty_config_validation() {
        // Valid config should pass
        let valid_config = DifficultyConfig::default();
        assert!(valid_config.validate().is_ok());

        // Invalid target_timespan
        let mut invalid = DifficultyConfig::default();
        invalid.target_timespan = 0;
        assert!(invalid.validate().is_err());

        // Invalid adjustment_interval
        let mut invalid = DifficultyConfig::default();
        invalid.adjustment_interval = 0;
        assert!(invalid.validate().is_err());

        // Invalid max_difficulty_decrease_factor
        let mut invalid = DifficultyConfig::default();
        invalid.max_difficulty_decrease_factor = 0;
        assert!(invalid.validate().is_err());

        // Invalid max_difficulty_increase_factor
        let mut invalid = DifficultyConfig::default();
        invalid.max_difficulty_increase_factor = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_difficulty_config_serialization() {
        let config = DifficultyConfig::default();
        
        // Serialize to JSON
        let json = serde_json::to_string(&config).unwrap();
        
        // Deserialize back
        let deserialized: DifficultyConfig = serde_json::from_str(&json).unwrap();
        
        // Should be equal
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_difficulty_config_with_params() {
        let config = DifficultyConfig::with_params(
            7 * 24 * 60 * 60, // 7 days
            1008,             // Half of Bitcoin's interval
            2,                // Max 2x decrease
            2,                // Max 2x increase
            1000,             // Updated at block 1000
        ).expect("Valid parameters should not fail");

        assert_eq!(config.target_timespan, 7 * 24 * 60 * 60);
        assert_eq!(config.adjustment_interval, 1008);
        assert_eq!(config.max_difficulty_decrease_factor, 2);
        assert_eq!(config.max_difficulty_increase_factor, 2);
        assert_eq!(config.last_updated_at_height, 1000);
    }

    #[test]
    fn test_difficulty_config_with_params_invalid() {
        // Test that with_params validates parameters

        // Invalid: target_timespan = 0
        assert!(DifficultyConfig::with_params(0, 1008, 2, 2, 0).is_err());

        // Invalid: adjustment_interval = 0
        assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 0, 2, 2, 0).is_err());

        // Invalid: max_difficulty_decrease_factor = 0
        assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 1008, 0, 2, 0).is_err());

        // Invalid: max_difficulty_increase_factor = 0
        assert!(DifficultyConfig::with_params(7 * 24 * 60 * 60, 1008, 2, 0, 0).is_err());

        // Invalid: target_timespan exceeds 1 year
        assert!(DifficultyConfig::with_params(365 * 24 * 60 * 60 + 1, 1008, 2, 2, 0).is_err());
    }

    #[test]
    fn test_adjust_difficulty_with_config() {
        let config = DifficultyConfig::default();
        let current_difficulty = 1000u32;

        // If blocks come too fast (half the expected time), difficulty should increase
        let fast_timespan = config.target_timespan / 2;
        let new_difficulty = adjust_difficulty_with_config(current_difficulty, fast_timespan, &config);
        assert!(new_difficulty > current_difficulty);

        // If blocks come too slow (double the expected time), difficulty should decrease
        let slow_timespan = config.target_timespan * 2;
        let new_difficulty = adjust_difficulty_with_config(current_difficulty, slow_timespan, &config);
        assert!(new_difficulty < current_difficulty);

        // Extreme fast should be clamped to 4x max increase
        let very_fast = 1000u64; // Much faster than target
        let new_difficulty = adjust_difficulty_with_config(current_difficulty, very_fast, &config);
        // Due to clamping, max increase is 4x
        assert!(new_difficulty <= current_difficulty * 4);
    }
}
