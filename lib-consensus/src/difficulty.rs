//! Difficulty Management Module for ZHTP Consensus
//!
//! This module owns the blockchain difficulty adjustment policy, following the principle
//! "consensus engine should own difficulty policy". It provides:
//!
//! - `DifficultyConfig`: Configuration parameters for difficulty adjustment
//! - `DifficultyManager`: Manages difficulty calculations and DAO governance updates
//!
//! # Architecture
//!
//! The consensus layer owns the difficulty policy, while the blockchain layer
//! calls into this module when difficulty adjustments are needed. This enables:
//!
//! 1. DAO governance of difficulty parameters
//! 2. Clear separation of concerns
//! 3. Unified parameter management in lib-consensus

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during difficulty operations
#[derive(Debug, Error)]
pub enum DifficultyError {
    #[error("Invalid difficulty value: {0}")]
    InvalidDifficulty(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Adjustment calculation error: {0}")]
    CalculationError(String),
}

/// Result type for difficulty operations
pub type DifficultyResult<T> = Result<T, DifficultyError>;

/// Configuration for blockchain difficulty adjustment.
///
/// These parameters control how mining difficulty adapts to network hashrate.
/// All parameters can be updated via DAO governance proposals.
///
/// # Bitcoin-Style Algorithm
///
/// The difficulty adjustment follows Bitcoin's algorithm:
/// - Adjust every `adjustment_interval` blocks
/// - Target `target_timespan` seconds for each interval
/// - Clamp adjustments to 4x range (prevent extreme changes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DifficultyConfig {
    /// Initial difficulty for genesis block (Bitcoin-style compact representation)
    /// Default: 0x1d00ffff (Bitcoin's initial difficulty)
    pub initial_difficulty: u32,

    /// Number of blocks between difficulty adjustments
    /// Default: 2016 blocks (same as Bitcoin)
    pub adjustment_interval: u64,

    /// Target time for completing an adjustment interval (in seconds)
    /// Default: 1,209,600 seconds (2 weeks, same as Bitcoin)
    pub target_timespan: u64,

    /// Minimum allowed difficulty (prevents difficulty from dropping too low)
    /// Default: 1 (minimum possible difficulty)
    pub min_difficulty: u32,

    /// Maximum allowed difficulty (prevents difficulty from going too high)
    /// Default: 0xFFFFFFFF (maximum u32)
    pub max_difficulty: u32,

    /// Maximum adjustment factor per interval (prevents extreme changes)
    /// Default: 4 (difficulty can at most quadruple or quarter each interval)
    pub max_adjustment_factor: u64,
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            initial_difficulty: 0x1d00ffff,          // Bitcoin's initial difficulty
            adjustment_interval: 2016,                // 2016 blocks
            target_timespan: 14 * 24 * 60 * 60,      // 2 weeks in seconds
            min_difficulty: 1,
            max_difficulty: 0xFFFFFFFF,
            max_adjustment_factor: 4,
        }
    }
}

impl DifficultyConfig {
    /// Create a new difficulty configuration with custom values
    pub fn new(
        initial_difficulty: u32,
        adjustment_interval: u64,
        target_timespan: u64,
    ) -> DifficultyResult<Self> {
        let config = Self {
            initial_difficulty,
            adjustment_interval,
            target_timespan,
            ..Default::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration parameters
    pub fn validate(&self) -> DifficultyResult<()> {
        if self.adjustment_interval == 0 {
            return Err(DifficultyError::InvalidConfig(
                "Adjustment interval must be greater than zero".to_string(),
            ));
        }

        if self.target_timespan == 0 {
            return Err(DifficultyError::InvalidConfig(
                "Target timespan must be greater than zero".to_string(),
            ));
        }

        if self.initial_difficulty == 0 {
            return Err(DifficultyError::InvalidConfig(
                "Initial difficulty must be greater than zero".to_string(),
            ));
        }

        if self.min_difficulty > self.max_difficulty {
            return Err(DifficultyError::InvalidConfig(
                "Min difficulty cannot exceed max difficulty".to_string(),
            ));
        }

        if self.max_adjustment_factor == 0 {
            return Err(DifficultyError::InvalidConfig(
                "Max adjustment factor must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Manages blockchain difficulty calculations and DAO governance updates.
///
/// This struct is the single source of truth for difficulty policy in the
/// ZHTP consensus system. It:
///
/// 1. Stores the current difficulty configuration
/// 2. Calculates new difficulty values based on block timing
/// 3. Accepts configuration updates from DAO governance
///
/// # Thread Safety
///
/// `DifficultyManager` is `Send + Sync` and can be safely shared across threads.
/// When integrated with `BlockchainConsensusCoordinator`, it should be wrapped
/// in `Arc<RwLock<DifficultyManager>>` for concurrent access.
#[derive(Debug, Clone)]
pub struct DifficultyManager {
    /// Current difficulty configuration
    config: DifficultyConfig,
}

impl Default for DifficultyManager {
    fn default() -> Self {
        Self::new(DifficultyConfig::default())
    }
}

impl DifficultyManager {
    /// Create a new difficulty manager with the given configuration
    pub fn new(config: DifficultyConfig) -> Self {
        Self { config }
    }

    /// Get the current difficulty configuration
    pub fn config(&self) -> &DifficultyConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration (for internal updates).
    ///
    /// This is intentionally private to ensure all external updates go through
    /// validated governance or setter methods that enforce configuration invariants.
    fn config_mut(&mut self) -> &mut DifficultyConfig {
        &mut self.config
    }

    /// Get the initial difficulty value
    pub fn initial_difficulty(&self) -> u32 {
        self.config.initial_difficulty
    }

    /// Get the adjustment interval
    pub fn adjustment_interval(&self) -> u64 {
        self.config.adjustment_interval
    }

    /// Get the target timespan
    pub fn target_timespan(&self) -> u64 {
        self.config.target_timespan
    }

    /// Check if difficulty should be adjusted at the given height
    pub fn should_adjust(&self, height: u64) -> bool {
        // Note: height >= adjustment_interval implies height > 0
        // since adjustment_interval is validated to be > 0
        height >= self.config.adjustment_interval 
            && height % self.config.adjustment_interval == 0
    }

    /// Calculate the new difficulty based on actual vs target timespan.
    ///
    /// # Algorithm
    ///
    /// 1. Clamp actual timespan to prevent extreme adjustments:
    ///    - Minimum: target_timespan / max_adjustment_factor
    ///    - Maximum: target_timespan * max_adjustment_factor
    ///
    /// 2. Calculate new difficulty:
    ///    new_difficulty = current_difficulty * target_timespan / clamped_actual_timespan
    ///
    /// 3. Clamp result to [min_difficulty, max_difficulty]
    ///
    /// # Arguments
    ///
    /// * `current_difficulty` - Current difficulty in compact (bits) format
    /// * `actual_timespan` - Actual time taken for the last adjustment interval (seconds)
    ///
    /// # Returns
    ///
    /// The new difficulty value in compact (bits) format
    pub fn calculate_new_difficulty(
        &self,
        current_difficulty: u32,
        actual_timespan: u64,
    ) -> DifficultyResult<u32> {
        if current_difficulty == 0 {
            return Err(DifficultyError::InvalidDifficulty(
                "Current difficulty cannot be zero".to_string(),
            ));
        }

        // Clamp actual timespan to prevent extreme adjustments
        let min_timespan = self.config.target_timespan / self.config.max_adjustment_factor;
        let max_timespan = self.config.target_timespan * self.config.max_adjustment_factor;
        // Ensure min_timespan is at least 1 to prevent division by zero
        // (can happen if target_timespan < max_adjustment_factor due to integer division)
        let min_timespan = min_timespan.max(1);
        let clamped_timespan = actual_timespan.max(min_timespan).min(max_timespan);

        // Calculate new difficulty: current * target / actual
        // Using u64 intermediate to prevent overflow
        let new_difficulty = (current_difficulty as u64)
            .saturating_mul(self.config.target_timespan)
            .checked_div(clamped_timespan)
            .ok_or_else(|| {
                DifficultyError::CalculationError("Division by zero in difficulty calculation".to_string())
            })?;

        // Clamp to valid range and convert back to u32
        let clamped = new_difficulty
            .max(self.config.min_difficulty as u64)
            .min(self.config.max_difficulty as u64) as u32;

        Ok(clamped)
    }

    /// Adjust difficulty given block timing information.
    ///
    /// This is the main entry point for blockchain difficulty adjustment.
    ///
    /// # Arguments
    ///
    /// * `height` - Current blockchain height
    /// * `current_difficulty` - Current difficulty value
    /// * `interval_start_time` - Timestamp of the block at the start of the interval
    /// * `interval_end_time` - Timestamp of the current block (end of interval)
    ///
    /// # Returns
    ///
    /// * `Ok(Some(new_difficulty))` - If adjustment was made
    /// * `Ok(None)` - If no adjustment needed at this height
    /// * `Err(...)` - If calculation failed
    pub fn adjust_difficulty(
        &self,
        height: u64,
        current_difficulty: u32,
        interval_start_time: u64,
        interval_end_time: u64,
    ) -> DifficultyResult<Option<u32>> {
        // Check if we should adjust at this height
        if !self.should_adjust(height) {
            return Ok(None);
        }

        // Calculate actual timespan
        let actual_timespan = interval_end_time.saturating_sub(interval_start_time);
        if actual_timespan == 0 {
            return Err(DifficultyError::CalculationError(
                "Actual timespan cannot be zero".to_string(),
            ));
        }

        // Calculate and return new difficulty
        let new_difficulty = self.calculate_new_difficulty(current_difficulty, actual_timespan)?;
        Ok(Some(new_difficulty))
    }

    /// Update configuration from DAO governance.
    ///
    /// This method validates and applies governance parameter updates.
    ///
    /// # Arguments
    ///
    /// * `initial_difficulty` - New initial difficulty (optional)
    /// * `adjustment_interval` - New adjustment interval (optional)
    /// * `target_timespan` - New target timespan (optional)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If update was successful
    /// * `Err(...)` - If validation failed (no changes made)
    pub fn apply_governance_update(
        &mut self,
        initial_difficulty: Option<u32>,
        adjustment_interval: Option<u64>,
        target_timespan: Option<u64>,
    ) -> DifficultyResult<()> {
        // Create a temporary config with proposed changes
        let mut new_config = self.config.clone();

        if let Some(value) = initial_difficulty {
            new_config.initial_difficulty = value;
        }
        if let Some(value) = adjustment_interval {
            new_config.adjustment_interval = value;
        }
        if let Some(value) = target_timespan {
            new_config.target_timespan = value;
        }

        // Validate before applying
        new_config.validate()?;

        // Apply the validated configuration
        self.config = new_config;
        Ok(())
    }

    /// Set the minimum difficulty bound
    pub fn set_min_difficulty(&mut self, min_difficulty: u32) -> DifficultyResult<()> {
        if min_difficulty > self.config.max_difficulty {
            return Err(DifficultyError::InvalidConfig(
                "Min difficulty cannot exceed max difficulty".to_string(),
            ));
        }
        self.config.min_difficulty = min_difficulty;
        Ok(())
    }

    /// Set the maximum difficulty bound
    pub fn set_max_difficulty(&mut self, max_difficulty: u32) -> DifficultyResult<()> {
        if max_difficulty < self.config.min_difficulty {
            return Err(DifficultyError::InvalidConfig(
                "Max difficulty cannot be less than min difficulty".to_string(),
            ));
        }
        self.config.max_difficulty = max_difficulty;
        Ok(())
    }

    /// Set the maximum adjustment factor
    pub fn set_max_adjustment_factor(&mut self, factor: u64) -> DifficultyResult<()> {
        if factor == 0 {
            return Err(DifficultyError::InvalidConfig(
                "Max adjustment factor must be greater than zero".to_string(),
            ));
        }
        self.config.max_adjustment_factor = factor;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DifficultyConfig::default();
        assert_eq!(config.initial_difficulty, 0x1d00ffff);
        assert_eq!(config.adjustment_interval, 2016);
        assert_eq!(config.target_timespan, 14 * 24 * 60 * 60);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        // Zero adjustment interval should fail
        let mut config = DifficultyConfig::default();
        config.adjustment_interval = 0;
        assert!(config.validate().is_err());

        // Zero target timespan should fail
        let mut config = DifficultyConfig::default();
        config.target_timespan = 0;
        assert!(config.validate().is_err());

        // Zero initial difficulty should fail
        let mut config = DifficultyConfig::default();
        config.initial_difficulty = 0;
        assert!(config.validate().is_err());

        // Min > max should fail
        let mut config = DifficultyConfig::default();
        config.min_difficulty = 100;
        config.max_difficulty = 10;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_should_adjust() {
        let manager = DifficultyManager::default();

        // Should not adjust at height 0
        assert!(!manager.should_adjust(0));

        // Should not adjust before first interval
        assert!(!manager.should_adjust(1000));

        // Should adjust at exactly adjustment_interval
        assert!(manager.should_adjust(2016));

        // Should not adjust between intervals
        assert!(!manager.should_adjust(2017));
        assert!(!manager.should_adjust(3000));

        // Should adjust at multiples of interval
        assert!(manager.should_adjust(4032));
        assert!(manager.should_adjust(6048));
    }

    #[test]
    fn test_calculate_new_difficulty_faster_blocks() {
        let manager = DifficultyManager::default();
        let current_difficulty = 0x1d00ffff;
        
        // Blocks came in twice as fast as expected
        let target = manager.target_timespan();
        let actual = target / 2;

        let new_difficulty = manager
            .calculate_new_difficulty(current_difficulty, actual)
            .unwrap();

        // Difficulty should increase (higher number = harder to mine)
        assert!(new_difficulty > current_difficulty);
    }

    #[test]
    fn test_calculate_new_difficulty_slower_blocks() {
        let manager = DifficultyManager::default();
        let current_difficulty = 0x1d00ffff;
        
        // Blocks came in twice as slow as expected
        let target = manager.target_timespan();
        let actual = target * 2;

        let new_difficulty = manager
            .calculate_new_difficulty(current_difficulty, actual)
            .unwrap();

        // Difficulty should decrease (lower number = easier to mine)
        assert!(new_difficulty < current_difficulty);
    }

    #[test]
    fn test_difficulty_clamping() {
        let manager = DifficultyManager::default();
        let current_difficulty = 0x1d00ffff;
        let target = manager.target_timespan();

        // Extremely fast blocks (should be clamped to 4x increase max)
        let actual = target / 100; // 100x faster
        let new_difficulty = manager
            .calculate_new_difficulty(current_difficulty, actual)
            .unwrap();
        
        // Should be at most 4x increase due to clamping
        assert!(new_difficulty <= current_difficulty * 4);

        // Extremely slow blocks (should be clamped to 4x decrease max)
        let actual = target * 100; // 100x slower
        let new_difficulty = manager
            .calculate_new_difficulty(current_difficulty, actual)
            .unwrap();
        
        // Should be at least 1/4 due to clamping
        assert!(new_difficulty >= current_difficulty / 4);
    }

    #[test]
    fn test_adjust_difficulty_integration() {
        let manager = DifficultyManager::default();
        let current_difficulty = 0x1d00ffff;
        let interval = manager.adjustment_interval();
        let target = manager.target_timespan();

        // At adjustment height with on-target timing
        let result = manager
            .adjust_difficulty(interval, current_difficulty, 0, target)
            .unwrap();
        
        assert!(result.is_some());
        let new_difficulty = result.unwrap();
        // Should be approximately the same (might have minor rounding)
        assert!((new_difficulty as i64 - current_difficulty as i64).abs() < 100);

        // Not at adjustment height - should return None
        let result = manager
            .adjust_difficulty(interval + 1, current_difficulty, 0, target)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_governance_update() {
        let mut manager = DifficultyManager::default();

        // Update adjustment interval
        manager
            .apply_governance_update(None, Some(1000), None)
            .unwrap();
        assert_eq!(manager.adjustment_interval(), 1000);

        // Update target timespan
        manager
            .apply_governance_update(None, None, Some(604800))
            .unwrap();
        assert_eq!(manager.target_timespan(), 604800);

        // Update initial difficulty
        manager
            .apply_governance_update(Some(0x1d00fffe), None, None)
            .unwrap();
        assert_eq!(manager.initial_difficulty(), 0x1d00fffe);

        // Invalid update should fail and not change anything
        let current_interval = manager.adjustment_interval();
        assert!(manager.apply_governance_update(None, Some(0), None).is_err());
        assert_eq!(manager.adjustment_interval(), current_interval);
    }

    #[test]
    fn test_difficulty_bounds() {
        let mut manager = DifficultyManager::default();
        
        // Set custom bounds
        manager.set_min_difficulty(100).unwrap();
        manager.set_max_difficulty(1000000).unwrap();

        // Calculation should respect bounds
        // With very slow blocks, difficulty should hit min
        let result = manager
            .calculate_new_difficulty(200, manager.target_timespan() * 1000)
            .unwrap();
        assert!(result >= 100);
    }

    #[test]
    fn test_set_min_difficulty_validation() {
        let mut manager = DifficultyManager::default();
        
        // Valid: set min below current max
        assert!(manager.set_min_difficulty(100).is_ok());
        assert_eq!(manager.config().min_difficulty, 100);
        
        // Test min > max scenario
        manager.set_max_difficulty(500).unwrap();
        let result = manager.set_min_difficulty(600);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_max_difficulty_validation() {
        let mut manager = DifficultyManager::default();
        
        // Set a min first
        manager.set_min_difficulty(100).unwrap();
        
        // Valid: set max above current min
        assert!(manager.set_max_difficulty(1000).is_ok());
        assert_eq!(manager.config().max_difficulty, 1000);
        
        // Invalid: set max below current min
        let result = manager.set_max_difficulty(50);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_max_adjustment_factor_validation() {
        let mut manager = DifficultyManager::default();
        
        // Valid: set factor to a positive value
        assert!(manager.set_max_adjustment_factor(8).is_ok());
        assert_eq!(manager.config().max_adjustment_factor, 8);
        
        // Valid: set factor to 1
        assert!(manager.set_max_adjustment_factor(1).is_ok());
        
        // Invalid: set factor to zero
        let result = manager.set_max_adjustment_factor(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_min_timespan_cannot_be_zero() {
        // Test edge case where target_timespan < max_adjustment_factor
        // could cause min_timespan to be 0 due to integer division
        let config = DifficultyConfig {
            initial_difficulty: 0x1d00ffff,
            adjustment_interval: 10,
            target_timespan: 3, // Small value
            min_difficulty: 1,
            max_difficulty: 0xFFFFFFFF,
            max_adjustment_factor: 10, // Larger than target_timespan
        };
        let manager = DifficultyManager::new(config);
        
        // This should not panic or return division by zero error
        // Even though 3 / 10 = 0 in integer division, we protect against this
        let result = manager.calculate_new_difficulty(1000, 1);
        assert!(result.is_ok());
    }
}
