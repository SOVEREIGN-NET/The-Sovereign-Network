//! Difficulty calculation and proof-of-work utilities
//!
//! Provides basic difficulty calculation for proof-of-work mining.
//! Advanced consensus mechanisms are handled by lib-consensus package.

use crate::types::Hash;
use serde::{Serialize, Deserialize};

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

/// Difficulty adjustment calculation
pub fn adjust_difficulty(
    current_difficulty: u32,
    actual_timespan: u64,
    target_timespan: u64,
) -> u32 {
    // Clamp the adjustment to prevent extreme changes
    let max_adjustment = target_timespan * 4;
    let min_adjustment = target_timespan / 4;
    
    let clamped_timespan = actual_timespan
        .max(min_adjustment)
        .min(max_adjustment);
    
    // Calculate new difficulty
    let new_difficulty = (current_difficulty as u64 * target_timespan / clamped_timespan) as u32;
    
    // Ensure difficulty doesn't go to zero
    new_difficulty.max(1)
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
}
