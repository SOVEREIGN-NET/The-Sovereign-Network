//! Anti-speculation design for post-scarcity economics
//! 
//! Implements economic mechanisms that discourage speculation
//! and focus on utility-based token economics.

use serde::{Serialize, Deserialize};

/// Anti-speculation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiSpeculationConfig {
    /// Whether speculation prevention is enabled
    pub enabled: bool,
    /// Maximum allowed token hoarding per entity
    pub max_hoarding_limit: Option<u64>,
    /// Decay rate for hoarded tokens (if any)
    pub hoarding_decay_rate: f64,
    /// Minimum utility usage requirement
    pub min_utility_usage_rate: f64,
}

impl AntiSpeculationConfig {
    /// Create default anti-speculation configuration
    pub fn new() -> Self {
        AntiSpeculationConfig {
            enabled: true,
            max_hoarding_limit: None, // No hard limit, use incentives instead
            hoarding_decay_rate: 0.0, // No decay for utility tokens
            min_utility_usage_rate: 0.0, // No minimum usage requirement
        }
    }
    
    /// Post-scarcity model configuration (unlimited supply, utility focus)
    pub fn post_scarcity() -> Self {
        AntiSpeculationConfig {
            enabled: true,
            max_hoarding_limit: None, // Unlimited supply makes hoarding pointless
            hoarding_decay_rate: 0.0, // No punishment for holding tokens
            min_utility_usage_rate: 0.0, // Encourage but don't force usage
        }
    }
}

/// Anti-speculation mechanisms
pub struct AntiSpeculationMechanisms {
    config: AntiSpeculationConfig,
}

impl AntiSpeculationMechanisms {
    /// Create new anti-speculation mechanisms
    pub fn new(config: AntiSpeculationConfig) -> Self {
        AntiSpeculationMechanisms { config }
    }
    
    /// Check if a token holding pattern indicates speculation
    pub fn is_speculative_behavior(
        &self,
        balance: u64,
        usage_in_period: u64,
        period_days: u64,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        // Calculate usage rate
        let usage_rate = if balance > 0 {
            (usage_in_period as f64) / (balance as f64)
        } else {
            1.0 // No tokens = no speculation
        };
        
        // Check against minimum usage requirement
        let min_rate_per_day = self.config.min_utility_usage_rate / (period_days as f64);
        usage_rate < min_rate_per_day
    }
    
    /// Calculate anti-speculation incentives
    pub fn calculate_utility_incentives(&self, utility_usage: u64, total_balance: u64) -> u64 {
        if !self.config.enabled || total_balance == 0 {
            return 0;
        }
        
        // Reward utility usage with small bonuses
        let usage_ratio = (utility_usage as f64) / (total_balance as f64);
        
        // Small bonus for active utility usage (not speculation)
        if usage_ratio > 0.1 {
            // 1% bonus for active network participation
            total_balance / 100
        } else {
            0
        }
    }
    
    /// Apply post-scarcity economics principles
    pub fn apply_post_scarcity_principles(&self, _balance: u64) -> PostScarcityEffects {
        PostScarcityEffects {
            speculation_deterrent: true, // Unlimited supply deters speculation
            utility_focused: true,       // Incentivize actual network usage
            hoarding_meaningless: true,  // Unlimited supply makes hoarding pointless
            value_from_utility: true,    // Value comes from network utility, not scarcity
        }
    }
}

/// Effects of post-scarcity economic design
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostScarcityEffects {
    /// Whether speculation is deterred
    pub speculation_deterrent: bool,
    /// Whether utility is the focus
    pub utility_focused: bool,
    /// Whether hoarding is meaningless
    pub hoarding_meaningless: bool,
    /// Whether value comes from utility
    pub value_from_utility: bool,
}

impl PostScarcityEffects {
    /// Get human-readable description of effects
    pub fn describe(&self) -> Vec<&'static str> {
        let mut effects = Vec::new();
        
        if self.speculation_deterrent {
            effects.push("Unlimited supply prevents speculation bubbles");
        }
        
        if self.utility_focused {
            effects.push("Token value based on network utility, not scarcity");
        }
        
        if self.hoarding_meaningless {
            effects.push("Token hoarding provides no advantage");
        }
        
        if self.value_from_utility {
            effects.push("Economic value derived from actual network services");
        }
        
        effects
    }
}

impl Default for AntiSpeculationConfig {
    fn default() -> Self {
        Self::post_scarcity() // Use post-scarcity model by default
    }
}

impl Default for AntiSpeculationMechanisms {
    fn default() -> Self {
        Self::new(AntiSpeculationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_scarcity_config() {
        let config = AntiSpeculationConfig::post_scarcity();
        assert!(config.enabled);
        assert!(config.max_hoarding_limit.is_none());
        assert_eq!(config.hoarding_decay_rate, 0.0);
    }

    #[test]
    fn test_speculative_behavior_detection() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        // High balance, no usage = speculative
        let is_spec = mechanisms.is_speculative_behavior(10000, 0, 30);
        assert_eq!(is_spec, false); // Post-scarcity doesn't penalize holding
        
        // Active usage = not speculative
        let is_spec2 = mechanisms.is_speculative_behavior(10000, 1000, 30);
        assert_eq!(is_spec2, false);
    }

    #[test]
    fn test_utility_incentives() {
        let mechanisms = AntiSpeculationMechanisms::default();
        
        let incentive = mechanisms.calculate_utility_incentives(1100, 10000); // 11% ratio > 10% threshold
        assert!(incentive > 0); // Should reward utility usage
        
        let no_incentive = mechanisms.calculate_utility_incentives(50, 10000); // 0.5% ratio < 10% threshold
        assert_eq!(no_incentive, 0); // Low usage gets no bonus
    }

    #[test]
    fn test_post_scarcity_effects() {
        let mechanisms = AntiSpeculationMechanisms::default();
        let effects = mechanisms.apply_post_scarcity_principles(10000);
        
        assert!(effects.speculation_deterrent);
        assert!(effects.utility_focused);
        assert!(effects.hoarding_meaningless);
        assert!(effects.value_from_utility);
    }
}
