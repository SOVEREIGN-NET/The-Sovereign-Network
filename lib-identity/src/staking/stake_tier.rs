//! Stake Tier definitions for the Sovereign Network
//!
//! Defines the tier levels based on staked SOV amounts.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stake tier levels in the Sovereign Network
///
/// Tiers determine governance rights, validator eligibility, and other privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum StakeTier {
    /// No stake - no tier privileges
    None = 0,
    /// Citizenship tier (500+ SOV) - basic governance rights
    Citizenship = 1,
    /// DAO Founder tier (2,000+ SOV) - enhanced governance
    DaoFounder = 2,
    /// Validator tier (10,000+ SOV) - full validator rights
    Validator = 3,
}

impl StakeTier {
    /// Minimum stake required for this tier (in micro-SOV)
    ///
    /// 1 SOV = 1_000_000_000_000 micro-SOV (12 decimal places)
    pub fn minimum_stake(&self) -> u64 {
        match self {
            StakeTier::None => 0,
            StakeTier::Citizenship => 500_000_000_000_000,    // 500 SOV
            StakeTier::DaoFounder => 2_000_000_000_000_000,   // 2,000 SOV
            StakeTier::Validator => 10_000_000_000_000_000,   // 10,000 SOV
        }
    }

    /// Human-readable tier name
    pub fn name(&self) -> &'static str {
        match self {
            StakeTier::None => "None",
            StakeTier::Citizenship => "Citizenship",
            StakeTier::DaoFounder => "DAO Founder",
            StakeTier::Validator => "Validator",
        }
    }

    /// Whether this tier grants governance voting rights
    pub fn has_governance_rights(&self) -> bool {
        matches!(self, StakeTier::Citizenship | StakeTier::DaoFounder | StakeTier::Validator)
    }

    /// Whether this tier can run a validator node
    pub fn can_validate(&self) -> bool {
        matches!(self, StakeTier::Validator)
    }

    /// Whether this tier can create proposals
    pub fn can_create_proposals(&self) -> bool {
        matches!(self, StakeTier::DaoFounder | StakeTier::Validator)
    }
}

impl Default for StakeTier {
    fn default() -> Self {
        StakeTier::None
    }
}

impl fmt::Display for StakeTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(StakeTier::None < StakeTier::Citizenship);
        assert!(StakeTier::Citizenship < StakeTier::DaoFounder);
        assert!(StakeTier::DaoFounder < StakeTier::Validator);
    }

    #[test]
    fn test_minimum_stakes() {
        assert_eq!(StakeTier::None.minimum_stake(), 0);
        assert_eq!(StakeTier::Citizenship.minimum_stake(), 500_000_000_000_000);
        assert_eq!(StakeTier::DaoFounder.minimum_stake(), 2_000_000_000_000_000);
        assert_eq!(StakeTier::Validator.minimum_stake(), 10_000_000_000_000_000);
    }

    #[test]
    fn test_tier_privileges() {
        assert!(!StakeTier::None.has_governance_rights());
        assert!(StakeTier::Citizenship.has_governance_rights());
        assert!(StakeTier::DaoFounder.has_governance_rights());
        assert!(StakeTier::Validator.has_governance_rights());

        assert!(!StakeTier::None.can_validate());
        assert!(!StakeTier::Citizenship.can_validate());
        assert!(!StakeTier::DaoFounder.can_validate());
        assert!(StakeTier::Validator.can_validate());

        assert!(!StakeTier::None.can_create_proposals());
        assert!(!StakeTier::Citizenship.can_create_proposals());
        assert!(StakeTier::DaoFounder.can_create_proposals());
        assert!(StakeTier::Validator.can_create_proposals());
    }
}
