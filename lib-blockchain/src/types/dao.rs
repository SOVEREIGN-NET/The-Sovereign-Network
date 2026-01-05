//! DAO classification and token metadata types
//!
//! Provides foundational types for DAO categorization, token classes,
//! and treasury allocation rules used across the blockchain stack.

use serde::{Deserialize, Serialize};

/// Sector classification for SOV DAO treasuries
/// Each sector receives an equal share of DAO fee allocations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SectorDao {
    /// Healthcare sector
    Healthcare,
    /// Education sector
    Education,
    /// Energy sector
    Energy,
    /// Housing sector
    Housing,
    /// Food security sector
    Food,
}

impl SectorDao {
    /// String representation of the sector
    pub fn as_str(&self) -> &'static str {
        match self {
            SectorDao::Healthcare => "healthcare",
            SectorDao::Education => "education",
            SectorDao::Energy => "energy",
            SectorDao::Housing => "housing",
            SectorDao::Food => "food",
        }
    }

    /// Parse a sector from a string (case-insensitive)
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "healthcare" => Some(SectorDao::Healthcare),
            "education" => Some(SectorDao::Education),
            "energy" => Some(SectorDao::Energy),
            "housing" => Some(SectorDao::Housing),
            "food" => Some(SectorDao::Food),
            _ => None,
        }
    }

    /// Get all available sectors
    pub fn all() -> &'static [SectorDao] {
        &[
            SectorDao::Healthcare,
            SectorDao::Education,
            SectorDao::Energy,
            SectorDao::Housing,
            SectorDao::Food,
        ]
    }
}

/// Classification of DAO entities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DAOType {
    /// Non-profit DAO focused on community goods
    NP,
    /// For-profit DAO oriented toward revenue generation
    FP,
}

impl DAOType {
    /// String representation of the DAO type
    pub fn as_str(&self) -> &'static str {
        match self {
            DAOType::NP => "np",
            DAOType::FP => "fp",
        }
    }

    /// Parse a DAO type from a string (case-insensitive)
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "np" | "non_profit" | "non-profit" => Some(DAOType::NP),
            "fp" | "for_profit" | "for-profit" => Some(DAOType::FP),
            _ => None,
        }
    }

    /// Check if this DAO is non-profit
    pub fn is_non_profit(&self) -> bool {
        matches!(self, DAOType::NP)
    }

    /// Check if this DAO is for-profit
    pub fn is_for_profit(&self) -> bool {
        matches!(self, DAOType::FP)
    }
}

/// Token classifications within the SOV ecosystem
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TokenClass {
    /// Base SOV token
    SOV,
    /// DAO-issued token for non-profit DAOs
    DAO_NP,
    /// DAO-issued token for for-profit DAOs
    DAO_FP,
    /// ZHTP utility token
    ZHTP,
}

impl TokenClass {
    /// String representation of the token class
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenClass::SOV => "sov",
            TokenClass::DAO_NP => "dao_np",
            TokenClass::DAO_FP => "dao_fp",
            TokenClass::ZHTP => "zhtp",
        }
    }

    /// Parse a token class from a string (case-insensitive)
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sov" => Some(TokenClass::SOV),
            "dao_np" | "dao-np" => Some(TokenClass::DAO_NP),
            "dao_fp" | "dao-fp" => Some(TokenClass::DAO_FP),
            "zhtp" => Some(TokenClass::ZHTP),
            _ => None,
        }
    }

    /// Determine if the token belongs to a DAO
    pub fn is_dao_token(&self) -> bool {
        matches!(self, TokenClass::DAO_NP | TokenClass::DAO_FP)
    }
}

/// Treasury allocation rule for a DAO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryAllocation {
    /// Allocation percentage (0-100)
    pub percentage: u8,
    /// Optional vesting schedule in months (0 = immediate)
    pub vesting_months: Option<u16>,
}

impl TreasuryAllocation {
    /// Create a new allocation ensuring the percentage is valid
    pub fn new(percentage: u8, vesting_months: Option<u16>) -> Result<Self, &'static str> {
        let allocation = Self {
            percentage,
            vesting_months,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    /// Validate allocation bounds
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.percentage > 100 {
            return Err("treasury allocation percentage must be between 0 and 100");
        }
        Ok(())
    }

    /// Returns true if funds are immediately available
    pub fn is_immediate(&self) -> bool {
        self.vesting_months.unwrap_or(0) == 0
    }
}

/// Metadata describing DAO classification and treasury rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DAOMetadata {
    /// DAO classification (NP/FP)
    pub dao_type: DAOType,
    /// Primary token class for the DAO
    pub token_class: TokenClass,
    /// Treasury allocation policy for this DAO
    pub treasury_allocation: TreasuryAllocation,
}

impl DAOMetadata {
    /// Construct metadata while validating invariants
    pub fn new(
        dao_type: DAOType,
        token_class: TokenClass,
        treasury_allocation: TreasuryAllocation,
    ) -> Result<Self, &'static str> {
        let metadata = Self {
            dao_type,
            token_class,
            treasury_allocation,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validate metadata consistency and allocation bounds
    pub fn validate(&self) -> Result<(), &'static str> {
        self.treasury_allocation.validate()?;

        if matches!(self.token_class, TokenClass::DAO_NP) && !self.dao_type.is_non_profit() {
            return Err("DAO_NP tokens require NP DAO type");
        }

        if matches!(self.token_class, TokenClass::DAO_FP) && !self.dao_type.is_for_profit() {
            return Err("DAO_FP tokens require FP DAO type");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dao_type_round_trip() {
        assert_eq!(DAOType::from_str("np"), Some(DAOType::NP));
        assert_eq!(DAOType::from_str("FP"), Some(DAOType::FP));
        assert_eq!(DAOType::NP.as_str(), "np");
        assert!(DAOType::from_str("unknown").is_none());
    }

    #[test]
    fn token_class_round_trip() {
        assert_eq!(TokenClass::from_str("dao_np"), Some(TokenClass::DAO_NP));
        assert_eq!(TokenClass::from_str("DAO-FP"), Some(TokenClass::DAO_FP));
        assert_eq!(TokenClass::from_str("zhtp"), Some(TokenClass::ZHTP));
        assert_eq!(TokenClass::SOV.as_str(), "sov");
        assert!(TokenClass::from_str("invalid").is_none());
    }

    #[test]
    fn treasury_allocation_validation() {
        let immediate = TreasuryAllocation::new(40, None).unwrap();
        assert!(immediate.is_immediate());

        let vested = TreasuryAllocation::new(60, Some(12)).unwrap();
        assert!(!vested.is_immediate());

        let invalid = TreasuryAllocation::new(120, None);
        assert!(invalid.is_err());
    }

    #[test]
    fn dao_metadata_validation_and_serialization() {
        let allocation = TreasuryAllocation::new(50, Some(6)).unwrap();
        let metadata = DAOMetadata::new(DAOType::NP, TokenClass::DAO_NP, allocation.clone()).unwrap();
        metadata.validate().unwrap();

        let serialized = bincode::serialize(&metadata).expect("serialize metadata");
        let deserialized: DAOMetadata =
            bincode::deserialize(&serialized).expect("deserialize metadata");
        assert_eq!(metadata, deserialized);
        assert_eq!(deserialized.treasury_allocation, allocation);

        // Mismatched token/DAO type should fail
        let invalid = DAOMetadata::new(DAOType::NP, TokenClass::DAO_FP, allocation);
        assert!(invalid.is_err());
    }
}
