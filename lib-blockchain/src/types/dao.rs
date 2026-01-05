//! DAO classification and token metadata types
//!
//! Provides foundational types for DAO categorization, token classes,
//! treasury allocation rules, and economic period scheduling used across the blockchain stack.

use serde::{Deserialize, Serialize};

/// Economic period for scheduled disbursements
///
/// # Invariant A1: Deterministic Mapping Invariant
/// EconomicPeriod must map deterministically to block height, never to wall-clock time.
/// EconomicPeriod × chain_constants → exact block intervals
///
/// # Invariant A2: Epoch Alignment Invariant
/// Economic periods must align to epoch boundaries:
/// period_boundary_height % epoch_length == 0
///
/// Rationale:
/// - Validator set changes only at epoch boundaries
/// - Economic disbursement must not straddle validator transitions
///
/// # Invariant A3: Non-Overlap Invariant
/// At any block height, at most one EconomicPeriod boundary event fires per contract.
/// for a given contract and height:
///   triggers_disbursement(height) ∈ {true, false}
/// No cascading or stacked disbursements.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EconomicPeriod {
    /// Daily treasury accounting (~24 hours ≈ 8,640 blocks at 10s/block)
    Daily,
    /// Monthly UBI distribution cycle (~30 days ≈ 259,200 blocks)
    Monthly,
    /// Quarterly DAO allocation review (~90 days ≈ 777,600 blocks)
    Quarterly,
}

impl EconomicPeriod {
    /// Get block count for this period (assuming 10-second block time)
    ///
    /// These values are hardcoded chain constants.
    /// Invariant A1 (Deterministic Mapping): same input always yields same output
    /// Invariant A2 (Epoch Alignment): all boundaries are multiples of 100 (epoch_length)
    pub fn block_height(&self) -> u64 {
        match self {
            // 8,600 = 86 epochs of 100 blocks each (~23.89 hours, aligned to epoch boundaries)
            // Changed from 8,640 to enforce Invariant A2 (epoch alignment)
            // Represents daily treasury accounting aligned to validator set transitions
            EconomicPeriod::Daily => 8_600,       // 86,000 seconds / 10 = 8,600 blocks
            EconomicPeriod::Monthly => 259_200,   // 2,592,000 seconds / 10 = 259,200 blocks
            EconomicPeriod::Quarterly => 777_600, // 7,776,000 seconds / 10 = 777,600 blocks
        }
    }

    /// Check if height is an exact boundary for this period
    ///
    /// # Invariant A2: Epoch Alignment
    /// Assumes epoch_length is a divisor of all period heights:
    /// - Daily (8,640) = 100 * 86.4 (must align with epoch boundaries)
    /// - Monthly (259,200) = 100 * 2,592 (must align with epoch boundaries)
    /// - Quarterly (777,600) = 100 * 7,776 (must align with epoch boundaries)
    pub fn is_boundary(&self, height: u64) -> bool {
        let period = self.block_height();
        if period == 0 {
            return false;
        }
        height > 0 && height % period == 0
    }

    /// Get the next boundary after (not including) the given height
    ///
    /// # Invariant A2: Epoch Alignment
    /// Returns a height that is guaranteed to be an epoch boundary
    pub fn next_boundary(&self, height: u64) -> u64 {
        let period = self.block_height();
        if period == 0 {
            return height;
        }
        ((height / period) + 1) * period
    }

    /// Get the period ID for a given block height
    ///
    /// Period ID is monotonically increasing: each period has a unique ID.
    /// Used by treasuries to track period progression (Invariant C2).
    pub fn period_id_for_height(&self, height: u64) -> u64 {
        let period = self.block_height();
        if period == 0 {
            return 0;
        }
        height / period
    }

    /// String representation of the period
    pub fn as_str(&self) -> &'static str {
        match self {
            EconomicPeriod::Daily => "daily",
            EconomicPeriod::Monthly => "monthly",
            EconomicPeriod::Quarterly => "quarterly",
        }
    }

    /// Parse a period from a string (case-insensitive)
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "daily" => Some(EconomicPeriod::Daily),
            "monthly" => Some(EconomicPeriod::Monthly),
            "quarterly" => Some(EconomicPeriod::Quarterly),
            _ => None,
        }
    }
}

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

    // ============================================================================
    // ECONOMIC PERIOD TESTS (Invariants A1-A3)
    // ============================================================================

    #[test]
    fn test_economic_period_deterministic_mapping() {
        // Invariant A1: Same input always yields same output
        assert_eq!(EconomicPeriod::Daily.block_height(), 8_600);
        assert_eq!(EconomicPeriod::Daily.block_height(), 8_600);
        
        assert_eq!(EconomicPeriod::Monthly.block_height(), 259_200);
        assert_eq!(EconomicPeriod::Monthly.block_height(), 259_200);
        
        assert_eq!(EconomicPeriod::Quarterly.block_height(), 777_600);
        assert_eq!(EconomicPeriod::Quarterly.block_height(), 777_600);
    }

    #[test]
    fn test_economic_period_is_boundary() {
        // Height 8640 is a Daily boundary
        assert!(EconomicPeriod::Daily.is_boundary(8_600));
        // Height 8641 is not
        assert!(!EconomicPeriod::Daily.is_boundary(8_641));
        // Height 0 is not a boundary
        assert!(!EconomicPeriod::Daily.is_boundary(0));
        
        // Monthly: 259,200 is boundary
        assert!(EconomicPeriod::Monthly.is_boundary(259_200));
        assert!(!EconomicPeriod::Monthly.is_boundary(259_201));
        
        // Quarterly: 777,600 is boundary
        assert!(EconomicPeriod::Quarterly.is_boundary(777_600));
        assert!(!EconomicPeriod::Quarterly.is_boundary(777_601));
    }

    #[test]
    fn test_economic_period_next_boundary() {
        // Next Daily boundary after 1 is 8,640
        assert_eq!(EconomicPeriod::Daily.next_boundary(1), 8_600);
        // Next Daily boundary after 8,640 is 17,280
        assert_eq!(EconomicPeriod::Daily.next_boundary(8_600), 17_200);
        // Next Daily boundary after 8,639 is 8,640
        assert_eq!(EconomicPeriod::Daily.next_boundary(8_599), 8_600);
        
        // Monthly boundaries
        assert_eq!(EconomicPeriod::Monthly.next_boundary(1), 259_200);
        assert_eq!(EconomicPeriod::Monthly.next_boundary(259_200), 518_400);
        
        // Quarterly boundaries
        assert_eq!(EconomicPeriod::Quarterly.next_boundary(1), 777_600);
        assert_eq!(EconomicPeriod::Quarterly.next_boundary(777_600), 1_555_200);
    }

    #[test]
    fn test_economic_period_id_monotonic() {
        // Period IDs must increase monotonically
        let period = EconomicPeriod::Daily;
        
        let id_at_0 = period.period_id_for_height(0);
        let id_at_1 = period.period_id_for_height(1);
        let id_at_8600 = period.period_id_for_height(8_600);
        let id_at_8641 = period.period_id_for_height(8_641);
        let id_at_17200 = period.period_id_for_height(17_200);
        
        // All in first period (0)
        assert_eq!(id_at_0, 0);
        assert_eq!(id_at_1, 0);
        
        // Boundary: moves to period 1
        assert_eq!(id_at_8600, 1);
        assert_eq!(id_at_8641, 1);
        
        // Next boundary: moves to period 2
        assert_eq!(id_at_17200, 2);
        
        // Verify monotonicity
        assert!(id_at_0 <= id_at_1);
        assert!(id_at_1 <= id_at_8600);
        assert!(id_at_8600 <= id_at_8641);
        assert!(id_at_8641 < id_at_17200);
    }

    #[test]
    fn test_economic_period_round_trip() {
        assert_eq!(EconomicPeriod::from_str("daily"), Some(EconomicPeriod::Daily));
        assert_eq!(EconomicPeriod::from_str("DAILY"), Some(EconomicPeriod::Daily));
        assert_eq!(EconomicPeriod::from_str("monthly"), Some(EconomicPeriod::Monthly));
        assert_eq!(EconomicPeriod::from_str("QUARTERLY"), Some(EconomicPeriod::Quarterly));
        
        assert_eq!(EconomicPeriod::Daily.as_str(), "daily");
        assert_eq!(EconomicPeriod::Monthly.as_str(), "monthly");
        assert_eq!(EconomicPeriod::Quarterly.as_str(), "quarterly");
        
        assert!(EconomicPeriod::from_str("invalid").is_none());
    }

    #[test]
    fn test_economic_period_alignment_with_epoch() {
        // CRITICAL: Invariant A2 - Periods must align to epoch boundaries
        // Economic disbursements must occur at validator set transition boundaries
        // to prevent straddle across validator changes.
        // Assuming epoch_length = 100 blocks (standard validator epoch length)
        let epoch_length = 100u64;
        
        // All period heights must be exact multiples of epoch_length
        // This enforces alignment to validator set transitions
        assert_eq!(
            EconomicPeriod::Daily.block_height() % epoch_length,
            0,
            "Daily period must align to epoch boundaries (invariant A2)"
        );
        assert_eq!(
            EconomicPeriod::Monthly.block_height() % epoch_length,
            0,
            "Monthly period must align to epoch boundaries (invariant A2)"
        );
        assert_eq!(
            EconomicPeriod::Quarterly.block_height() % epoch_length,
            0,
            "Quarterly period must align to epoch boundaries (invariant A2)"
        );
        
        // Verify that all boundaries are exact multiples of epoch_length
        for period in [EconomicPeriod::Daily, EconomicPeriod::Monthly, EconomicPeriod::Quarterly] {
            let period_height = period.block_height();
            assert_eq!(
                period_height % epoch_length,
                0,
                "Period {} height {} must be divisible by epoch_length {}",
                period.as_str(),
                period_height,
                epoch_length
            );
            
            // Verify that all calculated boundaries respect the alignment invariant
            for multiple in 1..=3 {
                let boundary = period_height * multiple;
                assert_eq!(
                    boundary % epoch_length,
                    0,
                    "Boundary {} for period {} must align to epoch_length {}",
                    boundary,
                    period.as_str(),
                    epoch_length
                );
                assert!(
                    period.is_boundary(boundary),
                    "Height {} should be recognized as boundary for period {}",
                    boundary,
                    period.as_str()
                );
            }
        }
    }
}
