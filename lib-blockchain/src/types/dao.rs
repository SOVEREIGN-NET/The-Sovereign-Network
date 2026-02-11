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
    DaoNp,
    /// DAO-issued token for for-profit DAOs
    DaoFp,
}

impl TokenClass {
    /// String representation of the token class
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenClass::DaoNp => "dao_np",
            TokenClass::DaoFp => "dao_fp",
            TokenClass::SOV => "sov",
        }
    }

    /// Parse a token class from a string (case-insensitive)
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "dao_np" | "dao-np" => Some(TokenClass::DaoNp),
            "dao_fp" | "dao-fp" => Some(TokenClass::DaoFp),
            "sov" => Some(TokenClass::SOV),
            _ => None,
        }
    }

    /// Determine if the token belongs to a DAO
    pub fn is_dao_token(&self) -> bool {
        matches!(self, TokenClass::DaoNp | TokenClass::DaoFp)
    }
}

/// Treasury allocation rule for a DAO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryAllocation {
    /// Allocation percentage (0-100)
    percentage: u8,
    /// Optional vesting schedule in months (0 = immediate)
    vesting_months: Option<u16>,
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

    /// Validate allocation bounds (invariant enforcement at construction time)
    fn validate(&self) -> Result<(), &'static str> {
        if self.percentage > 100 {
            return Err("treasury allocation percentage must be between 0 and 100");
        }
        Ok(())
    }

    /// Returns true if funds are immediately available
    pub fn is_immediate(&self) -> bool {
        self.vesting_months.unwrap_or(0) == 0
    }

    /// Get allocation percentage
    pub fn percentage(&self) -> u8 {
        self.percentage
    }

    /// Get vesting schedule
    pub fn vesting_months(&self) -> Option<u16> {
        self.vesting_months
    }
}

/// Metadata describing DAO classification and treasury rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DAOMetadata {
    /// DAO classification (NP/FP)
    dao_type: DAOType,
    /// Primary token class for the DAO
    token_class: TokenClass,
    /// Treasury allocation policy for this DAO
    treasury_allocation: TreasuryAllocation,
}

// ============================================================================
// Difficulty Parameter Update Types
// ============================================================================

/// Difficulty parameter update data for DAO governance proposals
///
/// Used to propose changes to the blockchain's difficulty adjustment parameters
/// through the DAO governance system. This enables adaptive difficulty adjustment
/// to be controlled by governance rather than hardcoded values.
///
/// # Validation Rules
///
/// - `target_timespan` must be > 0
/// - `adjustment_interval` must be > 0
/// - `min_adjustment_factor` must be >= 1 (if provided)
/// - `max_adjustment_factor` must be >= 1 (if provided)
/// - `max_adjustment_factor` must be >= `min_adjustment_factor` (if both provided)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use lib_blockchain::types::DifficultyParameterUpdateData;
///
/// // Create a proposal to reduce adjustment interval
/// let update = DifficultyParameterUpdateData::new(
///     7 * 24 * 60 * 60,  // 1 week target_timespan
///     1008,               // 1008 blocks (half of default)
/// ).expect("valid parameters");
///
/// // Verify target block time is unchanged (10 minutes)
/// assert_eq!(update.target_block_time_secs(), 600);
/// ```
///
/// ## With Custom Adjustment Factors
///
/// ```rust
/// use lib_blockchain::types::DifficultyParameterUpdateData;
///
/// // Create proposal with asymmetric factors
/// let update = DifficultyParameterUpdateData::new_with_factors(
///     14 * 24 * 60 * 60,  // 2 weeks
///     2016,                // 2016 blocks
///     Some(2),             // Allow 2x decrease (conservative)
///     Some(8),             // Allow 8x increase (aggressive)
/// ).expect("valid parameters");
///
/// assert_eq!(update.min_adjustment_factor, Some(2));
/// assert_eq!(update.max_adjustment_factor, Some(8));
/// ```
///
/// ## Builder Pattern
///
/// ```rust
/// use lib_blockchain::types::DifficultyParameterUpdateData;
///
/// let update = DifficultyParameterUpdateData::new(604800, 1008)
///     .expect("valid parameters")
///     .with_min_factor(2)
///     .with_max_factor(8);
///
/// assert_eq!(update.min_adjustment_factor, Some(2));
/// assert_eq!(update.max_adjustment_factor, Some(8));
/// ```
///
/// # Governance Flow
///
/// 1. Create `DifficultyParameterUpdateData` with desired parameters
/// 2. Submit as `DaoProposalType::DifficultyParameterUpdate` proposal
/// 3. Community votes (requires 30% quorum)
/// 4. After passing and 7-day timelock, execute with `apply_difficulty_parameter_update()`
///
/// See [DIFFICULTY_GOVERNANCE.md](../../../docs/DIFFICULTY_GOVERNANCE.md) for full documentation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifficultyParameterUpdateData {
    /// Target time for difficulty adjustment interval (in seconds)
    /// This is the desired total time for `adjustment_interval` blocks.
    /// e.g., Bitcoin uses 14 days (1,209,600 seconds) for 2016 blocks.
    pub target_timespan: u64,

    /// Number of blocks between difficulty adjustments
    /// e.g., Bitcoin uses 2016 blocks between adjustments.
    pub adjustment_interval: u64,

    /// Minimum adjustment factor (multiplier, >= 1)
    /// Limits how much difficulty can decrease in a single adjustment.
    /// e.g., 4 means difficulty can decrease by at most 1/4 (divide by 4)
    /// Default: None (use DifficultyConfig's symmetric max_adjustment_factor)
    pub min_adjustment_factor: Option<u64>,

    /// Maximum adjustment factor (multiplier, >= 1)
    /// Limits how much difficulty can increase in a single adjustment.
    /// e.g., 4 means difficulty can increase by at most 4x
    /// Default: None (use DifficultyConfig's symmetric max_adjustment_factor)
    pub max_adjustment_factor: Option<u64>,
}

impl DifficultyParameterUpdateData {
    /// Create a new difficulty parameter update with required fields
    ///
    /// # Arguments
    /// * `target_timespan` - Target time for the adjustment interval (seconds)
    /// * `adjustment_interval` - Number of blocks between adjustments
    ///
    /// # Errors
    /// Returns an error if validation fails (e.g., zero values)
    pub fn new(target_timespan: u64, adjustment_interval: u64) -> Result<Self, &'static str> {
        let data = Self {
            target_timespan,
            adjustment_interval,
            min_adjustment_factor: None,
            max_adjustment_factor: None,
        };
        data.validate()?;
        Ok(data)
    }

    /// Create a new difficulty parameter update with all fields
    ///
    /// # Arguments
    /// * `target_timespan` - Target time for the adjustment interval (seconds)
    /// * `adjustment_interval` - Number of blocks between adjustments
    /// * `min_adjustment_factor` - Minimum adjustment factor (multiplier, >= 1)
    /// * `max_adjustment_factor` - Maximum adjustment factor (multiplier, >= 1)
    ///
    /// # Errors
    /// Returns an error if validation fails
    pub fn new_with_factors(
        target_timespan: u64,
        adjustment_interval: u64,
        min_adjustment_factor: Option<u64>,
        max_adjustment_factor: Option<u64>,
    ) -> Result<Self, &'static str> {
        let data = Self {
            target_timespan,
            adjustment_interval,
            min_adjustment_factor,
            max_adjustment_factor,
        };
        data.validate()?;
        Ok(data)
    }

    /// Validate the difficulty parameter update data
    ///
    /// # Validation Rules
    /// - `target_timespan` must be > 0
    /// - `adjustment_interval` must be > 0
    /// - `min_adjustment_factor` must be >= 1 (if provided)
    /// - `max_adjustment_factor` must be >= 1 (if provided)
    /// - `max_adjustment_factor` must be >= `min_adjustment_factor` (if both provided)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.target_timespan == 0 {
            return Err("target_timespan must be greater than 0");
        }

        if self.adjustment_interval == 0 {
            return Err("adjustment_interval must be greater than 0");
        }

        if let Some(min_factor) = self.min_adjustment_factor {
            if min_factor < 1 {
                return Err("min_adjustment_factor must be >= 1");
            }
        }

        if let Some(max_factor) = self.max_adjustment_factor {
            if max_factor < 1 {
                return Err("max_adjustment_factor must be >= 1");
            }
        }

        // If both factors are provided, max must be >= min
        if let (Some(min_factor), Some(max_factor)) =
            (self.min_adjustment_factor, self.max_adjustment_factor)
        {
            if max_factor < min_factor {
                return Err("max_adjustment_factor must be >= min_adjustment_factor");
            }
        }

        Ok(())
    }

    /// Calculate the target block time in seconds
    ///
    /// Returns the expected time per block based on target_timespan and adjustment_interval.
    pub fn target_block_time_secs(&self) -> u64 {
        if self.adjustment_interval == 0 {
            return 0;
        }
        self.target_timespan / self.adjustment_interval
    }

    /// Set the minimum adjustment factor
    pub fn with_min_factor(mut self, factor: u64) -> Self {
        self.min_adjustment_factor = Some(factor);
        self
    }

    /// Set the maximum adjustment factor
    pub fn with_max_factor(mut self, factor: u64) -> Self {
        self.max_adjustment_factor = Some(factor);
        self
    }
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

    /// Validate metadata consistency and allocation bounds (invariant enforcement at construction time)
    fn validate(&self) -> Result<(), &'static str> {
        // Invariant: Treasury allocation must be valid
        if self.treasury_allocation.percentage() > 100 {
            return Err("treasury allocation percentage must be between 0 and 100");
        }

        // Invariant: Token-type consistency
        if matches!(self.token_class, TokenClass::DaoNp) && !self.dao_type.is_non_profit() {
            return Err("DaoNp tokens require NP DAO type");
        }

        if matches!(self.token_class, TokenClass::DaoFp) && !self.dao_type.is_for_profit() {
            return Err("DaoFp tokens require FP DAO type");
        }

        Ok(())
    }

    /// Get DAO type
    pub fn dao_type(&self) -> &DAOType {
        &self.dao_type
    }

    /// Get token class
    pub fn token_class(&self) -> &TokenClass {
        &self.token_class
    }

    /// Get treasury allocation
    pub fn treasury_allocation(&self) -> &TreasuryAllocation {
        &self.treasury_allocation
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
        assert_eq!(TokenClass::from_str("dao_np"), Some(TokenClass::DaoNp));
        assert_eq!(TokenClass::from_str("DAO-FP"), Some(TokenClass::DaoFp));
        assert_eq!(TokenClass::from_str("sov"), Some(TokenClass::SOV));
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
        let metadata = DAOMetadata::new(DAOType::NP, TokenClass::DaoNp, allocation.clone()).unwrap();
        metadata.validate().unwrap();

        let serialized = bincode::serialize(&metadata).expect("serialize metadata");
        let deserialized: DAOMetadata =
            bincode::deserialize(&serialized).expect("deserialize metadata");
        assert_eq!(metadata, deserialized);
        assert_eq!(deserialized.treasury_allocation, allocation);

        // Mismatched token/DAO type should fail
        let invalid = DAOMetadata::new(DAOType::NP, TokenClass::DaoFp, allocation);
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

    // ============================================================================
    // DIFFICULTY PARAMETER UPDATE TESTS
    // ============================================================================

    #[test]
    fn test_difficulty_parameter_update_basic_creation() {
        // Create with required fields only
        let update = DifficultyParameterUpdateData::new(
            14 * 24 * 60 * 60, // 2 weeks in seconds
            2016,             // blocks between adjustments (like Bitcoin)
        ).expect("valid parameters");

        assert_eq!(update.target_timespan, 14 * 24 * 60 * 60);
        assert_eq!(update.adjustment_interval, 2016);
        assert!(update.min_adjustment_factor.is_none());
        assert!(update.max_adjustment_factor.is_none());
    }

    #[test]
    fn test_difficulty_parameter_update_with_factors() {
        let update = DifficultyParameterUpdateData::new_with_factors(
            604800,   // 1 week in seconds
            1008,     // blocks
            Some(25), // min factor 25%
            Some(400), // max factor 400%
        ).expect("valid parameters");

        assert_eq!(update.target_timespan, 604800);
        assert_eq!(update.adjustment_interval, 1008);
        assert_eq!(update.min_adjustment_factor, Some(25));
        assert_eq!(update.max_adjustment_factor, Some(400));
    }

    #[test]
    fn test_difficulty_parameter_update_validation_zero_timespan() {
        let result = DifficultyParameterUpdateData::new(0, 2016);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "target_timespan must be greater than 0");
    }

    #[test]
    fn test_difficulty_parameter_update_validation_zero_interval() {
        let result = DifficultyParameterUpdateData::new(604800, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "adjustment_interval must be greater than 0");
    }

    #[test]
    fn test_difficulty_parameter_update_validation_zero_min_factor() {
        let result = DifficultyParameterUpdateData::new_with_factors(
            604800,
            2016,
            Some(0), // Invalid: must be >= 1
            None,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "min_adjustment_factor must be >= 1");
    }

    #[test]
    fn test_difficulty_parameter_update_validation_zero_max_factor() {
        let result = DifficultyParameterUpdateData::new_with_factors(
            604800,
            2016,
            None,
            Some(0), // Invalid: must be >= 1
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_adjustment_factor must be >= 1");
    }

    #[test]
    fn test_difficulty_parameter_update_validation_max_less_than_min() {
        let result = DifficultyParameterUpdateData::new_with_factors(
            604800,
            2016,
            Some(400), // min = 400
            Some(25),  // max = 25 (invalid: less than min)
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "max_adjustment_factor must be >= min_adjustment_factor");
    }

    #[test]
    fn test_difficulty_parameter_update_validation_equal_factors() {
        // Edge case: min == max should be valid
        let result = DifficultyParameterUpdateData::new_with_factors(
            604800,
            2016,
            Some(100),
            Some(100),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_difficulty_parameter_update_target_block_time() {
        // Bitcoin-like: 2 weeks / 2016 blocks = 600 seconds (10 minutes)
        let bitcoin_like = DifficultyParameterUpdateData::new(
            14 * 24 * 60 * 60,
            2016,
        ).unwrap();
        assert_eq!(bitcoin_like.target_block_time_secs(), 600);

        // SOV-like: 1 day / 8640 blocks = 10 seconds
        let zhtp_like = DifficultyParameterUpdateData::new(
            24 * 60 * 60,
            8640,
        ).unwrap();
        assert_eq!(zhtp_like.target_block_time_secs(), 10);
    }

    #[test]
    fn test_difficulty_parameter_update_builder_pattern() {
        let update = DifficultyParameterUpdateData::new(604800, 1008)
            .unwrap()
            .with_min_factor(25)
            .with_max_factor(400);

        assert_eq!(update.min_adjustment_factor, Some(25));
        assert_eq!(update.max_adjustment_factor, Some(400));
    }

    #[test]
    fn test_difficulty_parameter_update_serialization() {
        let update = DifficultyParameterUpdateData::new_with_factors(
            604800,
            2016,
            Some(25),
            Some(400),
        ).unwrap();

        let serialized = bincode::serialize(&update).expect("serialize update");
        let deserialized: DifficultyParameterUpdateData = 
            bincode::deserialize(&serialized).expect("deserialize update");

        assert_eq!(update, deserialized);
        assert_eq!(deserialized.target_timespan, 604800);
        assert_eq!(deserialized.adjustment_interval, 2016);
        assert_eq!(deserialized.min_adjustment_factor, Some(25));
        assert_eq!(deserialized.max_adjustment_factor, Some(400));
    }
}
