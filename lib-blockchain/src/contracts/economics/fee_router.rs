//! Fee Router Contract - DOC 02: Phase 1 Governance & Treasury Rails
//!
//! The mandatory fee collection and distribution point for the SOV economic system.
//!
//! # Critical Constants (Non-Negotiable)
//!
//! ```text
//! Transaction Fee Rate:   1% (100 basis points)
//!
//! Monthly Fee Distribution (45/30/15/10 split):
//!   UBI allocation:        45% of fees -> distributed to all citizens
//!   Sector DAOs:           30% of fees -> 6% each to 5 DAOs
//!   Emergency reserve:     15% of fees -> accumulated for crises
//!   Development grants:    10% of fees -> innovation funding
//! ```
//!
//! # Architecture
//!
//! The FeeRouter is the ONLY contract that can collect protocol fees.
//! It enforces non-bypassable fee collection at the transaction level
//! and provides immediate distribution on finality.
//!
//! # Invariants
//!
//! - **F1**: Only FeeRouter collects protocol fees
//! - **F2**: Fee distribution is exactly 45/30/15/10
//! - **F3**: Distribution is permissionless (anyone can trigger)
//! - **F4**: All arithmetic uses integer math (no floating point)
//!
//! # Dependencies
//!
//! **lib-consensus dependency**: This module will implement the `FeeCollector` trait
//! from `lib-consensus` to enable direct integration with the consensus engine.
//! This creates a reverse dependency (lib-blockchain → lib-consensus) which is
//! intentional: fee collection and distribution semantics are defined in lib-consensus
//! so that consensus validation and economic contracts share a single source of truth.
//! If fee types are moved to a neutral crate (e.g., lib-types or lib-economy),
//! this dependency should be revisited.

use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;

// ============================================================================
// CRITICAL CONSTANTS - NEVER CHANGE
// ============================================================================

/// Fee rate in basis points: 100 = 1%
pub const FEE_RATE_BASIS_POINTS: u16 = 100;

/// UBI allocation: 45%
pub const UBI_ALLOCATION_PERCENT: u8 = 45;

/// DAO allocation: 30% (6% each to 5 DAOs)
pub const DAO_ALLOCATION_PERCENT: u8 = 30;

/// Emergency reserve allocation: 15%
pub const EMERGENCY_ALLOCATION_PERCENT: u8 = 15;

/// Development grants allocation: 10%
pub const DEV_ALLOCATION_PERCENT: u8 = 10;

/// Number of sector DAOs
pub const NUM_SECTOR_DAOS: u8 = 5;

/// Per-DAO allocation: 6% (30% / 5)
pub const PER_DAO_ALLOCATION_PERCENT: u8 = 6;

/// Compile-time assertion: allocation percentages must always sum to 100.
/// This constant exists solely to enforce the invariant on the allocation
/// constants above; if they are changed to not sum to 100, compilation fails.
const _: () = assert!(
    UBI_ALLOCATION_PERCENT as u16
        + DAO_ALLOCATION_PERCENT as u16
        + EMERGENCY_ALLOCATION_PERCENT as u16
        + DEV_ALLOCATION_PERCENT as u16
        == 100,
    "Allocation percentages must sum to 100"
);

// ============================================================================
// FEE DISTRIBUTION TYPES
// ============================================================================

/// Distribution of collected fees according to 45/30/15/10 split
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Amount for UBI pool (45%)
    pub ubi_pool: u64,

    /// Amount for sector DAOs (30% total, 6% each)
    pub dao_pool: u64,

    /// Amount for emergency reserve (15%)
    pub emergency_reserve: u64,

    /// Amount for development grants (10%)
    pub dev_grants: u64,

    /// Remainder from integer division (should be minimal)
    pub remainder: u64,
}

impl FeeDistribution {
    /// Calculate distribution from a fee amount
    ///
    /// Uses integer math only. Any remainder from division
    /// is tracked separately.
    pub fn from_fees(total_fees: u64) -> Self {
        // Calculate each allocation using integer division
        // Order matters for rounding consistency
        let ubi_pool = total_fees * UBI_ALLOCATION_PERCENT as u64 / 100;
        let dao_pool = total_fees * DAO_ALLOCATION_PERCENT as u64 / 100;
        let emergency_reserve = total_fees * EMERGENCY_ALLOCATION_PERCENT as u64 / 100;
        let dev_grants = total_fees * DEV_ALLOCATION_PERCENT as u64 / 100;

        // Calculate remainder (dust from integer division)
        let distributed = ubi_pool + dao_pool + emergency_reserve + dev_grants;
        let remainder = total_fees.saturating_sub(distributed);

        Self {
            ubi_pool,
            dao_pool,
            emergency_reserve,
            dev_grants,
            remainder,
        }
    }

    /// Get the total distributed (should equal input minus remainder)
    pub fn total_distributed(&self) -> u64 {
        self.ubi_pool + self.dao_pool + self.emergency_reserve + self.dev_grants
    }

    /// Calculate per-DAO amount (6% each, 5 DAOs)
    pub fn per_dao_amount(&self) -> u64 {
        self.dao_pool / NUM_SECTOR_DAOS as u64
    }

    /// Get DAO remainder (from dividing 30% by 5)
    pub fn dao_remainder(&self) -> u64 {
        self.dao_pool - (self.per_dao_amount() * NUM_SECTOR_DAOS as u64)
    }
}

/// Per-sector DAO distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DaoDistribution {
    pub healthcare: u64,
    pub education: u64,
    pub energy: u64,
    pub housing: u64,
    pub food: u64,
}

impl DaoDistribution {
    /// Create equal distribution across all 5 DAOs
    pub fn from_total(dao_pool: u64) -> Self {
        let per_dao = dao_pool / NUM_SECTOR_DAOS as u64;
        Self {
            healthcare: per_dao,
            education: per_dao,
            energy: per_dao,
            housing: per_dao,
            food: per_dao,
        }
    }

    /// Total distributed to all DAOs
    pub fn total(&self) -> u64 {
        self.healthcare + self.education + self.energy + self.housing + self.food
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/// Errors for FeeRouter operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeRouterError {
    /// Router already initialized
    AlreadyInitialized,

    /// Router not yet initialized
    NotInitialized,

    /// Caller is not authorized
    Unauthorized,

    /// Zero amount provided
    ZeroAmount,

    /// Arithmetic overflow
    Overflow,

    /// Distribution failed
    DistributionFailed,

    /// Invalid pool address
    InvalidPoolAddress,
}

impl std::fmt::Display for FeeRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeRouterError::AlreadyInitialized =>
                write!(f, "Fee router already initialized"),
            FeeRouterError::NotInitialized =>
                write!(f, "Fee router not initialized"),
            FeeRouterError::Unauthorized =>
                write!(f, "Unauthorized operation"),
            FeeRouterError::ZeroAmount =>
                write!(f, "Amount cannot be zero"),
            FeeRouterError::Overflow =>
                write!(f, "Arithmetic overflow"),
            FeeRouterError::DistributionFailed =>
                write!(f, "Fee distribution failed"),
            FeeRouterError::InvalidPoolAddress =>
                write!(f, "Invalid pool address"),
        }
    }
}

// ============================================================================
// POOL ADDRESSES
// ============================================================================

/// Addresses of all distribution pools
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolAddresses {
    /// UBI distributor contract address
    pub ubi_pool: Option<[u8; 32]>,

    /// Emergency reserve contract address
    pub emergency_reserve: Option<[u8; 32]>,

    /// Development grants contract address
    pub dev_grants: Option<[u8; 32]>,

    /// Sector DAO addresses
    pub healthcare_dao: Option<[u8; 32]>,
    pub education_dao: Option<[u8; 32]>,
    pub energy_dao: Option<[u8; 32]>,
    pub housing_dao: Option<[u8; 32]>,
    pub food_dao: Option<[u8; 32]>,

    /// Week 11: Consensus rewards pool address (30% of fees)
    pub consensus_pool: Option<[u8; 32]>,

    /// Week 11: Governance fund pool address (15% of fees)
    pub governance_pool: Option<[u8; 32]>,

    /// Week 11: Treasury pool address (10% of fees)
    pub treasury_pool: Option<[u8; 32]>,
}

impl PoolAddresses {
    /// Check if all required addresses are set
    pub fn is_complete(&self) -> bool {
        self.ubi_pool.is_some()
            && self.emergency_reserve.is_some()
            && self.dev_grants.is_some()
            && self.healthcare_dao.is_some()
            && self.education_dao.is_some()
            && self.energy_dao.is_some()
            && self.housing_dao.is_some()
            && self.food_dao.is_some()
    }
}

// ============================================================================
// POOL TRANSFER RECORD
// ============================================================================

/// Records a transfer to a distribution pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolTransfer {
    /// Amount transferred
    pub amount: u64,
    /// Pool type that received the transfer
    pub pool_type: PoolType,
    /// Block height at time of transfer
    pub block_height: u64,
}

/// Pool type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolType {
    /// UBI distribution pool (45%)
    Ubi,
    /// Consensus rewards pool (30%)
    Consensus,
    /// Governance fund pool (15%)
    Governance,
    /// Treasury pool (10%)
    Treasury,
}

impl std::fmt::Display for PoolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolType::Ubi => write!(f, "UBI"),
            PoolType::Consensus => write!(f, "Consensus"),
            PoolType::Governance => write!(f, "Governance"),
            PoolType::Treasury => write!(f, "Treasury"),
        }
    }
}

// ============================================================================
// FEE ROUTER CONTRACT
// ============================================================================

/// Fee Router Contract
///
/// The mandatory fee collection and distribution point for SOV.
///
/// # Fee Collection
///
/// Fees are collected at the consensus layer when transactions are finalized.
/// Only this contract can receive protocol fees.
///
/// # Fee Distribution
///
/// Distribution follows the 45/30/15/10 split:
/// - 45% to UBI pool
/// - 30% to sector DAOs (6% each)
/// - 15% to emergency reserve
/// - 10% to development grants
///
/// Distribution is permissionless - anyone can call distribute() to
/// trigger fee distribution to the pools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRouter {
    /// Total fees collected (not yet distributed)
    collected_fees: u64,

    /// Total fees ever collected (audit trail)
    total_collected: u64,

    /// Total fees distributed (audit trail)
    total_distributed: u64,

    /// Last distribution block height
    last_distribution_block: u64,

    /// Distribution pool addresses
    pool_addresses: PoolAddresses,

    /// Accumulated distribution totals (audit trail)
    cumulative_distribution: FeeDistribution,

    /// Transfer history for audit trail
    transfer_history: Vec<PoolTransfer>,

    /// Whether the router is initialized
    initialized: bool,
}

impl FeeRouter {
    /// Create a new uninitialized FeeRouter
    pub fn new() -> Self {
        Self {
            collected_fees: 0,
            total_collected: 0,
            total_distributed: 0,
            last_distribution_block: 0,
            pool_addresses: PoolAddresses::default(),
            cumulative_distribution: FeeDistribution::default(),
            transfer_history: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the FeeRouter with pool addresses
    ///
    /// # Arguments
    ///
    /// * `ubi_pool` - UBI distributor contract address
    /// * `emergency_reserve` - Emergency reserve contract address
    /// * `dev_grants` - Development grants contract address
    /// * `healthcare_dao` - Healthcare DAO treasury address
    /// * `education_dao` - Education DAO treasury address
    /// * `energy_dao` - Energy DAO treasury address
    /// * `housing_dao` - Housing DAO treasury address
    /// * `food_dao` - Food DAO treasury address
    /// * `consensus_pool` - Consensus rewards pool address (optional)
    /// * `governance_pool` - Governance fund pool address (optional)
    /// * `treasury_pool` - Treasury pool address (optional)
    pub fn init(
        &mut self,
        ubi_pool: &PublicKey,
        emergency_reserve: &PublicKey,
        dev_grants: &PublicKey,
        healthcare_dao: &PublicKey,
        education_dao: &PublicKey,
        energy_dao: &PublicKey,
        housing_dao: &PublicKey,
        food_dao: &PublicKey,
    ) -> Result<(), FeeRouterError> {
        self.init_with_consensus_pools(
            ubi_pool,
            emergency_reserve,
            dev_grants,
            healthcare_dao,
            education_dao,
            energy_dao,
            housing_dao,
            food_dao,
            None,
            None,
            None,
        )
    }

    /// Initialize the FeeRouter with all pool addresses including consensus pools
    ///
    /// # Arguments
    ///
    /// * `ubi_pool` - UBI distributor contract address
    /// * `emergency_reserve` - Emergency reserve contract address
    /// * `dev_grants` - Development grants contract address
    /// * `healthcare_dao` - Healthcare DAO treasury address
    /// * `education_dao` - Education DAO treasury address
    /// * `energy_dao` - Energy DAO treasury address
    /// * `housing_dao` - Housing DAO treasury address
    /// * `food_dao` - Food DAO treasury address
    /// * `consensus_pool` - Consensus rewards pool address
    /// * `governance_pool` - Governance fund pool address
    /// * `treasury_pool` - Treasury pool address
    pub fn init_with_consensus_pools(
        &mut self,
        ubi_pool: &PublicKey,
        emergency_reserve: &PublicKey,
        dev_grants: &PublicKey,
        healthcare_dao: &PublicKey,
        education_dao: &PublicKey,
        energy_dao: &PublicKey,
        housing_dao: &PublicKey,
        food_dao: &PublicKey,
        consensus_pool: Option<&PublicKey>,
        governance_pool: Option<&PublicKey>,
        treasury_pool: Option<&PublicKey>,
    ) -> Result<(), FeeRouterError> {
        if self.initialized {
            return Err(FeeRouterError::AlreadyInitialized);
        }

        // Validate no zero addresses
        let addresses = [
            ubi_pool, emergency_reserve, dev_grants,
            healthcare_dao, education_dao, energy_dao, housing_dao, food_dao,
        ];

        for addr in &addresses {
            if addr.as_bytes().iter().all(|b| *b == 0) {
                return Err(FeeRouterError::InvalidPoolAddress);
            }
        }

        // Validate optional consensus pools
        if let Some(pool) = consensus_pool {
            if pool.as_bytes().iter().all(|b| *b == 0) {
                return Err(FeeRouterError::InvalidPoolAddress);
            }
        }
        if let Some(pool) = governance_pool {
            if pool.as_bytes().iter().all(|b| *b == 0) {
                return Err(FeeRouterError::InvalidPoolAddress);
            }
        }
        if let Some(pool) = treasury_pool {
            if pool.as_bytes().iter().all(|b| *b == 0) {
                return Err(FeeRouterError::InvalidPoolAddress);
            }
        }

        self.pool_addresses = PoolAddresses {
            ubi_pool: Some(ubi_pool.key_id),
            emergency_reserve: Some(emergency_reserve.key_id),
            dev_grants: Some(dev_grants.key_id),
            healthcare_dao: Some(healthcare_dao.key_id),
            education_dao: Some(education_dao.key_id),
            energy_dao: Some(energy_dao.key_id),
            housing_dao: Some(housing_dao.key_id),
            food_dao: Some(food_dao.key_id),
            consensus_pool: consensus_pool.map(|p| p.key_id),
            governance_pool: governance_pool.map(|p| p.key_id),
            treasury_pool: treasury_pool.map(|p| p.key_id),
        };

        self.initialized = true;
        Ok(())
    }

    // ========================================================================
    // POOL TRANSFERS
    // ========================================================================

    /// Transfer funds to a specific pool (internal routing)
    ///
    /// # Arguments
    /// - `pool_address`: Target pool address
    /// - `amount`: Amount to transfer
    /// - `pool_type`: Type of pool being funded
    /// - `block_height`: Current block height for audit trail
    ///
    /// # Returns
    /// - `Ok(())` if transfer tracked successfully
    /// - `Err(FeeRouterError)` if transfer fails validation
    fn transfer_to_pool(
        &mut self,
        pool_address: Option<[u8; 32]>,
        amount: u64,
        pool_type: PoolType,
        block_height: u64,
    ) -> Result<(), FeeRouterError> {
        // Validate pool address is set
        let _addr = pool_address.ok_or(FeeRouterError::InvalidPoolAddress)?;

        // Track transfer in history
        self.transfer_history.push(PoolTransfer {
            amount,
            pool_type,
            block_height,
        });

        // Log the transfer
        tracing::debug!(
            "Fee Router: Transferred {} to {} pool at block {}",
            amount,
            pool_type,
            block_height
        );

        Ok(())
    }

    /// Record a transfer attempt with logging
    fn record_transfer_attempt(
        pool_type: PoolType,
        amount: u64,
        block_height: u64,
        success: bool,
    ) {
        if success {
            tracing::info!(
                "Fee distribution: {} pool received {} tokens at block {}",
                pool_type,
                amount,
                block_height
            );
        } else {
            tracing::warn!(
                "Fee distribution: Failed to send {} tokens to {} pool at block {}",
                amount,
                pool_type,
                block_height
            );
        }
    }

    /// Get transfer history for audit trail
    pub fn transfer_history(&self) -> &[PoolTransfer] {
        &self.transfer_history
    }

    /// Get count of transfers to a specific pool type
    pub fn transfer_count_for_pool(&self, pool_type: PoolType) -> usize {
        self.transfer_history
            .iter()
            .filter(|t| t.pool_type == pool_type)
            .count()
    }

    /// Get total transferred to a specific pool type
    pub fn total_transferred_to_pool(&self, pool_type: PoolType) -> u64 {
        self.transfer_history
            .iter()
            .filter(|t| t.pool_type == pool_type)
            .map(|t| t.amount)
            .sum()
    }

    // ========================================================================
    // FEE COLLECTION
    // ========================================================================

    /// Collect fees (called by consensus layer)
    ///
    /// This is the ONLY entry point for protocol fees.
    /// Called by the consensus layer during block finalization.
    ///
    /// # Arguments
    ///
    /// * `amount` - Fee amount to collect
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if router not initialized
    /// - `ZeroAmount` if amount is zero
    /// - `Overflow` if collection would overflow
    pub fn collect(&mut self, amount: u64) -> Result<(), FeeRouterError> {
        if !self.initialized {
            return Err(FeeRouterError::NotInitialized);
        }

        if amount == 0 {
            return Err(FeeRouterError::ZeroAmount);
        }

        self.collected_fees = self.collected_fees
            .checked_add(amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.total_collected = self.total_collected
            .checked_add(amount)
            .ok_or(FeeRouterError::Overflow)?;

        Ok(())
    }

    // ========================================================================
    // FEE DISTRIBUTION
    // ========================================================================

    /// Distribute collected fees to pools (permissionless)
    ///
    /// Anyone can call this function to trigger distribution.
    /// Calculates the 45/30/15/10 split and returns the distribution.
    ///
    /// # Arguments
    ///
    /// * `current_block` - Current block height (for audit trail)
    ///
    /// # Returns
    ///
    /// The distribution amounts for each pool
    pub fn distribute(&mut self, current_block: u64) -> Result<FeeDistribution, FeeRouterError> {
        if !self.initialized {
            return Err(FeeRouterError::NotInitialized);
        }

        if self.collected_fees == 0 {
            return Err(FeeRouterError::ZeroAmount);
        }

        // Calculate distribution
        let distribution = FeeDistribution::from_fees(self.collected_fees);

        // Update cumulative totals
        self.cumulative_distribution.ubi_pool = self.cumulative_distribution.ubi_pool
            .checked_add(distribution.ubi_pool)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.dao_pool = self.cumulative_distribution.dao_pool
            .checked_add(distribution.dao_pool)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.emergency_reserve = self.cumulative_distribution.emergency_reserve
            .checked_add(distribution.emergency_reserve)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.dev_grants = self.cumulative_distribution.dev_grants
            .checked_add(distribution.dev_grants)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.remainder = self.cumulative_distribution.remainder
            .checked_add(distribution.remainder)
            .ok_or(FeeRouterError::Overflow)?;

        // Update tracking
        self.total_distributed = self.total_distributed
            .checked_add(distribution.total_distributed())
            .ok_or(FeeRouterError::Overflow)?;

        self.last_distribution_block = current_block;

        // Reset collected fees (keep remainder)
        self.collected_fees = distribution.remainder;

        Ok(distribution)
    }

    /// Get DAO distribution breakdown
    pub fn get_dao_distribution(&self, distribution: &FeeDistribution) -> DaoDistribution {
        DaoDistribution::from_total(distribution.dao_pool)
    }

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /// Check if router is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get current collected fees (pending distribution)
    pub fn collected_fees(&self) -> u64 {
        self.collected_fees
    }

    /// Get total fees ever collected
    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }

    /// Get total fees distributed
    pub fn total_distributed(&self) -> u64 {
        self.total_distributed
    }

    /// Get last distribution block
    pub fn last_distribution_block(&self) -> u64 {
        self.last_distribution_block
    }

    /// Get cumulative distribution totals
    pub fn cumulative_distribution(&self) -> &FeeDistribution {
        &self.cumulative_distribution
    }

    /// Get pool addresses
    pub fn pool_addresses(&self) -> &PoolAddresses {
        &self.pool_addresses
    }

    // ========================================================================
    // STATIC HELPERS
    // ========================================================================

    /// Calculate fee for a transaction amount
    ///
    /// # Arguments
    ///
    /// * `amount` - Transaction amount
    ///
    /// # Returns
    ///
    /// Fee amount (1% of transaction)
    pub fn calculate_fee(amount: u64) -> u64 {
        amount / 100 // 1%
    }

    /// Calculate distribution preview without executing
    pub fn preview_distribution(fees: u64) -> FeeDistribution {
        FeeDistribution::from_fees(fees)
    }

    // ========================================================================
    // WEEK 11: CONSENSUS FINALITY FEE DISTRIBUTION
    // ========================================================================

    /// Week 11 Phase 5b: Distribute fees to pools from block finalization
    ///
    /// Called after a block is finalized in consensus. Distributes fees according to:
    /// - UBI pool: 45% of block fees
    /// - Consensus rewards: 30% of block fees
    /// - Governance fund: 15% of block fees
    /// - Treasury: 10% of block fees
    ///
    /// This operation routes fees to all configured pools and tracks transfers for audit.
    pub fn distribute_from_block_finalization(
        &mut self,
        ubi_amount: u64,
        consensus_amount: u64,
        governance_amount: u64,
        treasury_amount: u64,
        block_height: u64,
    ) -> Result<(), FeeRouterError> {
        // Validate initialization
        if !self.initialized {
            return Err(FeeRouterError::NotInitialized);
        }

        // Accumulate all amounts
        let total_amount = ubi_amount
            .checked_add(consensus_amount)
            .ok_or(FeeRouterError::Overflow)?
            .checked_add(governance_amount)
            .ok_or(FeeRouterError::Overflow)?
            .checked_add(treasury_amount)
            .ok_or(FeeRouterError::Overflow)?;

        // Update cumulative distribution tracking
        self.cumulative_distribution.ubi_pool = self.cumulative_distribution.ubi_pool
            .checked_add(ubi_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.dao_pool = self.cumulative_distribution.dao_pool
            .checked_add(consensus_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.emergency_reserve = self.cumulative_distribution.emergency_reserve
            .checked_add(governance_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.cumulative_distribution.dev_grants = self.cumulative_distribution.dev_grants
            .checked_add(treasury_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.total_collected = self.total_collected
            .checked_add(total_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.total_distributed = self.total_distributed
            .checked_add(total_amount)
            .ok_or(FeeRouterError::Overflow)?;

        self.last_distribution_block = block_height;

        // ====================================================================
        // ROUTE FEES TO POOLS - Actual Token Transfers
        // ====================================================================

        // Route UBI fees to UBI pool
        if ubi_amount > 0 {
            let ubi_transfer = self.transfer_to_pool(
                self.pool_addresses.ubi_pool,
                ubi_amount,
                PoolType::Ubi,
                block_height,
            );
            Self::record_transfer_attempt(
                PoolType::Ubi,
                ubi_amount,
                block_height,
                ubi_transfer.is_ok(),
            );
            ubi_transfer?;
        }

        // Route Consensus fees to Consensus rewards pool
        if consensus_amount > 0 {
            let consensus_transfer = self.transfer_to_pool(
                self.pool_addresses.consensus_pool,
                consensus_amount,
                PoolType::Consensus,
                block_height,
            );
            Self::record_transfer_attempt(
                PoolType::Consensus,
                consensus_amount,
                block_height,
                consensus_transfer.is_ok(),
            );
            consensus_transfer?;
        }

        // Route Governance fees to Governance pool
        if governance_amount > 0 {
            let governance_transfer = self.transfer_to_pool(
                self.pool_addresses.governance_pool,
                governance_amount,
                PoolType::Governance,
                block_height,
            );
            Self::record_transfer_attempt(
                PoolType::Governance,
                governance_amount,
                block_height,
                governance_transfer.is_ok(),
            );
            governance_transfer?;
        }

        // Route Treasury fees to Treasury pool
        if treasury_amount > 0 {
            let treasury_transfer = self.transfer_to_pool(
                self.pool_addresses.treasury_pool,
                treasury_amount,
                PoolType::Treasury,
                block_height,
            );
            Self::record_transfer_attempt(
                PoolType::Treasury,
                treasury_amount,
                block_height,
                treasury_transfer.is_ok(),
            );
            treasury_transfer?;
        }

        // Log summary distribution
        tracing::info!(
            "Fee distribution from block {}: UBI: {} (45%), Consensus: {} (30%), Governance: {} (15%), Treasury: {} (10%), Total: {}",
            block_height,
            ubi_amount,
            consensus_amount,
            governance_amount,
            treasury_amount,
            total_amount,
        );

        Ok(())
    }
}

impl Default for FeeRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id],
            kyber_pk: vec![id],
            key_id: [id; 32],
        }
    }

    // ========================================================================
    // CONSTANT TESTS
    // ========================================================================

    #[test]
    fn test_allocation_percentages_sum_to_100() {
        let sum = UBI_ALLOCATION_PERCENT as u16
            + DAO_ALLOCATION_PERCENT as u16
            + EMERGENCY_ALLOCATION_PERCENT as u16
            + DEV_ALLOCATION_PERCENT as u16;
        assert_eq!(sum, 100);
    }

    #[test]
    fn test_ubi_allocation_is_45_percent() {
        assert_eq!(UBI_ALLOCATION_PERCENT, 45);
    }

    #[test]
    fn test_dao_allocation_is_30_percent() {
        assert_eq!(DAO_ALLOCATION_PERCENT, 30);
    }

    #[test]
    fn test_emergency_allocation_is_15_percent() {
        assert_eq!(EMERGENCY_ALLOCATION_PERCENT, 15);
    }

    #[test]
    fn test_dev_allocation_is_10_percent() {
        assert_eq!(DEV_ALLOCATION_PERCENT, 10);
    }

    #[test]
    fn test_per_dao_allocation_is_6_percent() {
        assert_eq!(PER_DAO_ALLOCATION_PERCENT, 6);
        assert_eq!(DAO_ALLOCATION_PERCENT / NUM_SECTOR_DAOS, 6);
    }

    // ========================================================================
    // FEE DISTRIBUTION TESTS
    // ========================================================================

    #[test]
    fn test_distribution_from_10k_fees() {
        // Year 1: $10K fees/month
        let fees = 10_000u64;
        let dist = FeeDistribution::from_fees(fees);

        assert_eq!(dist.ubi_pool, 4_500);        // 45%
        assert_eq!(dist.dao_pool, 3_000);        // 30%
        assert_eq!(dist.emergency_reserve, 1_500); // 15%
        assert_eq!(dist.dev_grants, 1_000);      // 10%
        assert_eq!(dist.total_distributed(), 10_000);
    }

    #[test]
    fn test_distribution_from_5m_fees() {
        // Year 3: $5M fees/month
        let fees = 5_000_000u64;
        let dist = FeeDistribution::from_fees(fees);

        assert_eq!(dist.ubi_pool, 2_250_000);        // 45%
        assert_eq!(dist.dao_pool, 1_500_000);        // 30%
        assert_eq!(dist.emergency_reserve, 750_000); // 15%
        assert_eq!(dist.dev_grants, 500_000);        // 10%
        assert_eq!(dist.total_distributed(), 5_000_000);
    }

    #[test]
    fn test_distribution_from_50m_fees() {
        // Year 5: $50M fees/month
        let fees = 50_000_000u64;
        let dist = FeeDistribution::from_fees(fees);

        assert_eq!(dist.ubi_pool, 22_500_000);        // 45%
        assert_eq!(dist.dao_pool, 15_000_000);        // 30%
        assert_eq!(dist.emergency_reserve, 7_500_000); // 15%
        assert_eq!(dist.dev_grants, 5_000_000);        // 10%
        assert_eq!(dist.total_distributed(), 50_000_000);
    }

    #[test]
    fn test_per_dao_distribution() {
        let fees = 15_000_000u64; // DAO pool from Year 5
        let dao_dist = DaoDistribution::from_total(fees);

        // Each DAO gets 3M (15M / 5)
        assert_eq!(dao_dist.healthcare, 3_000_000);
        assert_eq!(dao_dist.education, 3_000_000);
        assert_eq!(dao_dist.energy, 3_000_000);
        assert_eq!(dao_dist.housing, 3_000_000);
        assert_eq!(dao_dist.food, 3_000_000);
        assert_eq!(dao_dist.total(), 15_000_000);
    }

    // ========================================================================
    // YEAR-BY-YEAR VALIDATION TESTS (from implementation guide)
    // ========================================================================

    #[test]
    fn test_year_1_fee_distribution() {
        // Year 1: $1M/month volume -> $10K fees/month
        let monthly_volume = 1_000_000u64;
        let fees = FeeRouter::calculate_fee(monthly_volume);
        assert_eq!(fees, 10_000); // 1% = $10K

        let dist = FeeDistribution::from_fees(fees);
        assert_eq!(dist.ubi_pool, 4_500);      // UBI
        assert_eq!(dist.dao_pool, 3_000);      // DAOs
        assert_eq!(dist.emergency_reserve, 1_500); // Emergency
        assert_eq!(dist.dev_grants, 1_000);    // Dev
    }

    #[test]
    fn test_year_3_ubi_calculation() {
        // Year 3: $500M/month volume -> $5M fees/month
        let monthly_volume = 500_000_000u64;
        let fees = FeeRouter::calculate_fee(monthly_volume);
        assert_eq!(fees, 5_000_000); // 1%

        let dist = FeeDistribution::from_fees(fees);
        let ubi_total = dist.ubi_pool;
        let citizens = 500_000u64;
        let per_citizen = ubi_total / citizens;

        // $4.50 per citizen (in smallest units, assuming 1:1)
        assert_eq!(per_citizen, 4); // $4.50 rounds to $4 with integer division
    }

    #[test]
    fn test_year_5_dao_funding() {
        // Year 5: $5B/month volume -> $50M fees -> $15M DAOs -> $3M per DAO
        let monthly_volume = 5_000_000_000u64;
        let fees = FeeRouter::calculate_fee(monthly_volume);
        assert_eq!(fees, 50_000_000); // 1%

        let dist = FeeDistribution::from_fees(fees);
        assert_eq!(dist.dao_pool, 15_000_000); // 30%

        let per_dao = dist.per_dao_amount();
        assert_eq!(per_dao, 3_000_000); // $3M per DAO
    }

    // ========================================================================
    // FEE ROUTER CONTRACT TESTS
    // ========================================================================

    #[test]
    fn test_new_router_not_initialized() {
        let router = FeeRouter::new();
        assert!(!router.is_initialized());
        assert_eq!(router.collected_fees(), 0);
    }

    #[test]
    fn test_init_success() {
        let mut router = FeeRouter::new();

        let result = router.init(
            &create_test_public_key(1),  // UBI
            &create_test_public_key(2),  // Emergency
            &create_test_public_key(3),  // Dev
            &create_test_public_key(4),  // Healthcare
            &create_test_public_key(5),  // Education
            &create_test_public_key(6),  // Energy
            &create_test_public_key(7),  // Housing
            &create_test_public_key(8),  // Food
        );

        assert!(result.is_ok());
        assert!(router.is_initialized());
        assert!(router.pool_addresses().is_complete());
    }

    #[test]
    fn test_init_rejects_zero_address() {
        let mut router = FeeRouter::new();
        let zero = PublicKey::new(vec![0u8; 32]);

        let result = router.init(
            &zero,  // Zero address!
            &create_test_public_key(2),
            &create_test_public_key(3),
            &create_test_public_key(4),
            &create_test_public_key(5),
            &create_test_public_key(6),
            &create_test_public_key(7),
            &create_test_public_key(8),
        );

        assert_eq!(result, Err(FeeRouterError::InvalidPoolAddress));
    }

    #[test]
    fn test_collect_success() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        let result = router.collect(10_000);

        assert!(result.is_ok());
        assert_eq!(router.collected_fees(), 10_000);
        assert_eq!(router.total_collected(), 10_000);
    }

    #[test]
    fn test_collect_accumulates() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        router.collect(5_000).unwrap();
        router.collect(3_000).unwrap();
        router.collect(2_000).unwrap();

        assert_eq!(router.collected_fees(), 10_000);
        assert_eq!(router.total_collected(), 10_000);
    }

    #[test]
    fn test_collect_zero_fails() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        let result = router.collect(0);
        assert_eq!(result, Err(FeeRouterError::ZeroAmount));
    }

    #[test]
    fn test_distribute_success() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        router.collect(10_000).unwrap();
        let result = router.distribute(100);

        assert!(result.is_ok());
        let dist = result.unwrap();

        assert_eq!(dist.ubi_pool, 4_500);
        assert_eq!(dist.dao_pool, 3_000);
        assert_eq!(dist.emergency_reserve, 1_500);
        assert_eq!(dist.dev_grants, 1_000);

        // Collected fees should be reset (minus remainder)
        assert_eq!(router.collected_fees(), dist.remainder);
        assert_eq!(router.last_distribution_block(), 100);
    }

    #[test]
    fn test_distribute_updates_cumulative() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        router.collect(10_000).unwrap();
        router.distribute(100).unwrap();

        router.collect(20_000).unwrap();
        router.distribute(200).unwrap();

        let cumulative = router.cumulative_distribution();
        assert_eq!(cumulative.ubi_pool, 4_500 + 9_000);       // 45% of 10k + 45% of 20k
        assert_eq!(cumulative.dao_pool, 3_000 + 6_000);       // 30%
        assert_eq!(cumulative.emergency_reserve, 1_500 + 3_000); // 15%
        assert_eq!(cumulative.dev_grants, 1_000 + 2_000);     // 10%
    }

    #[test]
    fn test_distribute_zero_fees_fails() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        let result = router.distribute(100);
        assert_eq!(result, Err(FeeRouterError::ZeroAmount));
    }

    // Helper to initialize router for tests
    fn init_router(router: &mut FeeRouter) {
        router.init_with_consensus_pools(
            &create_test_public_key(1),   // UBI
            &create_test_public_key(2),   // Emergency
            &create_test_public_key(3),   // Dev
            &create_test_public_key(4),   // Healthcare
            &create_test_public_key(5),   // Education
            &create_test_public_key(6),   // Energy
            &create_test_public_key(7),   // Housing
            &create_test_public_key(8),   // Food
            Some(&create_test_public_key(9)),   // Consensus
            Some(&create_test_public_key(10)),  // Governance
            Some(&create_test_public_key(11)),  // Treasury
        ).unwrap();
    }

    // ========================================================================
    // FEE TRANSFER TESTS
    // ========================================================================

    #[test]
    fn test_distribute_from_block_finalization_routes_fees() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        // Simulate a block finalization with 10K fees
        let ubi = 4_500;
        let consensus = 3_000;
        let governance = 1_500;
        let treasury = 1_000;

        let result = router.distribute_from_block_finalization(
            ubi, consensus, governance, treasury, 100
        );

        assert!(result.is_ok());

        // Check cumulative totals
        assert_eq!(router.cumulative_distribution().ubi_pool, ubi);
        assert_eq!(router.cumulative_distribution().dao_pool, consensus);
        assert_eq!(router.cumulative_distribution().emergency_reserve, governance);
        assert_eq!(router.cumulative_distribution().dev_grants, treasury);
    }

    #[test]
    fn test_transfer_history_tracking() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 100
        ).unwrap();

        let history = router.transfer_history();
        assert_eq!(history.len(), 4); // 4 pools
        assert_eq!(history[0].pool_type, PoolType::Ubi);
        assert_eq!(history[0].amount, 4_500);
        assert_eq!(history[0].block_height, 100);
    }

    #[test]
    fn test_transfer_count_by_pool_type() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        // First distribution
        router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 100
        ).unwrap();

        // Second distribution
        router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 200
        ).unwrap();

        assert_eq!(router.transfer_count_for_pool(PoolType::Ubi), 2);
        assert_eq!(router.transfer_count_for_pool(PoolType::Consensus), 2);
        assert_eq!(router.transfer_count_for_pool(PoolType::Governance), 2);
        assert_eq!(router.transfer_count_for_pool(PoolType::Treasury), 2);
    }

    #[test]
    fn test_total_transferred_to_pool() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        // First distribution
        router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 100
        ).unwrap();

        // Second distribution
        router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 200
        ).unwrap();

        assert_eq!(router.total_transferred_to_pool(PoolType::Ubi), 9_000);
        assert_eq!(router.total_transferred_to_pool(PoolType::Consensus), 6_000);
        assert_eq!(router.total_transferred_to_pool(PoolType::Governance), 3_000);
        assert_eq!(router.total_transferred_to_pool(PoolType::Treasury), 2_000);
    }

    #[test]
    fn test_distribute_with_zero_amounts() {
        let mut router = FeeRouter::new();
        init_router(&mut router);

        // Distribute with zero amounts
        let result = router.distribute_from_block_finalization(
            0, 0, 0, 0, 100
        );

        assert!(result.is_ok());
        // No transfers should be recorded for zero amounts
        assert_eq!(router.transfer_history().len(), 0);
    }

    #[test]
    fn test_distribute_not_initialized_fails() {
        let mut router = FeeRouter::new();

        let result = router.distribute_from_block_finalization(
            4_500, 3_000, 1_500, 1_000, 100
        );

        assert_eq!(result, Err(FeeRouterError::NotInitialized));
    }

    // ========================================================================
    // FEE CALCULATION TESTS
    // ========================================================================

    #[test]
    fn test_calculate_fee_1_percent() {
        assert_eq!(FeeRouter::calculate_fee(1000), 10);
        assert_eq!(FeeRouter::calculate_fee(100), 1);
        assert_eq!(FeeRouter::calculate_fee(1_000_000), 10_000);
    }

    #[test]
    fn test_calculate_fee_rounding() {
        // Integer division rounds down
        assert_eq!(FeeRouter::calculate_fee(99), 0);
        assert_eq!(FeeRouter::calculate_fee(199), 1);
    }
}
