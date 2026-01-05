use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::SectorDao;

/// Minimal DAO treasury contract: stateful ledger only.
///
/// Accepts credits from the fee distributor and tracks total received.
/// No economic logic, no percentage math, no outbound transfers in Phase 1.
///
/// # Core invariants:
/// 1. Sector identity is immutable (set at init, never changes)
/// 2. Only authorized fee_collector can credit
/// 3. total_received only increases (monotonic)
/// 4. No internal fee calculations (prevents duplicate logic)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovDaoTreasury {
    // Immutable fields (set at init, never change)
    sector: SectorDao,
    authorized_fee_collector: PublicKey,

    // Mutable but auditable
    total_received: u64,
    last_credit_height: u64,
}

impl SovDaoTreasury {
    /// Initialize a new DAO treasury for a specific sector.
    ///
    /// # Invariants enforced:
    /// - Sector identity is immutable once set
    /// - Fee collector address must be non-zero
    /// - total_received starts at 0
    pub fn init(sector: SectorDao, authorized_fee_collector: PublicKey) -> Result<Self, String> {
        // Validate fee collector is non-zero
        if authorized_fee_collector.as_bytes().iter().all(|b| *b == 0) {
            return Err("Fee collector address cannot be zero".to_string());
        }

        Ok(SovDaoTreasury {
            sector,
            authorized_fee_collector,
            total_received: 0,
            last_credit_height: 0,
        })
    }

    /// Credit tokens to this treasury.
    ///
    /// Restricted to the authorized fee_collector only.
    /// Amount must be > 0 (rejects zero).
    /// Only increments, never decrements (monotonic invariant).
    /// Block height must be >= last recorded height (monotonic audit trail).
    ///
    /// # Invariants enforced:
    /// - Authorization: only fee_collector can credit
    /// - Monetary: amount > 0, no overflow
    /// - Temporal: block_height >= last_credit_height (monotonic audit trail)
    pub fn credit(
        &mut self,
        caller: &PublicKey,
        amount: u64,
        block_height: u64,
    ) -> Result<(), String> {
        // PRE-VALIDATE: all checks before any mutation

        // Authorization check
        if caller != &self.authorized_fee_collector {
            return Err(
                "Only authorized fee collector can credit this treasury".to_string(),
            );
        }

        // Reject zero amounts
        if amount == 0 {
            return Err("Cannot credit zero amount".to_string());
        }

        // Check overflow
        if self.total_received.checked_add(amount).is_none() {
            return Err("Credit would cause total_received to overflow".to_string());
        }

        // Enforce monotonic block height (audit trail invariant)
        // Prevents accidental or malicious out-of-order credits
        if block_height < self.last_credit_height {
            return Err(format!(
                "Block height must be >= last recorded height ({} >= {})",
                block_height, self.last_credit_height
            ));
        }

        // MUTATE only after all validations pass (atomicity)
        self.total_received += amount;
        self.last_credit_height = block_height;

        Ok(())
    }

    /// Get the sector this treasury serves.
    /// Sector identity is immutable.
    pub fn sector(&self) -> SectorDao {
        self.sector
    }

    /// Get total amount received by this treasury across all blocks.
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Get the block height of the last credit.
    /// Useful for audit and consistency checks.
    pub fn last_credit_height(&self) -> u64 {
        self.last_credit_height
    }

    /// Get the authorized fee collector address.
    /// Only this address can credit the treasury.
    pub fn authorized_fee_collector(&self) -> &PublicKey {
        &self.authorized_fee_collector
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    // ============================================================================
    // INITIALIZATION TESTS
    // ============================================================================

    #[test]
    fn test_init_sets_sector() {
        let fee_collector = create_test_public_key(1);

        let treasury = SovDaoTreasury::init(SectorDao::Healthcare, fee_collector).unwrap();

        assert_eq!(treasury.sector(), SectorDao::Healthcare);
        assert_eq!(treasury.total_received(), 0);
        assert_eq!(treasury.last_credit_height(), 0);
    }

    #[test]
    fn test_init_sets_fee_collector() {
        let fee_collector = create_test_public_key(1);

        let treasury = SovDaoTreasury::init(SectorDao::Education, fee_collector.clone()).unwrap();

        assert_eq!(treasury.authorized_fee_collector(), &fee_collector);
    }

    #[test]
    fn test_init_rejects_zero_fee_collector() {
        let zero_addr = PublicKey::new(vec![0u8; 1312]);

        let result = SovDaoTreasury::init(SectorDao::Energy, zero_addr);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Fee collector address cannot be zero"));
    }

    // ============================================================================
    // AUTHORIZATION TESTS
    // ============================================================================

    #[test]
    fn test_credit_by_authorized_fee_collector_succeeds() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone()).unwrap();

        let result = treasury.credit(&fee_collector, 1_000_000, 100);

        assert!(result.is_ok());
        assert_eq!(treasury.total_received(), 1_000_000);
        assert_eq!(treasury.last_credit_height(), 100);
    }

    #[test]
    fn test_credit_by_non_authorized_caller_fails() {
        let fee_collector = create_test_public_key(1);
        let attacker = create_test_public_key(2);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector).unwrap();

        let result = treasury.credit(&attacker, 1_000_000, 100);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Only authorized fee collector can credit"));

        // Verify state unchanged
        assert_eq!(treasury.total_received(), 0);
    }

    // ============================================================================
    // MONOTONIC ACCOUNTING TESTS
    // ============================================================================

    #[test]
    fn test_credit_zero_amount_rejected() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone()).unwrap();

        let result = treasury.credit(&fee_collector, 0, 100);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot credit zero amount"));

        // Verify state unchanged
        assert_eq!(treasury.total_received(), 0);
    }

    #[test]
    fn test_credit_increases_total_monotonically() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Housing, fee_collector.clone()).unwrap();

        // First credit
        treasury.credit(&fee_collector, 1_000_000, 100).unwrap();
        assert_eq!(treasury.total_received(), 1_000_000);

        // Second credit (adds to first)
        treasury.credit(&fee_collector, 2_000_000, 200).unwrap();
        assert_eq!(treasury.total_received(), 3_000_000);

        // Third credit (never decreases)
        treasury.credit(&fee_collector, 500_000, 300).unwrap();
        assert_eq!(treasury.total_received(), 3_500_000);
    }

    #[test]
    fn test_credit_overflow_protection() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Food, fee_collector.clone()).unwrap();

        // Set total_received near u64::MAX
        treasury.total_received = u64::MAX - 100;

        // Try to credit an amount that would overflow
        let result = treasury.credit(&fee_collector, 1000, 100);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("would cause total_received to overflow"));

        // Verify state unchanged
        assert_eq!(treasury.total_received(), u64::MAX - 100);
    }

    #[test]
    fn test_last_credit_height_updates() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Energy, fee_collector.clone()).unwrap();

        assert_eq!(treasury.last_credit_height(), 0);

        treasury.credit(&fee_collector, 1_000_000, 42).unwrap();
        assert_eq!(treasury.last_credit_height(), 42);

        treasury.credit(&fee_collector, 500_000, 100).unwrap();
        assert_eq!(treasury.last_credit_height(), 100);
    }

    // ============================================================================
    // IMMUTABILITY TESTS
    // ============================================================================

    #[test]
    fn test_sector_is_immutable() {
        let fee_collector = create_test_public_key(1);
        let treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector).unwrap();

        // sector() returns same value always
        assert_eq!(treasury.sector(), SectorDao::Healthcare);
        assert_eq!(treasury.sector(), SectorDao::Healthcare);

        // No setter method exists for sector
        // (This is verified by absence in the API)
    }

    #[test]
    fn test_all_five_sectors_supported() {
        let fee_collector = create_test_public_key(1);

        let sectors = [
            SectorDao::Healthcare,
            SectorDao::Education,
            SectorDao::Energy,
            SectorDao::Housing,
            SectorDao::Food,
        ];

        for sector in &sectors {
            let treasury = SovDaoTreasury::init(*sector, fee_collector.clone()).unwrap();
            assert_eq!(treasury.sector(), *sector);
        }
    }

    // ============================================================================
    // ATOMICITY TESTS
    // ============================================================================

    #[test]
    fn test_credit_atomicity_authorization_checked_before_mutation() {
        let fee_collector = create_test_public_key(1);
        let attacker = create_test_public_key(2);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone()).unwrap();

        let initial_total = treasury.total_received();
        let initial_height = treasury.last_credit_height();

        // Try unauthorized credit
        let result = treasury.credit(&attacker, 1_000_000, 100);

        // Must fail
        assert!(result.is_err());

        // CRITICAL: State must be completely unchanged on failure
        assert_eq!(treasury.total_received(), initial_total);
        assert_eq!(treasury.last_credit_height(), initial_height);
    }

    #[test]
    fn test_credit_atomicity_amount_checked_before_mutation() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Education, fee_collector.clone()).unwrap();

        let initial_total = treasury.total_received();
        let initial_height = treasury.last_credit_height();

        // Try credit with zero amount
        let result = treasury.credit(&fee_collector, 0, 100);

        // Must fail
        assert!(result.is_err());

        // CRITICAL: State must be completely unchanged on failure
        assert_eq!(treasury.total_received(), initial_total);
        assert_eq!(treasury.last_credit_height(), initial_height);
    }

    // ============================================================================
    // BLOCK HEIGHT MONOTONICITY TESTS (Audit Trail)
    // ============================================================================

    #[test]
    fn test_block_height_increases_monotonically() {
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone()).unwrap();

        // Credit at height 100
        treasury.credit(&fee_collector, 1_000_000, 100).unwrap();
        assert_eq!(treasury.last_credit_height(), 100);

        // Credit at height 200 (increases)
        treasury.credit(&fee_collector, 500_000, 200).unwrap();
        assert_eq!(treasury.last_credit_height(), 200);

        // Credit at height 200 again (same is ok)
        treasury.credit(&fee_collector, 250_000, 200).unwrap();
        assert_eq!(treasury.last_credit_height(), 200);
    }

    #[test]
    fn test_credit_rejects_decreasing_block_height() {
        // CRITICAL: Block height must never decrease (monotonic audit trail)
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Education, fee_collector.clone()).unwrap();

        // First credit at height 200
        treasury.credit(&fee_collector, 1_000_000, 200).unwrap();
        assert_eq!(treasury.last_credit_height(), 200);

        let state_before = treasury.total_received();

        // Try to credit at earlier height 100 (should fail)
        let result = treasury.credit(&fee_collector, 500_000, 100);

        // Must fail
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Block height must be"));

        // CRITICAL: State must be completely unchanged on failure
        assert_eq!(treasury.total_received(), state_before);
        assert_eq!(treasury.last_credit_height(), 200);
    }

    #[test]
    fn test_block_height_monotonicity_prevents_timestamp_manipulation() {
        // Prevents malicious fee collector from submitting credits out of order
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Energy, fee_collector.clone()).unwrap();

        // Credit at block 1000
        treasury
            .credit(&fee_collector, 1_000_000, 1000)
            .unwrap();

        // Try to sneak in a credit at block 500 (earlier)
        let result = treasury.credit(&fee_collector, 100_000, 500);

        // Must reject
        assert!(result.is_err());

        // Later blocks are always accepted
        treasury
            .credit(&fee_collector, 500_000, 2000)
            .unwrap();
        assert_eq!(treasury.last_credit_height(), 2000);
    }

    // ============================================================================
    // INTEGRATION NOTES
    // ============================================================================
    // These unit tests verify treasury contract invariants locally.
    // Integration tests belong in the fee distributor:
    //   - Given Year 5 volume ($5B/month), fee is $50M
    //   - DAO allocation (30% of fee): $15M
    //   - Each DAO sector gets $3M (6% of fee)
    //   - Verify: sum(credits to 5 treasuries) == $15M
    //   - Verify: each treasury received exactly $3M
    //
    // This is the ONLY place where "6%" and allocation math is tested.
    // DAO treasuries must remain dumb ledgers.
}
