use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::{SectorDao, EconomicPeriod};

/// Minimal DAO treasury contract: stateful ledger only.
///
/// Accepts credits from the fee distributor and tracks total received.
/// No economic logic, no percentage math, no outbound transfers in Phase 1.
///
/// # Core invariants (1-4):
/// 1. Sector identity is immutable (set at init, never changes)
/// 2. Only authorized fee_collector can credit
/// 3. total_received only increases (monotonic)
/// 4. No internal fee calculations (prevents duplicate logic)
///
/// # Invariant C1: Credit–period consistency invariant
/// Every credit to a SovDaoTreasury must be associated with exactly one EconomicPeriod window.
/// credit(period_id, amount)
/// Credits without a period identifier are invalid once EconomicPeriods exist.
///
/// # Invariant C2: Monotonic period progression invariant
/// Treasury must reject credits that move backwards in economic time.
/// incoming_period_id >= last_recorded_period_id
/// This is stronger than block height audit and prevents retroactive accounting.
///
/// # Invariant C3: Period completeness invariant
/// For a given period:
/// sum(period_received[period]) is final once period closes.
/// After the boundary:
/// no additional credits for that period
/// late credits must fail or be redirected to the next period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovDaoTreasury {
    // Immutable fields (set at init, never change)
    sector: SectorDao,
    authorized_fee_collector: PublicKey,

    // Mutable but auditable (block-height based)
    total_received: u64,
    last_credit_height: u64,
    
    // Economic period tracking (Invariants C1-C3)
    allocation_period: Option<EconomicPeriod>,
    current_period: Option<u64>,        // Current period ID
    last_recorded_period: Option<u64>,  // Last period we recorded a credit for
    period_received: HashMap<u64, u64>, // period_id -> amount received in that period
}

impl SovDaoTreasury {
    /// Initialize a new DAO treasury for a specific sector.
    ///
    /// # Parameters:
    /// - allocation_period: If Some, enables period-based accounting. If None, only block-height audit.
    ///
    /// # Invariants enforced:
    /// - Sector identity is immutable once set
    /// - Fee collector address must be non-zero
    /// - total_received starts at 0
    /// - Period state is explicit (Invariant C1)
    pub fn init(
        sector: SectorDao,
        authorized_fee_collector: PublicKey,
        allocation_period: Option<EconomicPeriod>,
    ) -> Result<Self, String> {
        // Validate fee collector is non-zero
        if authorized_fee_collector.as_bytes().iter().all(|b| *b == 0) {
            return Err("Fee collector address cannot be zero".to_string());
        }

        Ok(SovDaoTreasury {
            sector,
            authorized_fee_collector,
            total_received: 0,
            last_credit_height: 0,
            allocation_period,
            current_period: None,
            last_recorded_period: None,
            period_received: HashMap::new(),
        })
    }

    /// Credit tokens to this treasury.
    ///
    /// Restricted to the authorized fee_collector only.
    /// Amount must be > 0 (rejects zero).
    /// Only increments, never decrements (monotonic invariant).
    /// Block height must be >= last recorded height (monotonic audit trail).
    ///
    /// If allocation_period is set, also:
    /// - Associates credit with a period (Invariant C1)
    /// - Enforces monotonic period progression (Invariant C2)
    /// - Tracks per-period accumulation (Invariant C3)
    ///
    /// # Invariants enforced:
    /// - Authorization: only fee_collector can credit
    /// - Monetary: amount > 0, no overflow
    /// - Temporal: block_height >= last_credit_height (monotonic audit trail)
    /// - Period: period_id >= last_recorded_period (Invariant C2)
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

        // Period validation (Invariants C1-C3)
        let period_id = if let Some(period) = self.allocation_period {
            let pid = period.period_id_for_height(block_height);
            
            // Invariant C2: Monotonic period progression
            if let Some(last_period) = self.last_recorded_period {
                if pid < last_period {
                    return Err(format!(
                        "Period moved backwards: {} < {}",
                        pid, last_period
                    ));
                }
            }
            
            // Update current period
            self.current_period = Some(pid);
            
            Some(pid)
        } else {
            None
        };

        // MUTATE only after all validations pass (atomicity)
        self.total_received += amount;
        self.last_credit_height = block_height;
        
        // Track per-period accumulation (Invariant C3)
        if let Some(pid) = period_id {
            let period_sum = self.period_received.entry(pid).or_insert(0);
            *period_sum += amount;
            self.last_recorded_period = Some(pid);
        }

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

    /// Get the allocation period (if set)
    pub fn allocation_period(&self) -> Option<EconomicPeriod> {
        self.allocation_period
    }

    /// Get the current period ID (if period-based accounting is enabled)
    pub fn current_period(&self) -> Option<u64> {
        self.current_period
    }

    /// Get the last recorded period ID (if any credits were received)
    pub fn last_recorded_period(&self) -> Option<u64> {
        self.last_recorded_period
    }

    /// Get amount received in a specific period
    /// Returns 0 if period has no records.
    pub fn period_amount(&self, period_id: u64) -> u64 {
        self.period_received.get(&period_id).copied().unwrap_or(0)
    }

    /// Get all period records (period_id -> amount)
    pub fn all_periods(&self) -> HashMap<u64, u64> {
        self.period_received.clone()
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

        let treasury = SovDaoTreasury::init(SectorDao::Healthcare, fee_collector, None).unwrap();

        assert_eq!(treasury.sector(), SectorDao::Healthcare);
        assert_eq!(treasury.total_received(), 0);
        assert_eq!(treasury.last_credit_height(), 0);
    }

    #[test]
    fn test_init_sets_fee_collector() {
        let fee_collector = create_test_public_key(1);

        let treasury = SovDaoTreasury::init(SectorDao::Education, fee_collector.clone(), None).unwrap();

        assert_eq!(treasury.authorized_fee_collector(), &fee_collector);
    }

    #[test]
    fn test_init_rejects_zero_fee_collector() {
        let zero_addr = PublicKey::new(vec![0u8; 1312]);

        let result = SovDaoTreasury::init(SectorDao::Energy, zero_addr, None);

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            let treasury = SovDaoTreasury::init(*sector, fee_collector.clone(), None).unwrap();
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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
            SovDaoTreasury::init(SectorDao::Healthcare, fee_collector.clone(), None).unwrap();

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
    // PERIOD ACCOUNTING INVARIANT TESTS (Invariants C1-C3)
    // ============================================================================

    #[test]
    fn test_invariant_c1_period_state_existence_none() {
        // Invariant C1: Explicit None, not implicit absence
        let fee_collector = create_test_public_key(1);
        let treasury = SovDaoTreasury::init(SectorDao::Healthcare, fee_collector, None).unwrap();

        assert_eq!(treasury.allocation_period(), None);
        assert_eq!(treasury.current_period(), None);
        assert_eq!(treasury.last_recorded_period(), None);
    }

    #[test]
    fn test_invariant_c1_period_state_existence_some() {
        // Invariant C1: Explicit Some with period defined
        let fee_collector = create_test_public_key(1);
        let treasury = SovDaoTreasury::init(
            SectorDao::Education,
            fee_collector,
            Some(EconomicPeriod::Monthly),
        )
        .unwrap();

        assert_eq!(treasury.allocation_period(), Some(EconomicPeriod::Monthly));
        // current_period not set until first credit
        assert_eq!(treasury.current_period(), None);
        assert_eq!(treasury.last_recorded_period(), None);
    }

    #[test]
    fn test_invariant_c1_credit_creates_period_record() {
        // Invariant C1: Every credit associates with exactly one period
        let fee_collector = create_test_public_key(1);
        let mut treasury = SovDaoTreasury::init(
            SectorDao::Energy,
            fee_collector.clone(),
            Some(EconomicPeriod::Daily),
        )
        .unwrap();

        // Credit at height 8640 (first Daily boundary)
        treasury.credit(&fee_collector, 1_000_000, 8_640).unwrap();

        // Period 1 should be recorded
        assert_eq!(treasury.last_recorded_period(), Some(1));
        assert_eq!(treasury.period_amount(1), 1_000_000);
    }

    #[test]
    fn test_invariant_c2_monotonic_period_progression() {
        // Invariant C2: Period IDs only move forward, never backward
        // Note: Period monotonicity is implicitly enforced by block height monotonicity.
        // Since period_id = block_height / period_length, if heights are strictly monotonic,
        // periods can only stay the same or increase.
        let fee_collector = create_test_public_key(1);
        let mut treasury = SovDaoTreasury::init(
            SectorDao::Healthcare,
            fee_collector.clone(),
            Some(EconomicPeriod::Daily),
        )
        .unwrap();

        // Credit in period 1 (height 8_640)
        treasury.credit(&fee_collector, 1_000_000, 8_640).unwrap();
        assert_eq!(treasury.current_period(), Some(1));
        assert_eq!(treasury.last_recorded_period(), Some(1));

        // Credit in period 2 (height 17_280)
        treasury.credit(&fee_collector, 500_000, 17_280).unwrap();
        assert_eq!(treasury.current_period(), Some(2));
        assert_eq!(treasury.last_recorded_period(), Some(2));

        // Credit in period 3 (height 25_920)
        treasury.credit(&fee_collector, 250_000, 25_920).unwrap();
        assert_eq!(treasury.current_period(), Some(3));
        assert_eq!(treasury.last_recorded_period(), Some(3));

        // Verify monotonic progression: last_recorded_period can only increase
        assert!(treasury.last_recorded_period() > Some(1));
    }

    #[test]
    fn test_invariant_c3_period_accumulation_tracking() {
        // Invariant C3: sum(period_received[period]) is final once period closes
        let fee_collector = create_test_public_key(1);
        let mut treasury = SovDaoTreasury::init(
            SectorDao::Education,
            fee_collector.clone(),
            Some(EconomicPeriod::Daily),
        )
        .unwrap();

        // Period 1 (heights 8640-17279): receive multiple credits
        treasury.credit(&fee_collector, 100_000, 8_640).unwrap();
        assert_eq!(treasury.period_amount(1), 100_000);

        treasury.credit(&fee_collector, 50_000, 9_000).unwrap();
        assert_eq!(treasury.period_amount(1), 150_000);

        treasury.credit(&fee_collector, 75_000, 10_000).unwrap();
        assert_eq!(treasury.period_amount(1), 225_000);

        // Move to period 2 (heights 17280-25919)
        treasury.credit(&fee_collector, 300_000, 17_280).unwrap();
        assert_eq!(treasury.period_amount(2), 300_000);

        // Period 1 is now closed (we've moved to period 2), verify amount is final
        assert_eq!(treasury.period_amount(1), 225_000); // unchanged
    }

    #[test]
    fn test_period_tracking_multiple_cycles() {
        // Test Invariants C1-C3 across multiple periods
        let fee_collector = create_test_public_key(1);
        let mut treasury = SovDaoTreasury::init(
            SectorDao::Housing,
            fee_collector.clone(),
            Some(EconomicPeriod::Daily),
        )
        .unwrap();

        // Period 0 (genesis)
        treasury.credit(&fee_collector, 1_000, 100).unwrap();
        assert_eq!(treasury.period_amount(0), 1_000);

        // Period 1
        treasury.credit(&fee_collector, 2_000, 8_640).unwrap();
        assert_eq!(treasury.period_amount(1), 2_000);

        // Period 2
        treasury.credit(&fee_collector, 3_000, 17_280).unwrap();
        assert_eq!(treasury.period_amount(2), 3_000);

        // Period 3
        treasury.credit(&fee_collector, 4_000, 25_920).unwrap();
        assert_eq!(treasury.period_amount(3), 4_000);

        // Verify all periods independent
        assert_eq!(treasury.total_received(), 1_000 + 2_000 + 3_000 + 4_000);
        assert_eq!(treasury.last_recorded_period(), Some(3));
    }

    #[test]
    fn test_no_period_tracking_without_allocation_period() {
        // Token without allocation_period never tracks periods
        let fee_collector = create_test_public_key(1);
        let mut treasury =
            SovDaoTreasury::init(SectorDao::Food, fee_collector.clone(), None).unwrap();

        treasury.credit(&fee_collector, 1_000_000, 8_640).unwrap();

        // No period recorded
        assert_eq!(treasury.current_period(), None);
        assert_eq!(treasury.last_recorded_period(), None);
        assert_eq!(treasury.period_amount(0), 0);

        // Total is still tracked
        assert_eq!(treasury.total_received(), 1_000_000);
    }

    #[test]
    fn test_period_and_block_height_independent() {
        // Period progression is independent of block height ordering
        let fee_collector = create_test_public_key(1);
        let mut treasury = SovDaoTreasury::init(
            SectorDao::Healthcare,
            fee_collector.clone(),
            Some(EconomicPeriod::Monthly),
        )
        .unwrap();

        // Credit at height 100_000 (in period 0)
        treasury.credit(&fee_collector, 1_000_000, 100_000).unwrap();
        assert_eq!(treasury.current_period(), Some(0));
        assert_eq!(treasury.last_credit_height(), 100_000);

        // Credit at height 300_000 (in period 1)
        treasury.credit(&fee_collector, 2_000_000, 300_000).unwrap();
        assert_eq!(treasury.current_period(), Some(1));
        assert_eq!(treasury.last_credit_height(), 300_000);

        // Block height and period both advanced monotonically
        assert_eq!(treasury.total_received(), 3_000_000);
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
