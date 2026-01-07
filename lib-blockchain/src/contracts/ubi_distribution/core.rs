use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::tokens::core::TokenContract;
use super::types::*;

/// Universal Basic Income Distribution Contract
///
/// **Roles:**
/// - Passive income for verified citizens
/// - Deterministic monthly distribution (pull-based)
/// - Governance controls schedule and funding
///
/// **NOT:**
/// - Social engineering (no eligibility enforcement)
/// - Economic policy enforcement (years are schedule indices, not KPI targets)
/// - Wealth redistribution (pure distribution from fee pool)
///
/// **Consensus-Critical Invariants:**
/// - **Identity (I1):** Citizen identified by PublicKey.key_id [u8; 32]
/// - **Uniqueness (U1):** Each key_id registered at most once
/// - **Payment (P1):** Each citizen paid at most once per month
/// - **Atomicity (A1):** Payment record written only after token.transfer succeeds
/// - **Authorization (Auth1):** Governance controls funding and schedule
/// - **Determinism (D1):** month_index = current_height / blocks_per_month (pure)
/// - **No-Panic (NP1):** All arithmetic uses checked ops; zero amounts return errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiDistributor {
    /// Governance authority (immutable at init)
    /// Only this authority can fund and set schedule
    governance_authority: PublicKey,

    /// Blocks per month (immutable at init)
    /// Used for deterministic month computation
    blocks_per_month: u64,

    /// Current available balance (in smallest token units)
    balance: u64,

    /// Total fees received (audit trail)
    total_received: u64,

    /// Total amount paid out (audit trail)
    total_paid: u64,

    /// Registered citizens (by key_id only, never full PublicKey)
    /// Invariant U1: Each key_id appears at most once
    registered: HashSet<[u8; 32]>,

    /// Payment tracking: (month_index, citizen_key_id) membership
    /// Invariant P1: Each citizen can claim at most once per month
    /// Implementation: per-month set of paid key_ids
    paid: HashMap<MonthIndex, HashSet<[u8; 32]>>,

    /// Schedule: month_index -> per-citizen amount
    /// Governance controls this; if not set, amount defaults to 0
    /// Year-by-year mapping is done via month ranges:
    /// - Year 1: months 0..=11
    /// - Year 3: months 24..=35
    /// - Year 5: months 48..=59
    schedule: HashMap<MonthIndex, u64>,
}

impl UbiDistributor {
    /// Create a new UbiDistributor with governance authority
    ///
    /// **Consensus-Critical:** governance_authority is hard-bound and immutable.
    /// blocks_per_month is fixed at initialization.
    ///
    /// # Arguments
    /// * `governance_authority` - The PublicKey authorized to set schedule and receive funds
    /// * `blocks_per_month` - Number of blocks in one month (must be > 0)
    ///
    /// # Errors
    /// - `InvalidSchedule` if blocks_per_month == 0
    pub fn new(governance_authority: PublicKey, blocks_per_month: u64) -> Result<Self, Error> {
        if blocks_per_month == 0 {
            return Err(Error::InvalidSchedule);
        }

        Ok(Self {
            governance_authority,
            blocks_per_month,
            balance: 0,
            total_received: 0,
            total_paid: 0,
            registered: HashSet::new(),
            paid: HashMap::new(),
            schedule: HashMap::new(),
        })
    }

    /// Authority enforcement helper
    ///
    /// **Consensus-Critical:** All state-mutating operations involving governance
    /// check this. This check is NOT delegable.
    fn ensure_governance(&self, caller: &PublicKey) -> Result<(), Error> {
        if caller != &self.governance_authority {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Extract key_id from PublicKey
    ///
    /// **Invariant I1:** Citizens identified by key_id only, never full PQC material
    /// Keeps contract state lean and deterministic
    fn key_id(pk: &PublicKey) -> [u8; 32] {
        pk.key_id
    }

    /// Compute month index from block height (pure, deterministic)
    ///
    /// **Invariant D1:** month_index = current_height / blocks_per_month
    /// This is deterministic and can be verified by any observer
    fn month_index(&self, current_height: u64) -> MonthIndex {
        current_height / self.blocks_per_month
    }

    /// Get amount for a specific month (defaults to 0 if not in schedule)
    fn amount_for_month(&self, month: MonthIndex) -> u64 {
        *self.schedule.get(&month).unwrap_or(&0)
    }

    // ========================================================================
    // FUNDING FLOW
    // ========================================================================

    /// Receive funds (no minting, only external transfer in)
    ///
    /// Called after upstream transfer into this contract address.
    /// Accumulates funds for distribution.
    ///
    /// # Arguments
    /// * `amount` - Amount to add to balance (must be > 0)
    ///
    /// # Errors
    /// - `ZeroAmount` if amount == 0
    /// - `Overflow` if balance would exceed u64::MAX
    pub fn receive_funds(&mut self, amount: u64) -> Result<(), Error> {
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }

        self.total_received = self.total_received
            .checked_add(amount)
            .ok_or(Error::Overflow)?;

        self.balance = self.balance
            .checked_add(amount)
            .ok_or(Error::Overflow)?;

        Ok(())
    }

    // ========================================================================
    // CITIZEN REGISTRATION (OPEN)
    // ========================================================================

    /// Register a citizen for UBI eligibility
    ///
    /// Registration is open (no gating). Anti-sybil is delegated to caller.
    ///
    /// **Invariant U1:** Each key_id can be registered at most once.
    ///
    /// # Arguments
    /// * `citizen` - PublicKey of citizen (only key_id is stored)
    ///
    /// # Errors
    /// - `AlreadyRegistered` if this key_id already registered
    pub fn register(&mut self, citizen: &PublicKey) -> Result<(), Error> {
        let id = Self::key_id(citizen);

        // HashSet::insert returns false if already present
        if !self.registered.insert(id) {
            return Err(Error::AlreadyRegistered);
        }

        Ok(())
    }

    // ========================================================================
    // SCHEDULE CONFIGURATION (GOVERNANCE-ONLY)
    // ========================================================================

    /// Set UBI amount for a specific month (governance-only)
    ///
    /// **Called by:** Governance authority only
    ///
    /// # Arguments
    /// * `caller` - Must equal governance_authority
    /// * `month` - Month index to configure
    /// * `amount` - Per-citizen amount for this month (must be > 0)
    ///
    /// # Errors
    /// - `Unauthorized` if caller is not governance_authority
    /// - `ZeroAmount` if amount == 0
    pub fn set_month_amount(
        &mut self,
        caller: &PublicKey,
        month: MonthIndex,
        amount: u64,
    ) -> Result<(), Error> {
        self.ensure_governance(caller)?;
        let _ = Amount::try_new(amount)?; // Validates non-zero

        self.schedule.insert(month, amount);
        Ok(())
    }

    /// Set UBI amount for a range of months (governance-only)
    ///
    /// **Called by:** Governance authority only
    ///
    /// Practical for configuring year spans at once:
    /// - Year 1: set_amount_range(0, 11, AMOUNT_Y1)
    /// - Year 3: set_amount_range(24, 35, AMOUNT_Y3)
    /// - Year 5: set_amount_range(48, 59, AMOUNT_Y5)
    ///
    /// # Arguments
    /// * `caller` - Must equal governance_authority
    /// * `start_month` - First month to configure (inclusive)
    /// * `end_month_inclusive` - Last month to configure (inclusive)
    /// * `amount` - Per-citizen amount for entire range (must be > 0)
    ///
    /// # Errors
    /// - `Unauthorized` if caller is not governance_authority
    /// - `ZeroAmount` if amount == 0
    /// - `InvalidSchedule` if end_month_inclusive < start_month
    pub fn set_amount_range(
        &mut self,
        caller: &PublicKey,
        start_month: MonthIndex,
        end_month_inclusive: MonthIndex,
        amount: u64,
    ) -> Result<(), Error> {
        self.ensure_governance(caller)?;
        let _ = Amount::try_new(amount)?; // Validates non-zero

        if end_month_inclusive < start_month {
            return Err(Error::InvalidSchedule);
        }

        for m in start_month..=end_month_inclusive {
            self.schedule.insert(m, amount);
        }

        Ok(())
    }

    // ========================================================================
    // CLAIMING FLOW (PULL-BASED)
    // ========================================================================

    /// Claim monthly UBI (pull-based, citizen initiates)
    ///
    /// **Called by:** Citizen or on citizen's behalf (via ExecutionContext)
    ///
    /// **Consensus-Critical (Atomicity A1):**
    /// Payment record is written only after token.transfer succeeds.
    /// Either:
    /// 1. Token transfer succeeds AND state updated, OR
    /// 2. Both fail (no partial state)
    ///
    /// **Consensus-Critical (Uniqueness U1):**
    /// Each citizen claimed at most once per month.
    ///
    /// **Consensus-Critical (Payment P1):**
    /// Payment record created only for registered citizens.
    ///
    /// **Capability-Bound Authorization:**
    /// Token transfer source is derived from ctx.call_origin:
    /// - User calls: debit from ctx.caller
    /// - Contract calls: debit from ctx.contract (this UBI contract address)
    ///
    /// # Arguments
    /// * `citizen` - PublicKey of claiming citizen (only key_id used)
    /// * `current_height` - Block height (for month computation)
    /// * `token` - Token contract (mutable) to perform transfer
    /// * `ctx` - Execution context providing authorization and contract address
    ///
    /// # Errors
    /// - `NotRegistered` if citizen not registered
    /// - `ZeroAmount` if no amount scheduled for this month
    /// - `AlreadyPaidThisMonth` if citizen already claimed this month
    /// - `InsufficientFunds` if balance < amount
    /// - `TokenTransferFailed` if token transfer fails
    /// - `Overflow` if balance underflow (should not happen if logic correct)
    pub fn claim_ubi(
        &mut self,
        citizen: &PublicKey,
        current_height: u64,
        token: &mut TokenContract,
        ctx: &crate::contracts::executor::ExecutionContext,
    ) -> Result<(), Error> {
        let id = Self::key_id(citizen);

        // Invariant U1: Must be registered
        if !self.registered.contains(&id) {
            return Err(Error::NotRegistered);
        }

        // Deterministic month computation (Invariant D1)
        let month = self.month_index(current_height);

        // Get amount for this month (defaults to 0 if not in schedule)
        let amount = self.amount_for_month(month);
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }

        // Invariant P1: Check not already paid this month
        let month_set = self.paid.entry(month).or_insert_with(HashSet::new);
        if month_set.contains(&id) {
            return Err(Error::AlreadyPaidThisMonth);
        }

        // Invariant A2: Balance check before transfer
        if self.balance < amount {
            return Err(Error::InsufficientFunds);
        }

        // ====================================================================
        // ATOMIC TRANSFER PHASE - Token transfer must succeed first
        // Capability-bound: source is derived from ctx, not from parameter
        // ====================================================================
        let _burned = token
            .transfer(ctx, citizen, amount)
            .map_err(|_| Error::TokenTransferFailed)?;

        // ====================================================================
        // STATE MUTATION PHASE - Only after successful token transfer
        // ====================================================================

        // Update balance
        self.balance = self.balance
            .checked_sub(amount)
            .ok_or(Error::Overflow)?;

        // Update total paid
        self.total_paid = self.total_paid
            .checked_add(amount)
            .ok_or(Error::Overflow)?;

        // Mark as paid this month (Invariant P1)
        month_set.insert(id);

        Ok(())
    }

    // ========================================================================
    // VIEWS (READ-ONLY)
    // ========================================================================

    /// Get current available balance
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Get total funds received (audit trail)
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Get total funds paid out (audit trail)
    pub fn total_paid(&self) -> u64 {
        self.total_paid
    }

    /// Get number of registered citizens
    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }

    /// Get number of citizens paid in a specific month
    pub fn month_paid_count(&self, month: MonthIndex) -> usize {
        self.paid.get(&month).map(|s| s.len()).unwrap_or(0)
    }

    /// Get amount for a specific month
    pub fn amount_for(&self, month: MonthIndex) -> u64 {
        self.amount_for_month(month)
    }

    /// Get blocks per month (fixed at initialization)
    pub fn blocks_per_month(&self) -> u64 {
        self.blocks_per_month
    }
}

impl Default for UbiDistributor {
    fn default() -> Self {
        // Default to zero-authority for testing only
        // Production must always call new() with valid governance authority
        Self::new(
            PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            1000,
        )
        .expect("default construction failed")
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::executor::{ExecutionContext, CallOrigin};

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id],
            kyber_pk: vec![id],
            key_id: [id; 32],
        }
    }

    fn test_governance() -> PublicKey {
        test_public_key(99)
    }

    fn test_citizen(id: u8) -> PublicKey {
        test_public_key(id)
    }

    fn test_execution_context_for_contract(contract_address: &PublicKey) -> ExecutionContext {
        ExecutionContext::with_contract(
            test_governance().clone(),  // caller
            contract_address.clone(),   // contract address
            1,                          // block_number
            1000,                       // timestamp
            100000,                     // gas_limit
            [1u8; 32],                  // tx_hash
        )
    }

    #[test]
    fn test_new_contract_initialized() {
        let gov = test_governance();
        let ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        assert_eq!(ubi.balance(), 0);
        assert_eq!(ubi.total_received(), 0);
        assert_eq!(ubi.total_paid(), 0);
        assert_eq!(ubi.registered_count(), 0);
        assert_eq!(ubi.blocks_per_month(), 1000);
    }

    #[test]
    fn test_new_contract_blocks_per_month_zero_fails() {
        let gov = test_governance();
        let result = UbiDistributor::new(gov.clone(), 0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidSchedule);
    }

    #[test]
    fn test_receive_funds_success() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.receive_funds(1000);
        assert!(result.is_ok());
        assert_eq!(ubi.balance(), 1000);
        assert_eq!(ubi.total_received(), 1000);
    }

    #[test]
    fn test_receive_funds_zero_fails() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.receive_funds(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_register_success() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.register(&citizen);
        assert!(result.is_ok());
        assert_eq!(ubi.registered_count(), 1);
    }

    #[test]
    fn test_register_duplicate_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("first registration failed");
        let result = ubi.register(&citizen);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::AlreadyRegistered);
    }

    #[test]
    fn test_set_month_amount_success() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.set_month_amount(&gov, 0, 500);
        assert!(result.is_ok());
        assert_eq!(ubi.amount_for(0), 500);
    }

    #[test]
    fn test_set_month_amount_unauthorized_fails() {
        let gov = test_governance();
        let wrong_gov = test_public_key(88);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.set_month_amount(&wrong_gov, 0, 500);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Unauthorized);
    }

    #[test]
    fn test_set_month_amount_zero_fails() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.set_month_amount(&gov, 0, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_set_amount_range_success() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.set_amount_range(&gov, 0, 11, 450);
        assert!(result.is_ok());

        // Verify all months in range have the amount
        for month in 0..=11 {
            assert_eq!(ubi.amount_for(month), 450);
        }
        // Verify month outside range is 0
        assert_eq!(ubi.amount_for(12), 0);
    }

    #[test]
    fn test_set_amount_range_invalid_order_fails() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.set_amount_range(&gov, 11, 0, 450);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InvalidSchedule);
    }

    #[test]
    fn test_claim_ubi_not_registered_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.receive_funds(1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::NotRegistered);
    }

    #[test]
    fn test_claim_ubi_zero_schedule_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(1000).expect("fund failed");
        // Note: don't set amount for month 0 (defaults to 0)

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_claim_ubi_success() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);

        assert!(result.is_ok());
        assert_eq!(ubi.balance(), 900);
        assert_eq!(ubi.total_paid(), 100);
        assert_eq!(ubi.month_paid_count(0), 1);
    }

    #[test]
    fn test_claim_ubi_already_paid_this_month_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(2000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // First claim succeeds
        ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx)
            .expect("first claim failed");

        // Second claim same month fails
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::AlreadyPaidThisMonth);
    }

    #[test]
    fn test_claim_ubi_next_month_succeeds() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let blocks_per_month = 1000;
        let mut ubi = UbiDistributor::new(gov.clone(), blocks_per_month).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(2000).expect("fund failed");
        ubi.set_amount_range(&gov, 0, 2, 100).expect("set_amount_range failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // Claim in month 0 (height 100)
        ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx)
            .expect("claim month 0 failed");
        assert_eq!(ubi.month_paid_count(0), 1);

        // Claim in month 1 (height 1100)
        let result = ubi.claim_ubi(&citizen, 1100, &mut mock_token, &ctx);
        assert!(result.is_ok());
        assert_eq!(ubi.month_paid_count(1), 1);
        assert_eq!(ubi.total_paid(), 200);
    }

    #[test]
    fn test_claim_ubi_insufficient_funds_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(50).expect("fund failed"); // Only 50, but trying to pay 100
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InsufficientFunds);
    }

    #[test]
    fn test_claim_ubi_transfer_failure_does_not_mark_paid() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        // Use a token with insufficient balance to simulate transfer failure
        let mut mock_token = create_mock_token_with_insufficient_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);

        // Transfer failed (insufficient balance in token), so claim should fail
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::TokenTransferFailed);

        // Balance and paid count should not change (atomicity preserved)
        assert_eq!(ubi.balance(), 1000);
        assert_eq!(ubi.total_paid(), 0);
        assert_eq!(ubi.month_paid_count(0), 0);
    }

    #[test]
    fn test_month_index_calculation() {
        let gov = test_governance();
        let ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        // blocks_per_month = 1000
        assert_eq!(ubi.month_index(0), 0);    // height 0
        assert_eq!(ubi.month_index(999), 0);  // height 999
        assert_eq!(ubi.month_index(1000), 1); // height 1000 (start of month 1)
        assert_eq!(ubi.month_index(1999), 1); // height 1999
        assert_eq!(ubi.month_index(2000), 2); // height 2000 (start of month 2)
    }

    #[test]
    fn test_multiple_citizens_same_month() {
        let gov = test_governance();
        let citizen1 = test_citizen(1);
        let citizen2 = test_citizen(2);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen1).expect("register citizen1 failed");
        ubi.register(&citizen2).expect("register citizen2 failed");
        ubi.receive_funds(2000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // Both citizens claim in same month
        ubi.claim_ubi(&citizen1, 100, &mut mock_token, &ctx)
            .expect("citizen1 claim failed");
        ubi.claim_ubi(&citizen2, 100, &mut mock_token, &ctx)
            .expect("citizen2 claim failed");

        assert_eq!(ubi.month_paid_count(0), 2);
        assert_eq!(ubi.total_paid(), 200);
        assert_eq!(ubi.balance(), 1800);
    }

    #[test]
    fn test_receive_funds_overflow_protection() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        // Simulate large amount close to u64::MAX
        ubi.receive_funds(u64::MAX - 100).expect("first receive failed");

        // Try to add 200 more (should overflow)
        let result = ubi.receive_funds(200);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Overflow);
    }

    #[test]
    fn test_total_paid_overflow_protection() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");

        // Simulate very large balance and total_paid
        ubi.balance = 200;  // Enough for one transfer
        ubi.total_received = 200;
        ubi.total_paid = u64::MAX - 100;  // Already very large

        ubi.set_month_amount(&gov, 0, 200).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // This should fail due to total_paid overflow when adding 200
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Overflow);
    }

    // Helper: create a mock TokenContract that succeeds
    fn create_mock_token_with_balance(contract_address: &PublicKey) -> TokenContract {
        use crate::contracts::utils::generate_lib_token_id;

        let creator = test_public_key(100);
        let mut token = TokenContract::new(
            generate_lib_token_id(),
            "Test Token".to_string(),
            "TTK".to_string(),
            8,
            u64::MAX,
            false,
            0,
            creator.clone(),
        );

        // Mint a large balance to the contract address for transfers
        let _ = token.mint(contract_address, u64::MAX / 2);
        token
    }

    // Helper: create a mock TokenContract with minimal balance (for failure testing)
    fn create_mock_token_with_insufficient_balance(contract_address: &PublicKey) -> TokenContract {
        use crate::contracts::utils::generate_lib_token_id;

        let creator = test_public_key(100);
        let mut token = TokenContract::new(
            generate_lib_token_id(),
            "Test Token".to_string(),
            "TTK".to_string(),
            8,
            u64::MAX,
            false,
            0,
            creator.clone(),
        );

        // Mint tiny balance to contract address - not enough for transfers
        let _ = token.mint(contract_address, 10);
        token
    }
}
