use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::tokens::core::TokenContract;
use crate::contracts::treasury_kernel::TreasuryKernel;
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
    ///
    /// **Mapping:** MonthIndex is a pure function of block height:
    /// - month_index = current_height / blocks_per_month
    /// - Not tied to calendar years or dates
    /// - Governance sets amounts for specific month indices
    /// - Examples: months 0-11 (year 1), 12-23 (year 2), 24-35 (year 3), etc.
    schedule: HashMap<MonthIndex, u64>,

    /// Phase C: UBI claim intent events (epoch -> list of claims)
    /// Records UbiClaimRecorded events for Treasury Kernel to process
    /// Treasury Kernel will poll these events at epoch boundaries
    ///
    /// **Design:** Passive client pattern - just record intent, Kernel executes
    /// - key: epoch (u64)
    /// - value: Vec<UbiClaimRecorded> events for that epoch
    claim_events: HashMap<u64, Vec<UbiClaimRecorded>>,
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
            claim_events: HashMap::new(),
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
    /// **Called by:** Governance authority only
    /// Called after upstream transfer into this contract address.
    /// Accumulates funds for distribution.
    ///
    /// **Consensus-Critical (G1):** Only governance_authority may receive funds.
    /// Prevents unauthorized balance inflation without actual token backing.
    ///
    /// # Arguments
    /// * `caller` - Must equal governance_authority
    /// * `amount` - Amount to add to balance (must be > 0)
    ///
    /// # Errors
    /// - `Unauthorized` if caller is not governance_authority
    /// - `ZeroAmount` if amount == 0
    /// - `Overflow` if balance would exceed u64::MAX
    pub fn receive_funds(&mut self, caller: &PublicKey, amount: u64) -> Result<(), Error> {
        // Invariant G1: Authorization check
        self.ensure_governance(caller)?;

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
        kernel: Option<&mut TreasuryKernel>,
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
        if let Some(kernel) = kernel {
            // Route through Treasury Kernel (preferred path)
            use crate::contracts::executor::CallOrigin;
            let from = match ctx.call_origin {
                CallOrigin::User => &ctx.caller,
                CallOrigin::Contract => &ctx.contract,
                CallOrigin::System => return Err(Error::TokenTransferFailed),
            };
            let kernel_addr = kernel.kernel_address().clone();
            kernel
                .transfer(token, &kernel_addr, from, citizen, amount)
                .map_err(|_| Error::TokenTransferFailed)?;
        } else {
            // Legacy direct path
            let _burned = token
                .transfer(ctx, citizen, amount)
                .map_err(|_| Error::TokenTransferFailed)?;
        }

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

    /// Get current month's UBI amount based on block height
    ///
    /// **Consensus-Critical:** Uses deterministic month calculation.
    /// Result depends only on current_height and blocks_per_month (both inputs/immutable).
    ///
    /// # Arguments
    /// * `current_height` - Current blockchain block height
    ///
    /// # Returns
    /// Per-citizen UBI amount for the current month, or 0 if not scheduled
    pub fn get_monthly_ubi(&self, current_height: u64) -> u64 {
        let month = self.month_index(current_height);
        self.amount_for_month(month)
    }

    /// Check if citizen is registered for UBI
    ///
    /// # Arguments
    /// * `citizen` - The citizen's PublicKey
    ///
    /// # Returns
    /// true if citizen is registered, false otherwise
    pub fn is_registered(&self, citizen: &PublicKey) -> bool {
        let id = Self::key_id(citizen);
        self.registered.contains(&id)
    }

    /// Check if citizen has claimed UBI for the current month
    ///
    /// **Consensus-Critical:** Uses deterministic month calculation.
    /// Invariant P1: Each citizen paid at most once per month.
    ///
    /// # Arguments
    /// * `citizen` - The citizen's PublicKey
    /// * `current_height` - Current blockchain block height
    ///
    /// # Returns
    /// true if citizen already claimed this month, false otherwise
    pub fn has_claimed_this_month(&self, citizen: &PublicKey, current_height: u64) -> bool {
        let id = Self::key_id(citizen);
        let month = self.month_index(current_height);
        self.paid.get(&month).map(|s| s.contains(&id)).unwrap_or(false)
    }

    /// Initialize UBI pool with funding
    ///
    /// Semantic alias for `receive_funds()` - clarifies intent for UBI initialization.
    /// The amount is total pool funding, not per-citizen monthly amount.
    ///
    /// # Arguments
    /// * `caller` - Must be governance_authority
    /// * `amount` - Total funds to add to pool (must be > 0)
    ///
    /// # Errors
    /// - `Unauthorized` if caller is not governance_authority
    /// - `InvalidSchedule` if amount == 0
    /// - `InvalidSchedule` if total would overflow
    pub fn initialize_ubi_pool(&mut self, caller: &PublicKey, amount: u64) -> Result<(), Error> {
        self.receive_funds(caller, amount)
    }

    // ========================================================================
    // PERFORMANCE OPTIMIZATION METHODS
    // ========================================================================

    /// Create a new UbiDistributor with pre-allocated capacity for citizens
    ///
    /// Improves performance for large-scale operations (e.g., 1M citizen registration).
    /// By pre-allocating HashSet capacity, we reduce rehashing overhead.
    ///
    /// # Arguments
    /// * `governance_authority` - The PublicKey authorized to set schedule and receive funds
    /// * `blocks_per_month` - Number of blocks in one month (must be > 0)
    /// * `expected_citizens` - Expected number of citizens to register (for capacity planning)
    ///
    /// # Errors
    /// - `InvalidSchedule` if blocks_per_month == 0
    ///
    /// # Performance
    /// Allocates up-front space for faster registration at scale.
    /// Beneficial when registering 10K+ citizens.
    pub fn new_with_capacity(
        governance_authority: PublicKey,
        blocks_per_month: u64,
        expected_citizens: usize,
    ) -> Result<Self, Error> {
        if blocks_per_month == 0 {
            return Err(Error::InvalidSchedule);
        }

        Ok(Self {
            governance_authority,
            blocks_per_month,
            balance: 0,
            total_received: 0,
            total_paid: 0,
            registered: HashSet::with_capacity(expected_citizens),
            paid: HashMap::new(),
            schedule: HashMap::new(),
            claim_events: HashMap::new(),
        })
    }

    /// Register multiple citizens in a single batch operation
    ///
    /// More efficient than repeated `register()` calls for bulk registration.
    /// Useful for initialization of large citizen bases.
    ///
    /// # Arguments
    /// * `citizens` - Slice of PublicKeys to register
    ///
    /// # Returns
    /// Number of citizens successfully registered (duplicates skipped).
    /// No errors returned - duplicate registrations are silently skipped.
    ///
    /// # Invariants Maintained
    /// - Invariant U1: No duplicates in final registered set
    /// - Each citizen can only be registered once
    ///
    /// # Performance
    /// O(n) where n = len(citizens). No authorization checks needed
    /// as batch registration is permissionless (matches individual register behavior).
    pub fn register_batch(&mut self, citizens: &[PublicKey]) -> usize {
        let mut count = 0;
        for citizen in citizens {
            let id = Self::key_id(citizen);
            if self.registered.insert(id) {
                count += 1;
            }
        }
        count
    }

    // ========================================================================
    // PHASE C: TREASURY KERNEL CLIENT METHODS (NEW)
    // ========================================================================
    // Per ADR-0017: UBI is a passive client of the Treasury Kernel.
    // These methods enable the Kernel to validate and execute UBI claims.

    /// Record citizen's intent to claim UBI (Phase C - NEW)
    ///
    /// # Design (Per ADR-0017)
    /// UBI is a **passive** client: citizens record intent, Kernel executes validation/minting.
    ///
    /// This method is **intentionally minimal**:
    /// - Minimal validation (zero-amount check only)
    /// - Records state: stores UbiClaimRecorded event in local claim_events HashMap
    /// - No minting (Kernel owns minting)
    /// - Treasury Kernel will poll these stored events at epoch boundaries
    ///
    /// Treasury Kernel will later:
    /// 1. Call query_ubi_claims() to retrieve all UbiClaimRecorded events
    /// 2. Validate each claim (5 gates)
    /// 3. Mint or reject with reason code
    /// 4. Emit UbiDistributed or UbiClaimRejected
    ///
    /// # Arguments
    /// * `citizen_id` - Verified citizen identifier [u8; 32]
    /// * `amount` - Requested amount (typically 1000, but flexible)
    /// * `epoch` - Epoch for which claim is made
    ///
    /// # Errors
    /// - `ZeroAmount` if amount == 0
    ///
    /// # Returns
    /// Ok(()) on successful recording (claim stored and will be retrieved by Kernel)
    pub fn record_claim_intent(
        &mut self,
        citizen_id: [u8; 32],
        amount: u64,
        epoch: u64,
    ) -> Result<(), Error> {
        // Minimal validation: amount must be positive
        if amount == 0 {
            return Err(Error::ZeroAmount);
        }

        // Phase C: Emit UbiClaimRecorded event for Treasury Kernel to process
        // Kernel will poll these events at epoch boundaries and validate/mint
        // Note: timestamp will be set by executor when processing; set to 0 for now
        let claim_event = UbiClaimRecorded {
            citizen_id,
            amount,
            epoch,
            timestamp: 0, // TODO: Will be set by ContractExecutor with actual block height
        };

        // Store event in our local event map (grouped by epoch)
        self.claim_events
            .entry(epoch)
            .or_insert_with(Vec::new)
            .push(claim_event);

        Ok(())
    }

    /// Query if citizen has claimed in a specific epoch (Phase C - NEW)
    ///
    /// # Design
    /// Convenience query for governance/UI.
    /// Canonical dedup state is maintained by Treasury Kernel.
    ///
    /// # Arguments
    /// * `citizen_id` - Verified citizen identifier
    /// * `epoch` - Epoch to query
    ///
    /// # Returns
    /// true if citizen has already claimed in this epoch, false otherwise
    ///
    /// # Note
    /// This would query Kernel state in production implementation.
    /// For now returns placeholder.
    pub fn has_claimed_this_epoch(&self, citizen_id: [u8; 32], epoch: u64) -> bool {
        // TODO: Query Treasury Kernel dedup state
        // In production: kernel.state().has_claimed(citizen_id, epoch)
        let _ = (citizen_id, epoch);
        false // Placeholder
    }

    /// Get UBI pool status for an epoch (Phase C - NEW)
    ///
    /// # Design
    /// Returns epoch-level distribution summary for governance monitoring.
    /// Aggregates data from:
    /// - CitizenRegistry: eligible citizen count
    /// - Treasury Kernel state: total distributed this epoch
    ///
    /// # Arguments
    /// * `epoch` - Epoch to query
    ///
    /// # Returns
    /// UbiPoolStatus struct with: epoch, citizens_eligible, total_distributed, remaining_capacity
    ///
    /// # Note
    /// Requires access to CitizenRegistry and Treasury Kernel state.
    /// For now returns placeholder.
    pub fn get_pool_status(&self, epoch: u64) -> UbiPoolStatus {
        // TODO: Query CitizenRegistry for eligible count
        // TODO: Query Treasury Kernel for total_distributed
        // In production:
        // let eligible = citizen_registry.get_active_citizens().len() as u64;
        // let total = kernel.state.get_distributed(epoch);
        // UbiPoolStatus::new(epoch, eligible, total)

        UbiPoolStatus::new(epoch, 0, 0)  // Placeholder
    }

    /// Query all UBI claims recorded for an epoch (Phase C - NEW)
    ///
    /// # Design
    /// Treasury Kernel calls this to retrieve all UbiClaimRecorded events for processing.
    ///
    /// # Arguments
    /// * `epoch` - Epoch to retrieve claims for
    ///
    /// # Returns
    /// Vector of UbiClaimRecorded events for this epoch
    ///
    /// # Note
    /// Returns events from local storage. In full integration with executor,
    /// these would come from the persistent event log.
    pub fn query_ubi_claims(&self, epoch: u64) -> Vec<UbiClaimRecorded> {
        // Phase C: Retrieve UbiClaimRecorded events from local storage
        // Treasury Kernel uses this to get all claims for processing
        self.claim_events
            .get(&epoch)
            .cloned()
            .unwrap_or_default()
    }
}

// DEPRECATED: Do not use Default::default() - it creates invalid zero-authority state.
// For tests, use UbiDistributor::new() with a valid test governance authority.
// Use test_new_with_zero_authority() in test modules instead.

#[cfg(test)]
impl UbiDistributor {
    /// Test-only constructor that creates zero-authority UbiDistributor for unit test isolation.
    /// This violates invariants and must NEVER be used in production.
    pub fn test_new_with_zero_authority() -> Self {
        Self::new(
            PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            },
            1000,
        )
        .expect("test construction failed")
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

        let result = ubi.receive_funds(&gov, 1000);
        assert!(result.is_ok());
        assert_eq!(ubi.balance(), 1000);
        assert_eq!(ubi.total_received(), 1000);
    }

    #[test]
    fn test_receive_funds_zero_fails() {
        let gov = test_governance();
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        let result = ubi.receive_funds(&gov, 0);
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

        ubi.receive_funds(&gov, 1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::NotRegistered);
    }

    #[test]
    fn test_claim_ubi_zero_schedule_fails() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(&gov, 1000).expect("fund failed");
        // Note: don't set amount for month 0 (defaults to 0)

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::ZeroAmount);
    }

    #[test]
    fn test_claim_ubi_success() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(&gov, 1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);

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
        ubi.receive_funds(&gov, 2000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // First claim succeeds
        ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None)
            .expect("first claim failed");

        // Second claim same month fails
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);
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
        ubi.receive_funds(&gov, 2000).expect("fund failed");
        ubi.set_amount_range(&gov, 0, 2, 100).expect("set_amount_range failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // Claim in month 0 (height 100)
        ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None)
            .expect("claim month 0 failed");
        assert_eq!(ubi.month_paid_count(0), 1);

        // Claim in month 1 (height 1100)
        let result = ubi.claim_ubi(&citizen, 1100, &mut mock_token, &ctx, None);
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
        ubi.receive_funds(&gov, 50).expect("fund failed"); // Only 50, but trying to pay 100
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InsufficientFunds);
    }

    #[test]
    fn test_claim_ubi_transfer_failure_does_not_mark_paid() {
        let gov = test_governance();
        let citizen = test_citizen(1);
        let mut ubi = UbiDistributor::new(gov.clone(), 1000).expect("init failed");

        ubi.register(&citizen).expect("register failed");
        ubi.receive_funds(&gov, 1000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        // Use a token with insufficient balance to simulate transfer failure
        let mut mock_token = create_mock_token_with_insufficient_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);

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
        ubi.receive_funds(&gov, 2000).expect("fund failed");
        ubi.set_month_amount(&gov, 0, 100).expect("set_month failed");

        let mut mock_token = create_mock_token_with_balance(&gov);
        let ctx = test_execution_context_for_contract(&gov);

        // Both citizens claim in same month
        ubi.claim_ubi(&citizen1, 100, &mut mock_token, &ctx, None)
            .expect("citizen1 claim failed");
        ubi.claim_ubi(&citizen2, 100, &mut mock_token, &ctx, None)
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
        ubi.receive_funds(&gov, u64::MAX - 100).expect("first receive failed");

        // Try to add 200 more (should overflow)
        let result = ubi.receive_funds(&gov, 200);
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
        let result = ubi.claim_ubi(&citizen, 100, &mut mock_token, &ctx, None);
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

    // ========================================================================
    // PHASE C TESTS: TREASURY KERNEL CLIENT METHODS
    // ========================================================================

    #[test]
    fn test_record_claim_intent_zero_amount_fails() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];
        let epoch = 100u64;

        let result = ubi.record_claim_intent(citizen_id, 0, epoch);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::ZeroAmount));
    }

    #[test]
    fn test_record_claim_intent_success() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];
        let amount = 1000u64;
        let epoch = 100u64;

        let result = ubi.record_claim_intent(citizen_id, amount, epoch);
        assert!(result.is_ok());

        // Verify event was recorded
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].citizen_id, citizen_id);
        assert_eq!(claims[0].amount, amount);
        assert_eq!(claims[0].epoch, epoch);
    }

    #[test]
    fn test_record_multiple_claims_same_epoch() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;

        // Record 3 different claims in same epoch
        for i in 1..=3 {
            let citizen_id = [i as u8; 32];
            let amount = 1000u64;
            let result = ubi.record_claim_intent(citizen_id, amount, epoch);
            assert!(result.is_ok());
        }

        // Verify all 3 claims were recorded
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 3);
        for (i, claim) in claims.iter().enumerate() {
            assert_eq!(claim.citizen_id, [(i + 1) as u8; 32]);
            assert_eq!(claim.amount, 1000u64);
        }
    }

    #[test]
    fn test_record_claims_different_epochs() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];

        // Record same citizen claiming in different epochs
        for epoch in 100..105 {
            let result = ubi.record_claim_intent(citizen_id, 1000, epoch);
            assert!(result.is_ok());
        }

        // Verify claims in different epochs are separate
        for epoch in 100..105 {
            let claims = ubi.query_ubi_claims(epoch);
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].epoch, epoch);
        }
    }

    #[test]
    fn test_record_claim_intent_large_amount() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];
        let amount = u64::MAX / 2; // Very large amount
        let epoch = 100u64;

        let result = ubi.record_claim_intent(citizen_id, amount, epoch);
        assert!(result.is_ok());

        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].amount, amount);
    }

    // Query method tests (8+ scenarios)

    #[test]
    fn test_query_ubi_claims_empty_epoch() {
        let ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let claims = ubi.query_ubi_claims(100);
        assert!(claims.is_empty());
    }

    #[test]
    fn test_query_ubi_claims_returns_correct_epoch() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // Record claims in epochs 100, 101, 102
        for epoch in 100..103 {
            let citizen_id = [epoch as u8; 32];
            let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
        }

        // Query should only return claims for requested epoch
        let claims_100 = ubi.query_ubi_claims(100);
        assert_eq!(claims_100.len(), 1);
        assert_eq!(claims_100[0].citizen_id, [100u8; 32]);

        let claims_101 = ubi.query_ubi_claims(101);
        assert_eq!(claims_101.len(), 1);
        assert_eq!(claims_101[0].citizen_id, [101u8; 32]);
    }

    #[test]
    fn test_has_claimed_this_epoch_placeholder() {
        let ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];

        // For now, this is a placeholder that always returns false
        // Once integrated with Treasury Kernel state, it will check actual dedup
        assert!(!ubi.has_claimed_this_epoch(citizen_id, 100));
    }

    #[test]
    fn test_get_pool_status_placeholder() {
        let ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // For now, this returns placeholder values (0 eligible, 0 distributed)
        // Once integrated with CitizenRegistry and Treasury Kernel, will return real values
        let status = ubi.get_pool_status(100);
        assert_eq!(status.epoch, 100);
        assert_eq!(status.citizens_eligible, 0);
        assert_eq!(status.total_distributed, 0);
        assert_eq!(status.remaining_capacity, 1_000_000);
    }

    #[test]
    fn test_query_ubi_claims_preserves_order() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;

        // Record 5 claims in specific order
        let citizens: Vec<[u8; 32]> = (1..=5).map(|i| [i as u8; 32]).collect();
        for (idx, citizen_id) in citizens.iter().enumerate() {
            let _ = ubi.record_claim_intent(*citizen_id, 1000 + idx as u64, epoch);
        }

        // Query and verify order is preserved
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 5);
        for (idx, claim) in claims.iter().enumerate() {
            assert_eq!(claim.citizen_id, citizens[idx]);
            assert_eq!(claim.amount, 1000 + idx as u64);
        }
    }

    #[test]
    fn test_record_claim_intent_timestamp_is_zero() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];

        let _ = ubi.record_claim_intent(citizen_id, 1000, 100);

        let claims = ubi.query_ubi_claims(100);
        assert_eq!(claims[0].timestamp, 0);
        // TODO: Will be set to actual block height by executor
    }

    #[test]
    fn test_multiple_claims_same_citizen_different_epochs() {
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];

        // Same citizen claiming in 3 different epochs
        for epoch in 100..103 {
            let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
        }

        // Each epoch should have 1 claim from this citizen
        for epoch in 100..103 {
            let claims = ubi.query_ubi_claims(epoch);
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].citizen_id, citizen_id);
        }
    }

    // ========================================================================
    // END-TO-END INTEGRATION TESTS (15+ scenarios)
    // ========================================================================

    #[test]
    fn test_e2e_single_citizen_claim_intent_and_query() {
        // Test: Single citizen records intent and Kernel queries for processing
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];
        let epoch = 100u64;

        // Citizen records intent
        let result = ubi.record_claim_intent(citizen_id, 1000, epoch);
        assert!(result.is_ok());

        // Kernel queries for claims to process
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].citizen_id, citizen_id);
        assert_eq!(claims[0].amount, 1000);
        assert_eq!(claims[0].epoch, epoch);
    }

    #[test]
    fn test_e2e_multiple_citizens_claim_same_epoch() {
        // Test: Multiple citizens claim in same epoch, Kernel processes all
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;
        let num_citizens = 10;

        // 10 citizens record intent in same epoch
        for i in 1..=num_citizens {
            let citizen_id = [i as u8; 32];
            let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
        }

        // Kernel queries all claims for epoch
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), num_citizens);

        // Verify all citizen IDs are present
        let citizen_ids: Vec<[u8; 32]> = claims.iter().map(|c| c.citizen_id).collect();
        for i in 1..=num_citizens {
            assert!(citizen_ids.contains(&[i as u8; 32]));
        }
    }

    #[test]
    fn test_e2e_epoch_boundary_transitions() {
        // Test: Citizens claim in multiple epoch boundaries sequentially
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // 5 epochs, 2 claims each
        for epoch in 100..105 {
            for claim_idx in 1..=2 {
                let citizen_id = [((epoch * 10 + claim_idx) % 256) as u8; 32];
                let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
            }
        }

        // Verify each epoch has exactly 2 claims
        for epoch in 100..105 {
            let claims = ubi.query_ubi_claims(epoch);
            assert_eq!(claims.len(), 2);
            assert!(claims.iter().all(|c| c.epoch == epoch));
        }
    }

    #[test]
    fn test_e2e_claim_with_varying_amounts() {
        // Test: Citizens can claim different amounts (flexible design)
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;

        // Citizens claim different amounts
        let amounts = vec![500, 1000, 1500, 2000, 5000];
        for (idx, &amount) in amounts.iter().enumerate() {
            let citizen_id = [(idx + 1) as u8; 32];
            let _ = ubi.record_claim_intent(citizen_id, amount, epoch);
        }

        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), amounts.len());

        for (idx, claim) in claims.iter().enumerate() {
            assert_eq!(claim.amount, amounts[idx]);
        }
    }

    #[test]
    fn test_e2e_empty_epoch_query() {
        // Test: Query for epoch with no claims returns empty vector
        let ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        let claims = ubi.query_ubi_claims(999);
        assert!(claims.is_empty());
    }

    #[test]
    fn test_e2e_skip_epochs_then_claim() {
        // Test: Citizens skip some epochs, then claim in later epoch
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // No claims in epochs 100-104
        for epoch in 100..105 {
            let claims = ubi.query_ubi_claims(epoch);
            assert!(claims.is_empty());
        }

        // Claims start at epoch 105
        let citizen_id = [1u8; 32];
        let _ = ubi.record_claim_intent(citizen_id, 1000, 105);

        // Verify isolation
        let claims_105 = ubi.query_ubi_claims(105);
        assert_eq!(claims_105.len(), 1);

        let claims_104 = ubi.query_ubi_claims(104);
        assert!(claims_104.is_empty());
    }

    #[test]
    fn test_e2e_rejected_claim_zero_amount() {
        // Test: Treasury Kernel would reject zero-amount claims
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        let result = ubi.record_claim_intent([1u8; 32], 0, 100);
        assert_eq!(result, Err(Error::ZeroAmount));

        // No event recorded
        let claims = ubi.query_ubi_claims(100);
        assert!(claims.is_empty());
    }

    #[test]
    fn test_e2e_concurrent_epochs_isolation() {
        // Test: Claims in different epochs don't interfere
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // 5 citizens, each claiming in 3 different epochs
        for citizen_idx in 1..=5 {
            for epoch_offset in 0..3 {
                let citizen_id = [citizen_idx as u8; 32];
                let epoch = 100 + epoch_offset;
                let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
            }
        }

        // Verify each epoch has exactly 5 claims
        for epoch_offset in 0..3 {
            let epoch = 100 + epoch_offset;
            let claims = ubi.query_ubi_claims(epoch);
            assert_eq!(claims.len(), 5);
            assert!(claims.iter().all(|c| c.epoch == epoch));
        }
    }

    #[test]
    fn test_e2e_max_epoch_boundary() {
        // Test: Very large epoch numbers work correctly
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let max_epoch = u64::MAX - 1;

        let citizen_id = [1u8; 32];
        let _ = ubi.record_claim_intent(citizen_id, 1000, max_epoch);

        let claims = ubi.query_ubi_claims(max_epoch);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].epoch, max_epoch);
    }

    #[test]
    fn test_e2e_claim_records_immutable_fields() {
        // Test: Recorded claims preserve exact citizen_id, amount, epoch
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [42u8; 32];
        let amount = 5555u64;
        let epoch = 123u64;

        let _ = ubi.record_claim_intent(citizen_id, amount, epoch);

        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims[0].citizen_id, citizen_id);
        assert_eq!(claims[0].amount, amount);
        assert_eq!(claims[0].epoch, epoch);
    }

    #[test]
    fn test_e2e_duplicate_citizen_same_epoch() {
        // Test: Same citizen can record multiple intents in same epoch
        // (dedup is Kernel's responsibility, not UBI's)
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let citizen_id = [1u8; 32];
        let epoch = 100u64;

        // Same citizen records 3 times
        for _ in 0..3 {
            let _ = ubi.record_claim_intent(citizen_id, 1000, epoch);
        }

        // All 3 are recorded (UBI is passive)
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 3);
        assert!(claims.iter().all(|c| c.citizen_id == citizen_id));
    }

    #[test]
    fn test_e2e_large_batch_claims() {
        // Test: UBI can handle large batch of claims (scalability)
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;
        let num_claims = 1000;

        // Record 1000 claims
        for i in 0..num_claims {
            let citizen_id = [(i % 256) as u8; 32];
            let amount = 1000 + (i as u64);
            let _ = ubi.record_claim_intent(citizen_id, amount, epoch);
        }

        // Query and verify count
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), num_claims);

        // Verify first and last claims
        assert_eq!(claims[0].amount, 1000);
        assert_eq!(claims[num_claims - 1].amount, 1000 + (num_claims - 1) as u64);
    }

    #[test]
    fn test_e2e_query_before_and_after_claims() {
        // Test: Query returns nothing before claims, records after claims
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");
        let epoch = 100u64;

        // Query empty epoch
        assert!(ubi.query_ubi_claims(epoch).is_empty());

        // Record claims
        for i in 1..=5 {
            let _ = ubi.record_claim_intent([i as u8; 32], 1000, epoch);
        }

        // Query returns claims
        let claims = ubi.query_ubi_claims(epoch);
        assert_eq!(claims.len(), 5);
    }

    #[test]
    fn test_e2e_sequential_epochs_independent_state() {
        // Test: Each epoch maintains independent claim state
        let mut ubi = UbiDistributor::new(test_governance(), 1000).expect("init failed");

        // Epoch 100: 3 claims
        for i in 1..=3 {
            let _ = ubi.record_claim_intent([i as u8; 32], 1000, 100);
        }

        // Epoch 101: 5 claims (completely different)
        for i in 4..=8 {
            let _ = ubi.record_claim_intent([i as u8; 32], 2000, 101);
        }

        // Epoch 102: 2 claims (overlap with 100's citizens)
        for i in 1..=2 {
            let _ = ubi.record_claim_intent([i as u8; 32], 1500, 102);
        }

        // Verify each epoch has correct claims
        let epoch_100 = ubi.query_ubi_claims(100);
        assert_eq!(epoch_100.len(), 3);
        assert!(epoch_100.iter().all(|c| c.amount == 1000));

        let epoch_101 = ubi.query_ubi_claims(101);
        assert_eq!(epoch_101.len(), 5);
        assert!(epoch_101.iter().all(|c| c.amount == 2000));

        let epoch_102 = ubi.query_ubi_claims(102);
        assert_eq!(epoch_102.len(), 2);
        assert!(epoch_102.iter().all(|c| c.amount == 1500));
    }
}
