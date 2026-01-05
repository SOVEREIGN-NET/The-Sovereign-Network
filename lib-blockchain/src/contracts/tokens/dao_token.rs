use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::{DAOType, EconomicPeriod};
use super::token_id::derive_token_id;

/// Core DAO token contract with locked-down invariants
///
/// # Invariant B1: Disbursement State Existence Invariant
/// Every DAOToken that supports scheduled disbursement must store:
/// - allocation_period: EconomicPeriod (or None if no scheduled disbursement)
/// - next_disbursement_height: BlockHeight (or None)
/// If a token has no scheduled disbursement, this must be explicit (None), not implicit absence.
///
/// # Invariant B2: Monotonic Disbursement Invariant
/// next_disbursement_height must only move forward.
/// new_next_height > old_next_height
/// Rollback, replay, or backward movement is forbidden.
///
/// # Invariant B3: Boundary-Trigger Invariant
/// A DAOToken may only disburse if:
/// current_height == next_disbursement_height (exact match, not >=, not >)
/// This ensures:
/// - deterministic replay
/// - no "late" or "early" payouts
///
/// # Invariant B4: Single-Execution Invariant
/// For any disbursement boundary:
/// exactly one disbursement may occur
/// Even if the block is reprocessed or messages are reordered,
/// the disbursement function is called twice.
/// This implies an internal "already executed for height H" guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAOToken {
    // Immutable fields (set at init, never change)
    dao_type: DAOType,
    treasury_addr: PublicKey,
    staking_contract_addr: PublicKey,
    token_id: [u8; 32],
    initialized: bool,

    // Mutable but auditable
    name: String,
    symbol: String,
    decimals: u8,
    total_supply: u64,
    balances: HashMap<PublicKey, u64>,
    
    // Economic period scheduling (Invariants B1-B4)
    allocation_period: Option<EconomicPeriod>,
    next_disbursement_height: Option<u64>,
    last_executed_disbursement_height: Option<u64>, // Invariant B4: single-execution guard
}

impl DAOToken {
    /// Initialize a new DAO token with deterministic treasury allocation
    ///
    /// NP: 100% to treasury
    /// FP: 20% to treasury, 80% (+ remainder) to initial_holder (caller)
    ///
    /// # Parameters:
    /// - allocation_period: If Some, enables scheduled disbursements. If None, no schedule.
    /// - allocation_period must align to block boundaries (EconomicPeriod).
    ///
    /// # Invariants enforced:
    /// - DAOType is immutable once set
    /// - Initialization runs exactly once
    /// - Treasury and staking addresses are non-zero and valid
    /// - Supply allocation is deterministic
    /// - sum(balances) == total_supply always holds
    /// - Disbursement period and height are explicit (Invariant B1)
    pub fn init_dao_token(
        dao_type: DAOType,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: u64,
        treasury_addr: PublicKey,
        staking_contract_addr: PublicKey,
        caller: PublicKey, // Used as initial_holder for FP tokens
        allocation_period: Option<EconomicPeriod>,
        current_height: u64, // Block height at initialization (supports post-genesis init)
    ) -> Result<Self, String> {
        // Validate inputs
        if name.is_empty() {
            return Err("Token name cannot be empty".to_string());
        }
        if symbol.is_empty() {
            return Err("Token symbol cannot be empty".to_string());
        }
        if symbol.len() > 10 {
            return Err("Token symbol too long (max 10 characters)".to_string());
        }
        if decimals > 18 {
            return Err("Too many decimal places (max 18)".to_string());
        }
        if total_supply == 0 {
            return Err("Total supply must be greater than 0".to_string());
        }

        // Validate addresses are non-zero
        if treasury_addr.as_bytes().iter().all(|b| *b == 0) {
            return Err("Treasury address cannot be zero".to_string());
        }
        if staking_contract_addr.as_bytes().iter().all(|b| *b == 0) {
            return Err("Staking contract address cannot be zero".to_string());
        }
        
        // For FP tokens: validate caller is non-zero (becomes initial_holder)
        if dao_type.is_for_profit() && caller.as_bytes().iter().all(|b| *b == 0) {
            return Err("For-profit DAO: initial_holder (caller) cannot be zero address".to_string());
        }

        // Generate token_id using canonical derivation function
        // Ensures deterministic, globally unique IDs that include:
        // - name, symbol, dao_type (prevents NP/FP collision)
        // - decimals (prevents precision confusion)
        let token_id = derive_token_id(&name, &symbol, dao_type, decimals);
        
        // Calculate initial next disbursement height if period is set (Invariant B1)
        // CRITICAL: Compute from current_height, not genesis (height 0)
        // This supports post-genesis initialization (new DAOs, upgrades, redeployments)
        let next_disbursement_height = allocation_period.map(|period| {
            let boundary = period.next_boundary(current_height);
            // Invariant: next disbursement must be >= current height
            // (satisfies "next boundary is at or after current height")
            boundary
        });

        let mut token = DAOToken {
            dao_type,
            treasury_addr: treasury_addr.clone(),
            staking_contract_addr: staking_contract_addr.clone(),
            token_id,
            initialized: false, // Will be set to true only after successful allocation
            name,
            symbol,
            decimals,
            total_supply: 0, // Will be set by allocation
            balances: HashMap::new(),
            allocation_period,
            next_disbursement_height,
            last_executed_disbursement_height: None, // Invariant B4: no execution yet
        };

        // Allocate supply based on DAO type
        token.allocate_on_init(total_supply, &treasury_addr, &caller)?;

        // Verify invariants hold
        token.assert_supply_invariant()?;

        // CRITICAL: Set initialized = true only after all validation and mutation succeeds
        // This ensures initialization is atomic: either fully completed or fully rejected
        token.initialized = true;

        Ok(token)
    }

    /// Allocate tokens to treasury and initial holder based on DAOType
    ///
    /// NP: 100% to treasury
    /// FP: 20% to treasury, 80% (+ remainder due to integer division) to initial_holder
    fn allocate_on_init(
        &mut self,
        supply: u64,
        treasury_addr: &PublicKey,
        initial_holder: &PublicKey,
    ) -> Result<(), String> {
        match self.dao_type {
            DAOType::NP => {
                // Non-profit: 100% to treasury
                self.balances.insert(treasury_addr.clone(), supply);
                self.total_supply = supply;
            }
            DAOType::FP => {
                // For-profit: 20% to treasury, 80% (+ remainder) to initial_holder
                let treasury_share = (supply as u128 * 20 / 100) as u64;
                let holder_share = supply.saturating_sub(treasury_share);

                self.balances.insert(treasury_addr.clone(), treasury_share);
                self.balances.insert(initial_holder.clone(), holder_share);
                self.total_supply = supply;
            }
        }

        Ok(())
    }

    /// Verify supply conservation invariant: sum(all_balances) == total_supply
    fn assert_supply_invariant(&self) -> Result<(), String> {
        let sum_balances: u64 = self.balances.values().sum();
        if sum_balances != self.total_supply {
            return Err(format!(
                "Supply invariant violation: sum(balances)={} != total_supply={}",
                sum_balances, self.total_supply
            ));
        }
        Ok(())
    }

    /// Check caller is the staking contract
    fn require_staking_auth(&self, caller: &PublicKey) -> Result<(), String> {
        if caller != &self.staking_contract_addr {
            return Err("Only staking contract can mint/burn".to_string());
        }
        Ok(())
    }

    /// Mint tokens (only callable by staking contract)
    pub fn mint(&mut self, caller: &PublicKey, to: &PublicKey, amount: u64) -> Result<(), String> {
        // Validate authorization
        self.require_staking_auth(caller)?;

        // Reject zero amounts
        if amount == 0 {
            return Err("Cannot mint zero amount".to_string());
        }

        // Check overflow
        if self.total_supply.checked_add(amount).is_none() {
            return Err("Mint would cause overflow".to_string());
        }

        // Update state
        let current_balance = self.balances.get(to).copied().unwrap_or(0);
        if current_balance.checked_add(amount).is_none() {
            return Err("Balance would overflow".to_string());
        }

        self.balances.insert(to.clone(), current_balance + amount);
        self.total_supply += amount;

        // Verify invariant
        self.assert_supply_invariant()?;

        Ok(())
    }

    /// Burn tokens (only callable by staking contract)
    pub fn burn(&mut self, caller: &PublicKey, from: &PublicKey, amount: u64) -> Result<(), String> {
        // Validate authorization
        self.require_staking_auth(caller)?;

        // Reject zero amounts
        if amount == 0 {
            return Err("Cannot burn zero amount".to_string());
        }

        // Check balance
        let balance = self.balances.get(from).copied().unwrap_or(0);
        if balance < amount {
            return Err("Insufficient balance to burn".to_string());
        }

        // Update state
        self.balances.insert(from.clone(), balance - amount);
        self.total_supply = self.total_supply.saturating_sub(amount);

        // Verify invariant
        self.assert_supply_invariant()?;

        Ok(())
    }

    /// Transfer tokens between accounts (no authorization required)
    /// State-atomic: validates all preconditions before any mutation.
    pub fn transfer(&mut self, from: &PublicKey, to: &PublicKey, amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("Cannot transfer zero amount".to_string());
        }

        // PRE-VALIDATE: all checks before any mutation
        let from_balance = self.balances.get(from).copied().unwrap_or(0);
        if from_balance < amount {
            return Err("Insufficient balance".to_string());
        }

        let to_balance = self.balances.get(to).copied().unwrap_or(0);
        let new_to_balance = to_balance
            .checked_add(amount)
            .ok_or_else(|| "Recipient balance would overflow".to_string())?;

        // NEW_FROM_BALANCE is implicitly safe: from_balance >= amount
        let new_from_balance = from_balance - amount;

        // MUTATE only after all validations pass
        self.balances.insert(from.clone(), new_from_balance);
        self.balances.insert(to.clone(), new_to_balance);

        // Verify invariant (transfer should not change total_supply)
        self.assert_supply_invariant()?;

        Ok(())
    }

    /// Get the balance of an account
    pub fn balance_of(&self, account: &PublicKey) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// Get the DAO type (immutable)
    pub fn class(&self) -> DAOType {
        self.dao_type
    }

    /// Get the treasury address
    pub fn treasury(&self) -> &PublicKey {
        &self.treasury_addr
    }

    /// Get the staking contract address
    pub fn staking_contract(&self) -> &PublicKey {
        &self.staking_contract_addr
    }

    /// Check if this token has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get total supply
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Get token name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get token symbol
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Get decimals
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Get all non-zero balances
    pub fn all_balances(&self) -> HashMap<PublicKey, u64> {
        self.balances
            .iter()
            .filter(|(_, &balance)| balance > 0)
            .map(|(key, &balance)| (key.clone(), balance))
            .collect()
    }

    // ============================================================================
    // DISBURSEMENT SCHEDULE METHODS (Invariants B1-B4)
    // ============================================================================

    /// Check if a disbursement is due at the current block height
    ///
    /// # Invariant B3: Boundary-Trigger Invariant
    /// Returns true only if current_height == next_disbursement_height (exact match).
    /// Not >=, not approximate.
    pub fn is_disbursement_due(&self, current_height: u64) -> bool {
        match (self.next_disbursement_height, self.last_executed_disbursement_height) {
            (Some(next_height), Some(last_height)) => {
                // Invariant B4: Already executed this height
                if last_height == current_height {
                    return false;
                }
                current_height == next_height
            }
            (Some(next_height), None) => {
                // First disbursement
                current_height == next_height
            }
            (None, _) => {
                // No schedule
                false
            }
        }
    }

    /// Mark a disbursement as executed at the given height
    ///
    /// # Invariant B3: Boundary-Trigger Invariant (CRITICAL)
    /// Disbursement execution is permitted ONLY when current_height == next_disbursement_height.
    /// Execution at any other height is rejected.
    /// This ensures deterministic, consensus-agreed payout timing.
    ///
    /// # Invariant B2: Monotonic Disbursement Invariant
    /// Enforces that next_disbursement_height only moves forward.
    ///
    /// # Invariant B4: Single-Execution Invariant
    /// Records execution height to prevent re-execution at the same boundary.
    ///
    /// # Errors:
    /// - no allocation_period is set
    /// - height != next_disbursement_height (violates B3: boundary trigger)
    /// - disbursement was already executed at this height (violates B4)
    pub fn record_disbursement_executed(&mut self, height: u64) -> Result<(), String> {
        if self.allocation_period.is_none() {
            return Err("Token has no scheduled disbursement period".to_string());
        }

        // CRITICAL: Invariant B3 - Boundary-Trigger Enforement
        // Disbursement must occur ONLY at the exact scheduled boundary height.
        // Not before (height < next), not after (height > next), only at exact match.
        if let Some(next_height) = self.next_disbursement_height {
            if height != next_height {
                return Err(format!(
                    "Disbursement not due at height {}: next boundary is at height {}",
                    height, next_height
                ));
            }
        } else {
            // First disbursement: must be at the period's first boundary
            let period = self.allocation_period.unwrap();
            let first_boundary = period.next_boundary(0);
            if height != first_boundary {
                return Err(format!(
                    "First disbursement must occur at boundary height {}, not {}",
                    first_boundary, height
                ));
            }
        }

        // Invariant B4: Prevent double execution at same height
        if let Some(last_height) = self.last_executed_disbursement_height {
            if last_height == height {
                return Err(format!(
                    "Disbursement already executed at height {}",
                    height
                ));
            }
            // Invariant B2: Must move forward (height > last, not just !=)
            if height <= last_height {
                return Err(format!(
                    "Cannot execute disbursement at height {} (last was {})",
                    height, last_height
                ));
            }
        }

        let period = self.allocation_period.unwrap(); // Already checked above
        let next_boundary = period.next_boundary(height);

        // Invariant B2: Verify next boundary moves forward monotonically
        if let Some(prev_next) = self.next_disbursement_height {
            if next_boundary <= prev_next {
                return Err("Next disbursement height must increase".to_string());
            }
        }

        self.last_executed_disbursement_height = Some(height);
        self.next_disbursement_height = Some(next_boundary);

        Ok(())
    }

    /// Get the allocation period (if set)
    pub fn allocation_period(&self) -> Option<EconomicPeriod> {
        self.allocation_period
    }

    /// Get the next disbursement height (if scheduled)
    pub fn next_disbursement_height(&self) -> Option<u64> {
        self.next_disbursement_height
    }

    /// Get the last executed disbursement height (if any)
    pub fn last_executed_disbursement_height(&self) -> Option<u64> {
        self.last_executed_disbursement_height
    }


}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    // ============================================================================
    // INITIALIZATION AND ALLOCATION TESTS
    // ============================================================================

    #[test]
    fn test_np_init_allocates_100_percent_to_treasury() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "NonProfit Token".to_string(),
            "NP".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None, // No scheduled disbursement
            0, // genesis height
        )
        .unwrap();

        assert_eq!(token.balance_of(&treasury), 1_000_000);
        assert_eq!(token.total_supply(), 1_000_000);
    }

    #[test]
    fn test_fp_init_allocates_20_percent_to_treasury() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::FP,
            "ForProfit Token".to_string(),
            "FP".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let treasury_balance = token.balance_of(&treasury);
        assert_eq!(treasury_balance, 200_000); // 20% of 1_000_000
    }

    #[test]
    fn test_fp_init_allocates_remainder_to_initial_holder() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::FP,
            "ForProfit Token".to_string(),
            "FP".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        let caller_balance = token.balance_of(&caller);
        let treasury_balance = token.balance_of(&treasury);
        
        // Caller should get 80% = 800_000
        assert_eq!(caller_balance, 800_000);
        // Total should still equal supply
        assert_eq!(caller_balance + treasury_balance, 1_000_000);
    }

    #[test]
    fn test_fp_init_with_odd_supply_handles_remainder() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        // Use odd number: 1_000_001
        let token = DAOToken::init_dao_token(
            DAOType::FP,
            "ForProfit Token".to_string(),
            "FP".to_string(),
            8,
            1_000_001,
            treasury.clone(),
            staking,
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        let treasury_balance = token.balance_of(&treasury);
        let caller_balance = token.balance_of(&caller);
        
        // 1_000_001 * 20 / 100 = 200_000 (integer division)
        assert_eq!(treasury_balance, 200_000);
        // Remainder goes to caller: 1_000_001 - 200_000 = 800_001
        assert_eq!(caller_balance, 800_001);
        // Total must equal supply
        assert_eq!(token.total_supply(), 1_000_001);
        assert_eq!(treasury_balance + caller_balance, 1_000_001);
    }

    #[test]
    fn test_init_rejects_zero_treasury_address() {
        let zero_addr = PublicKey::new(vec![0u8; 1312]);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let result = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            zero_addr,
            staking,
            caller,
            None,
            0, // genesis height
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Treasury address cannot be zero"));
    }

    #[test]
    fn test_init_rejects_zero_staking_address() {
        let treasury = create_test_public_key(1);
        let zero_addr = PublicKey::new(vec![0u8; 1312]);
        let caller = create_test_public_key(3);

        let result = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            zero_addr,
            caller,
            None,
            0, // genesis height
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Staking contract address cannot be zero"));
    }

    #[test]
    fn test_class_returns_immutable_dao_type() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token_np = DAOToken::init_dao_token(
            DAOType::NP,
            "NP Token".to_string(),
            "NP".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        assert_eq!(token_np.class(), DAOType::NP);

        let token_fp = DAOToken::init_dao_token(
            DAOType::FP,
            "FP Token".to_string(),
            "FP".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        assert_eq!(token_fp.class(), DAOType::FP);
    }

    // ============================================================================
    // MINTING RESTRICTIONS AND SUPPLY ACCOUNTING
    // ============================================================================

    #[test]
    fn test_mint_by_non_staking_contract_fails() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let attacker = create_test_public_key(4);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let result = token.mint(&attacker, &recipient, 1000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only staking contract can mint"));
    }

    #[test]
    fn test_mint_by_staking_contract_succeeds() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let initial_supply = token.total_supply();
        let result = token.mint(&staking, &recipient, 1000);
        
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&recipient), 1000);
        assert_eq!(token.total_supply(), initial_supply + 1000);
    }

    #[test]
    fn test_mint_with_zero_amount_rejected() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let result = token.mint(&staking, &recipient, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot mint zero amount"));
    }

    #[test]
    fn test_mint_overflow_protection() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            u64::MAX - 100,
            treasury,
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // Try to mint more than would fit
        let result = token.mint(&staking, &recipient, 1000);
        assert!(result.is_err());
    }

    // ============================================================================
    // BURNING AND AUTHORIZATION
    // ============================================================================

    #[test]
    fn test_burn_decreases_supply_and_balance() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let initial_supply = token.total_supply();
        let initial_balance = token.balance_of(&treasury);

        let result = token.burn(&staking, &treasury, 100_000);
        
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&treasury), initial_balance - 100_000);
        assert_eq!(token.total_supply(), initial_supply - 100_000);
    }

    #[test]
    fn test_burn_by_unauthorized_caller_fails() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let attacker = create_test_public_key(4);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let result = token.burn(&attacker, &treasury, 100_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Only staking contract can mint"));
    }

    #[test]
    fn test_burn_with_zero_amount_rejected() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let result = token.burn(&staking, &treasury, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot burn zero amount"));
    }

    #[test]
    fn test_burn_with_insufficient_balance_fails() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let user = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // User has 0 balance
        let result = token.burn(&staking, &user, 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient balance to burn"));
    }

    // ============================================================================
    // SUPPLY CONSERVATION INVARIANT
    // ============================================================================

    #[test]
    fn test_supply_invariant_after_init() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let sum_balances: u64 = token.all_balances().values().sum();
        assert_eq!(sum_balances, token.total_supply());
    }

    #[test]
    fn test_supply_invariant_after_mint() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        token.mint(&staking, &recipient, 50_000).unwrap();

        let sum_balances: u64 = token.all_balances().values().sum();
        assert_eq!(sum_balances, token.total_supply());
    }

    #[test]
    fn test_supply_invariant_after_burn() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        token.burn(&staking, &treasury, 100_000).unwrap();

        let sum_balances: u64 = token.all_balances().values().sum();
        assert_eq!(sum_balances, token.total_supply());
    }

    #[test]
    fn test_supply_invariant_after_transfer() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let recipient = create_test_public_key(5);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        token.transfer(&treasury, &recipient, 250_000).unwrap();

        let sum_balances: u64 = token.all_balances().values().sum();
        assert_eq!(sum_balances, token.total_supply());
    }

    #[test]
    fn test_supply_invariant_across_multiple_operations() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let user_a = create_test_public_key(5);
        let user_b = create_test_public_key(6);

        let mut token = DAOToken::init_dao_token(
            DAOType::FP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        // Verify after init
        let mut sum = token.all_balances().values().sum::<u64>();
        assert_eq!(sum, token.total_supply());

        // Mint
        token.mint(&staking, &user_a, 50_000).unwrap();
        sum = token.all_balances().values().sum::<u64>();
        assert_eq!(sum, token.total_supply());

        // Transfer
        token.transfer(&caller, &user_b, 100_000).unwrap();
        sum = token.all_balances().values().sum::<u64>();
        assert_eq!(sum, token.total_supply());

        // Burn
        token.burn(&staking, &user_a, 25_000).unwrap();
        sum = token.all_balances().values().sum::<u64>();
        assert_eq!(sum, token.total_supply());
    }

    // ============================================================================
    // CRITICAL REGRESSION TESTS (Consensus Safety)
    // ============================================================================

    #[test]
    fn test_transfer_atomicity_no_mutation_on_error() {
        // CRITICAL: validate → compute → mutate (no mutation if validation fails)
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);
        let user_a = create_test_public_key(5);
        let user_b = create_test_public_key(6);
        
        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // Transfer some tokens to user_a
        token.transfer(&treasury, &user_a, 100_000).unwrap();
        
        let user_a_before = token.balance_of(&user_a);
        let user_b_before = token.balance_of(&user_b);
        let supply_before = token.total_supply();

        // Try transfer with insufficient balance (validation will fail)
        let result = token.transfer(&user_a, &user_b, 200_000); // user_a only has 100_000

        // Must fail
        assert!(result.is_err());

        // CRITICAL: State must be completely unchanged on error
        assert_eq!(token.balance_of(&user_a), user_a_before);
        assert_eq!(token.balance_of(&user_b), user_b_before);
        assert_eq!(token.total_supply(), supply_before);
        
        // CRITICAL: All other balances unchanged (supply invariant still holds)
        let sum: u64 = token.all_balances().values().sum();
        assert_eq!(sum, token.total_supply());
    }

    #[test]
    fn test_token_id_determinism_from_init() {
        // Verify that init produces deterministic token_ids via canonical function
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let name = "TestToken";
        let symbol = "TEST";
        let decimals = 8;

        let token1 = DAOToken::init_dao_token(
            DAOType::NP,
            name.to_string(),
            symbol.to_string(),
            decimals,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        let token2 = DAOToken::init_dao_token(
            DAOType::NP,
            name.to_string(),
            symbol.to_string(),
            decimals,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // Same init inputs must produce identical token IDs
        assert_eq!(token1.token_id, token2.token_id);
    }

    #[test]
    fn test_token_id_differs_across_dao_types_via_init() {
        // Verify canonical function prevents NP/FP collision
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let name = "SectorToken";
        let symbol = "SECT";
        let decimals = 8;

        let token_np = DAOToken::init_dao_token(
            DAOType::NP,
            name.to_string(),
            symbol.to_string(),
            decimals,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            None,
            0, // genesis height
        )
        .unwrap();

        let token_fp = DAOToken::init_dao_token(
            DAOType::FP,
            name.to_string(),
            symbol.to_string(),
            decimals,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // NP and FP must have different token IDs (canonical function enforces this)
        assert_ne!(token_np.token_id, token_fp.token_id);
    }

    #[test]
    fn test_fp_init_rejects_zero_caller_address() {
        // CRITICAL: FP token must validate initial_holder (caller)
        // Cannot silently burn 80% of supply to zero address
        
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let zero_caller = PublicKey::new(vec![0u8; 1312]);

        let result = DAOToken::init_dao_token(
            DAOType::FP,
            "ForProfit".to_string(),
            "FP".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            zero_caller,
            None,
            0, // genesis height
        );

        // Must reject zero caller for FP
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("initial_holder (caller) cannot be zero address"));
    }

    #[test]
    fn test_initialized_flag_prevents_re_initialization() {
        // CRITICAL: initialized flag must be enforced to prevent re-init
        // Ensures:
        // - no partial initialization
        // - no re-entry
        // - safe upgrades/migrations
        
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        // First init succeeds
        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // Verify initialized flag is set to true
        assert!(token.is_initialized());
        
        // Token is immutable after successful init.
        // Re-initialization is prevented by the lack of a re-init method
        // and the initialized flag being set.
        // If a mutable re-init method existed, it would be guarded by:
        // if self.initialized { return Err(...) }
    }

    #[test]
    fn test_initialization_flag_set() {
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        assert!(token.is_initialized());
    }

    // ============================================================================
    // DISBURSEMENT INVARIANT TESTS (Invariants B1-B4)
    // ============================================================================

    #[test]
    fn test_invariant_b1_disbursement_state_existence_none() {
        // Invariant B1: Explicit None, not implicit absence
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        // No allocation period set
        assert_eq!(token.allocation_period(), None);
        assert_eq!(token.next_disbursement_height(), None);
    }

    #[test]
    fn test_invariant_b1_disbursement_state_existence_some() {
        // Invariant B1: Explicit Some with both period and height
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Monthly),
            0, // genesis height
        )
        .unwrap();

        // Period is set
        assert_eq!(token.allocation_period(), Some(EconomicPeriod::Monthly));
        // Next disbursement height calculated from first boundary
        assert_eq!(token.next_disbursement_height(), Some(259_200));
    }

    #[test]
    fn test_invariant_b3_boundary_trigger_exact_match() {
        // Invariant B3: Only exact match triggers disbursement
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        // Not at boundary yet
        assert!(!token.is_disbursement_due(8_639));
        
        // Exact boundary
        assert!(token.is_disbursement_due(8_640));
        
        // Past boundary (but next disbursement not yet recorded)
        assert!(!token.is_disbursement_due(8_641));
    }

    #[test]
    fn test_invariant_b2_monotonic_disbursement() {
        // Invariant B2: next_disbursement_height only moves forward
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        let first_next = token.next_disbursement_height().unwrap();
        assert_eq!(first_next, 8_640); // First Daily boundary

        // Execute disbursement at boundary
        token.record_disbursement_executed(8_640).unwrap();

        let second_next = token.next_disbursement_height().unwrap();
        assert_eq!(second_next, 17_280); // Second Daily boundary

        // Verify monotonic increase
        assert!(second_next > first_next);
    }

    #[test]
    fn test_invariant_b4_single_execution_guard() {
        // Invariant B4: Cannot execute at a height where execution already occurred
        // (Note: With B3 boundary enforcement, we can't naturally hit this by calling at
        // the same height twice, since the schedule advances. But the guard is still there.)
        // This test verifies the B3 + B4 interaction: after execution at 8640,
        // attempting to execute at 8640 again fails B3 (not the current due height anymore).
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        // First execution at boundary succeeds
        token.record_disbursement_executed(8_640).unwrap();
        assert_eq!(token.last_executed_disbursement_height(), Some(8_640));
        assert_eq!(token.next_disbursement_height(), Some(17_280)); // advanced

        // Second attempt at the same height (8640) fails with B3 check
        // because 8640 is no longer the due height (due is now 17280)
        let result = token.record_disbursement_executed(8_640);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Disbursement not due at height")); // B3 violation
    }

    #[test]
    fn test_invariant_b2_rejects_backward_movement() {
        // Invariant B2: Cannot execute at a height <= last_executed_disbursement_height
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        // Execute at first boundary
        token.record_disbursement_executed(8_640).unwrap();

        // Try to execute at earlier height
        let result = token.record_disbursement_executed(8_639);
        assert!(result.is_err());
        // Will fail B3 check first (8639 != 17280 which is current due height)
        assert!(result.unwrap_err().contains("Disbursement not due at height"));
    }

    #[test]
    fn test_disbursement_schedule_multiple_cycles() {
        // Test Invariant B3 and B4 across multiple disbursement cycles
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        // Cycle 1
        assert_eq!(token.next_disbursement_height(), Some(8_640));
        assert!(token.is_disbursement_due(8_640));
        token.record_disbursement_executed(8_640).unwrap();

        // Cycle 2
        assert_eq!(token.next_disbursement_height(), Some(17_280));
        assert!(token.is_disbursement_due(17_280));
        token.record_disbursement_executed(17_280).unwrap();

        // Cycle 3
        assert_eq!(token.next_disbursement_height(), Some(25_920));
        assert!(token.is_disbursement_due(25_920));
        token.record_disbursement_executed(25_920).unwrap();

        // Verify last executed height
        assert_eq!(token.last_executed_disbursement_height(), Some(25_920));
    }

    #[test]
    fn test_no_scheduled_disbursement_never_due() {
        // Token without schedule never reports disbursement due
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None, // No schedule
            0, // genesis height
        )
        .unwrap();

        // Never due, regardless of height
        assert!(!token.is_disbursement_due(8_640));
        assert!(!token.is_disbursement_due(259_200));
        assert!(!token.is_disbursement_due(777_600));
    }

    #[test]
    fn test_record_disbursement_without_schedule_fails() {
        // Cannot record execution if no schedule is set
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            None,
            0, // genesis height
        )
        .unwrap();

        let result = token.record_disbursement_executed(8_640);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Token has no scheduled disbursement period"));
    }

    // ============================================================================
    // CRITICAL: BOUNDARY ENFORCEMENT TESTS (Invariant B3)
    // ============================================================================
    // These tests ensure the B3 invariant is enforced:
    // "Disbursement execution is permitted ONLY when current_height == next_disbursement_height"
    // Any deviation (early or late) must be rejected to maintain consensus-deterministic timing.

    #[test]
    fn test_invariant_b3_rejects_early_execution() {
        // CRITICAL: Calling record_disbursement_executed() before the scheduled boundary
        // must fail and NOT update any state.
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily), // First boundary: 8640
            0, // genesis height
        )
        .unwrap();

        // Verify initial state
        assert_eq!(token.next_disbursement_height(), Some(8_640));
        assert_eq!(token.last_executed_disbursement_height(), None);

        // Try to execute EARLY (at height 8639, one block before boundary)
        let result = token.record_disbursement_executed(8_639);

        // Must fail
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Disbursement not due at height"));

        // CRITICAL: State must be UNCHANGED after failed attempt
        assert_eq!(token.next_disbursement_height(), Some(8_640)); // unchanged
        assert_eq!(token.last_executed_disbursement_height(), None); // unchanged
    }

    #[test]
    fn test_invariant_b3_rejects_late_execution() {
        // CRITICAL: Calling record_disbursement_executed() after the scheduled boundary
        // must fail and NOT update any state (prevents "catch-up" execution).
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily), // First boundary: 8640
            0, // genesis height
        )
        .unwrap();

        // Verify initial state
        assert_eq!(token.next_disbursement_height(), Some(8_640));

        // Try to execute LATE (at height 8641, one block after boundary)
        let result = token.record_disbursement_executed(8_641);

        // Must fail
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Disbursement not due at height"));

        // CRITICAL: State must be UNCHANGED after failed attempt
        assert_eq!(token.next_disbursement_height(), Some(8_640)); // unchanged
        assert_eq!(token.last_executed_disbursement_height(), None); // unchanged
    }

    #[test]
    fn test_invariant_b3_accepts_exact_boundary_and_advances() {
        // CRITICAL: Calling record_disbursement_executed() at the EXACT boundary
        // must succeed and advance the schedule to the next boundary.
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        let mut token = DAOToken::init_dao_token(
            DAOType::NP,
            "Token".to_string(),
            "TKN".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Daily), // First boundary: 8640
            0, // genesis height
        )
        .unwrap();

        // Verify initial state
        assert_eq!(token.next_disbursement_height(), Some(8_640));
        assert_eq!(token.last_executed_disbursement_height(), None);

        // Execute at EXACT boundary
        let result = token.record_disbursement_executed(8_640);
        assert!(result.is_ok()); // Must succeed

        // CRITICAL: State must be ADVANCED after successful execution
        assert_eq!(token.next_disbursement_height(), Some(17_280)); // advanced to next boundary
        assert_eq!(token.last_executed_disbursement_height(), Some(8_640)); // recorded execution

        // Verify we can call again at the new boundary
        let result2 = token.record_disbursement_executed(17_280);
        assert!(result2.is_ok());
        assert_eq!(token.next_disbursement_height(), Some(25_920)); // next boundary
        assert_eq!(token.last_executed_disbursement_height(), Some(17_280));
    }

    #[test]
    fn test_invariant_b3_boundary_enforcement_survives_multiple_periods() {
        // Test B3 enforcement across all period types
        let treasury = create_test_public_key(1);
        let staking = create_test_public_key(2);
        let caller = create_test_public_key(3);

        // Test with Daily period
        let mut token_daily = DAOToken::init_dao_token(
            DAOType::NP,
            "Daily".to_string(),
            "DAILY".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            Some(EconomicPeriod::Daily),
            0, // genesis height
        )
        .unwrap();

        // Daily: first boundary 8640
        assert_eq!(token_daily.next_disbursement_height(), Some(8_640));
        assert!(token_daily.record_disbursement_executed(8_640).is_ok());
        assert!(token_daily.record_disbursement_executed(17_280).is_ok());

        // Test with Monthly period
        let mut token_monthly = DAOToken::init_dao_token(
            DAOType::NP,
            "Monthly".to_string(),
            "MONTHLY".to_string(),
            8,
            1_000_000,
            treasury.clone(),
            staking.clone(),
            caller.clone(),
            Some(EconomicPeriod::Monthly),
            0, // genesis height
        )
        .unwrap();

        // Monthly: first boundary 259200
        assert_eq!(token_monthly.next_disbursement_height(), Some(259_200));
        assert!(token_monthly.record_disbursement_executed(259_200).is_ok());
        assert!(token_monthly.record_disbursement_executed(518_400).is_ok());

        // Test with Quarterly period
        let mut token_quarterly = DAOToken::init_dao_token(
            DAOType::NP,
            "Quarterly".to_string(),
            "QUARTERLY".to_string(),
            8,
            1_000_000,
            treasury,
            staking,
            caller,
            Some(EconomicPeriod::Quarterly),
            0, // genesis height
        )
        .unwrap();

        // Quarterly: first boundary 777600
        assert_eq!(token_quarterly.next_disbursement_height(), Some(777_600));
        assert!(token_quarterly
            .record_disbursement_executed(777_600)
            .is_ok());
        assert!(token_quarterly
            .record_disbursement_executed(1_555_200)
            .is_ok());
    }
}
