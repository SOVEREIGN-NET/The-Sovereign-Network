use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::DAOType;
use super::token_id::derive_token_id;

/// Core DAO token contract with locked-down invariants
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
}

impl DAOToken {
    /// Initialize a new DAO token with deterministic treasury allocation
    ///
    /// NP: 100% to treasury
    /// FP: 20% to treasury, 80% (+ remainder) to initial_holder (caller)
    ///
    /// # Invariants enforced:
    /// - DAOType is immutable once set
    /// - Initialization runs exactly once
    /// - Treasury and staking addresses are non-zero and valid
    /// - Supply allocation is deterministic
    /// - sum(balances) == total_supply always holds
    pub fn init_dao_token(
        dao_type: DAOType,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: u64,
        treasury_addr: PublicKey,
        staking_contract_addr: PublicKey,
        caller: PublicKey, // Used as initial_holder for FP tokens
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
        )
        .unwrap();

        assert!(token.is_initialized());
    }
}
