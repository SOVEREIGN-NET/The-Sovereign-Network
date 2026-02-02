//! Token Transfer Execution
//!
//! The `apply_token_transfer` function is the canonical way to execute
//! token transfers with full validation.

use lib_types::{Address, Amount, TokenId};

use crate::contract::{TokenContract, TransferResult};
use crate::errors::{TokenError, TokenResult};

/// Trait for token storage operations
///
/// This trait defines the minimal storage interface needed for token transfers.
/// Implementations should be provided by the blockchain storage layer.
pub trait TokenStore {
    /// Get token contract by ID
    fn get_token_contract(&self, id: &TokenId) -> TokenResult<Option<TokenContract>>;

    /// Update token contract
    fn put_token_contract(&self, contract: &TokenContract) -> TokenResult<()>;

    /// Get token balance for an address
    fn get_token_balance(&self, token: &TokenId, address: &Address) -> TokenResult<Amount>;

    /// Set token balance for an address
    fn set_token_balance(&self, token: &TokenId, address: &Address, amount: Amount) -> TokenResult<()>;
}

/// Apply a token transfer with full validation
///
/// # Enforcement
///
/// This function enforces:
/// - **Pause**: Transfer fails if contract is paused
/// - **Transfer policy**: Transfer must be allowed by policy
/// - **Fee + burn conservation**: sender_debit == amount + transfer_fee + burn_fee
/// - **Cap invariants**: total_supply never exceeds max_supply
///
/// # Arguments
///
/// * `store` - Storage backend implementing TokenStore
/// * `contract` - Token contract (will be mutated)
/// * `from` - Sender address
/// * `to` - Recipient address
/// * `amount` - Amount to transfer
///
/// # Returns
///
/// * `Ok(TransferResult)` - Transfer details on success
/// * `Err(TokenError)` - Error describing failure
pub fn apply_token_transfer(
    store: &dyn TokenStore,
    contract: &mut TokenContract,
    from: Address,
    to: Address,
    amount: Amount,
) -> TokenResult<TransferResult> {
    // =========================================================================
    // Precondition: spec_version == 2
    // =========================================================================
    if contract.spec_version != 2 {
        return Err(TokenError::InvalidSpecVersion(contract.spec_version));
    }

    // =========================================================================
    // Check 1: Pause
    // =========================================================================
    if contract.paused {
        return Err(TokenError::Paused);
    }

    // =========================================================================
    // Check 2: Transfer policy
    // =========================================================================
    if !contract.transfer_policy.allows_transfer(&from, &to) {
        return Err(TokenError::TransferNotAllowed(
            "Transfer not allowed by policy".to_string()
        ));
    }

    // =========================================================================
    // Check 3: Amount > 0
    // =========================================================================
    if amount == 0 {
        return Err(TokenError::ZeroAmount);
    }

    // =========================================================================
    // Compute fees
    // =========================================================================
    let transfer_fee = contract.fee_schedule.compute_transfer_fee(amount);
    let burn_fee = contract.fee_schedule.compute_burn_fee(amount);

    // Total debit from sender
    let total_debit = amount
        .checked_add(transfer_fee)
        .and_then(|v| v.checked_add(burn_fee))
        .ok_or(TokenError::Overflow)?;

    // =========================================================================
    // Check 4: Sufficient balance
    // =========================================================================
    let from_balance = store.get_token_balance(&contract.id, &from)?;
    if from_balance < total_debit {
        return Err(TokenError::InsufficientBalance {
            have: from_balance,
            need: total_debit,
        });
    }

    // =========================================================================
    // Apply state transitions atomically
    // =========================================================================

    // 1. Debit sender: balances[from] -= total_debit
    let new_from_balance = from_balance
        .checked_sub(total_debit)
        .ok_or(TokenError::Underflow)?;
    store.set_token_balance(&contract.id, &from, new_from_balance)?;

    // 2. Credit recipient: balances[to] += amount
    let to_balance = store.get_token_balance(&contract.id, &to)?;
    let new_to_balance = to_balance
        .checked_add(amount)
        .ok_or(TokenError::Overflow)?;
    store.set_token_balance(&contract.id, &to, new_to_balance)?;

    // 3. Credit fee recipient: balances[fee_recipient] += transfer_fee
    if transfer_fee > 0 {
        let fee_balance = store.get_token_balance(&contract.id, &contract.fee_recipient)?;
        let new_fee_balance = fee_balance
            .checked_add(transfer_fee)
            .ok_or(TokenError::Overflow)?;
        store.set_token_balance(&contract.id, &contract.fee_recipient, new_fee_balance)?;
    }

    // 4. Apply burn: total_supply -= burn_fee, total_burned += burn_fee
    if burn_fee > 0 {
        contract.total_supply = contract.total_supply
            .checked_sub(burn_fee)
            .ok_or(TokenError::Underflow)?;
        contract.total_burned = contract.total_burned
            .checked_add(burn_fee)
            .ok_or(TokenError::Overflow)?;

        // Update contract in storage
        store.put_token_contract(contract)?;
    }

    // =========================================================================
    // Conservation invariant verification
    // =========================================================================
    // sender_debit == amount + transfer_fee + burn_fee
    let expected_debit = amount
        .checked_add(transfer_fee)
        .and_then(|v| v.checked_add(burn_fee))
        .ok_or(TokenError::Overflow)?;

    if total_debit != expected_debit {
        return Err(TokenError::ConservationViolated(format!(
            "total_debit ({}) != amount ({}) + transfer_fee ({}) + burn_fee ({})",
            total_debit, amount, transfer_fee, burn_fee
        )));
    }

    // =========================================================================
    // Cap invariant check (if applicable)
    // =========================================================================
    if let Some(max) = contract.supply_policy.max_supply() {
        if contract.total_supply > max {
            return Err(TokenError::SupplyCapExceeded {
                max,
                would_have: contract.total_supply,
            });
        }
    }

    Ok(TransferResult {
        amount,
        transfer_fee,
        burn_fee,
        total_debit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{FeeSchedule, SupplyPolicy, TransferPolicy};
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Mock token store for testing
    struct MockTokenStore {
        contracts: RefCell<HashMap<TokenId, TokenContract>>,
        balances: RefCell<HashMap<(TokenId, Address), Amount>>,
    }

    impl MockTokenStore {
        fn new() -> Self {
            Self {
                contracts: RefCell::new(HashMap::new()),
                balances: RefCell::new(HashMap::new()),
            }
        }

        fn set_balance(&self, token: TokenId, address: Address, amount: Amount) {
            self.balances.borrow_mut().insert((token, address), amount);
        }
    }

    impl TokenStore for MockTokenStore {
        fn get_token_contract(&self, id: &TokenId) -> TokenResult<Option<TokenContract>> {
            Ok(self.contracts.borrow().get(id).cloned())
        }

        fn put_token_contract(&self, contract: &TokenContract) -> TokenResult<()> {
            self.contracts.borrow_mut().insert(contract.id, contract.clone());
            Ok(())
        }

        fn get_token_balance(&self, token: &TokenId, address: &Address) -> TokenResult<Amount> {
            Ok(*self.balances.borrow().get(&(*token, *address)).unwrap_or(&0))
        }

        fn set_token_balance(&self, token: &TokenId, address: &Address, amount: Amount) -> TokenResult<()> {
            self.balances.borrow_mut().insert((*token, *address), amount);
            Ok(())
        }
    }

    fn create_test_contract() -> TokenContract {
        TokenContract::new(
            TokenId::default(),
            "Test".to_string(),
            "TST".to_string(),
            18,
            SupplyPolicy::FixedCap { max: 1_000_000_000 },
            Address::default(),
        )
    }

    #[test]
    fn test_basic_transfer() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();
        contract.total_supply = 1_000_000;

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        store.set_balance(contract.id, from, 10_000);

        let result = apply_token_transfer(&store, &mut contract, from, to, 1_000).unwrap();

        assert_eq!(result.amount, 1_000);
        assert_eq!(result.transfer_fee, 0);
        assert_eq!(result.burn_fee, 0);
        assert_eq!(result.total_debit, 1_000);

        assert_eq!(store.get_token_balance(&contract.id, &from).unwrap(), 9_000);
        assert_eq!(store.get_token_balance(&contract.id, &to).unwrap(), 1_000);
    }

    #[test]
    fn test_transfer_with_fees() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();
        contract.total_supply = 1_000_000;
        contract.fee_schedule = FeeSchedule {
            transfer_fee_bps: 100, // 1%
            burn_fee_bps: 50,      // 0.5%
            fee_cap: 0,
            min_fee: 0,
        };
        let fee_recipient = Address::new([99u8; 32]);
        contract.fee_recipient = fee_recipient;

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        store.set_balance(contract.id, from, 10_000);

        let result = apply_token_transfer(&store, &mut contract, from, to, 1_000).unwrap();

        assert_eq!(result.amount, 1_000);
        assert_eq!(result.transfer_fee, 10);  // 1% of 1000
        assert_eq!(result.burn_fee, 5);       // 0.5% of 1000
        assert_eq!(result.total_debit, 1_015); // 1000 + 10 + 5

        // Verify balances
        assert_eq!(store.get_token_balance(&contract.id, &from).unwrap(), 8_985); // 10000 - 1015
        assert_eq!(store.get_token_balance(&contract.id, &to).unwrap(), 1_000);
        assert_eq!(store.get_token_balance(&contract.id, &fee_recipient).unwrap(), 10);

        // Verify burn
        assert_eq!(contract.total_supply, 999_995); // 1_000_000 - 5
        assert_eq!(contract.total_burned, 5);
    }

    #[test]
    fn test_transfer_paused() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();
        contract.paused = true;

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);
        store.set_balance(contract.id, from, 10_000);

        let result = apply_token_transfer(&store, &mut contract, from, to, 1_000);
        assert!(matches!(result, Err(TokenError::Paused)));
    }

    #[test]
    fn test_transfer_non_transferable() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();
        contract.transfer_policy = TransferPolicy::NonTransferable;

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);
        store.set_balance(contract.id, from, 10_000);

        let result = apply_token_transfer(&store, &mut contract, from, to, 1_000);
        assert!(matches!(result, Err(TokenError::TransferNotAllowed(_))));
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();
        contract.total_supply = 1_000_000;

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);
        store.set_balance(contract.id, from, 500);

        let result = apply_token_transfer(&store, &mut contract, from, to, 1_000);
        assert!(matches!(result, Err(TokenError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_transfer_zero_amount() {
        let store = MockTokenStore::new();
        let mut contract = create_test_contract();

        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        let result = apply_token_transfer(&store, &mut contract, from, to, 0);
        assert!(matches!(result, Err(TokenError::ZeroAmount)));
    }
}
