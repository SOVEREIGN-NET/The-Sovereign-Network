use super::core::{TokenContract, TokenInfo};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::utils;
use crate::contracts::treasury_kernel::{
    TreasuryKernel, KernelOpError, CreditReason, DebitReason,
};
use std::collections::HashMap;

/// Token operation functions for contract system integration
///
/// NOTE: transfer_tokens() and transfer_from_allowance() removed in Phase 3.
/// These wrapper functions wrapped the old transfer(from, to, amount) API.
/// The new transfer(ctx, to, amount) API requires ExecutionContext for capability-bound authorization.
/// Callers should call contract.transfer(ctx, to, amount) directly with ExecutionContext.

/// Approve spending allowance
pub fn approve_spending(
    contract: &mut TokenContract,
    owner: &PublicKey,
    spender: &PublicKey,
    amount: u64,
) {
    contract.approve(owner, spender, amount);
}

/// Mint new tokens
///
/// **Deprecated**: Use `mint_tokens_via_kernel()` or `TreasuryKernel::execute_authorized_mint()`
/// instead. Direct minting bypasses governance authorization and audit trail.
#[deprecated(since = "0.1.0", note = "Use mint_tokens_via_kernel() or TreasuryKernel::execute_authorized_mint() for governance-gated minting")]
pub fn mint_tokens(
    contract: &mut TokenContract,
    to: &PublicKey,
    amount: u64,
) -> Result<(), String> {
    contract.mint(to, amount)
}

/// Burn tokens from account
///
/// **Deprecated**: Use `burn_tokens_via_kernel()` or `TreasuryKernel::execute_authorized_burn()`
/// instead. Direct burning bypasses governance authorization and audit trail.
#[deprecated(since = "0.1.0", note = "Use burn_tokens_via_kernel() or TreasuryKernel::execute_authorized_burn() for governance-gated burning")]
pub fn burn_tokens(
    contract: &mut TokenContract,
    from: &PublicKey,
    amount: u64,
) -> Result<(), String> {
    contract.burn(from, amount)
}

/// Mint new tokens via Treasury Kernel (preferred path)
///
/// Routes minting through the kernel's authorization layer.
/// Use this instead of direct `mint_tokens()` when kernel is available.
pub fn mint_tokens_via_kernel(
    kernel: &mut TreasuryKernel,
    contract: &mut TokenContract,
    to: &PublicKey,
    amount: u64,
) -> Result<(), KernelOpError> {
    let caller = kernel.kernel_address().clone();
    kernel.credit(contract, &caller, to, amount, CreditReason::Mint)
}

/// Burn tokens via Treasury Kernel (preferred path)
///
/// Routes burning through the kernel's authorization layer.
/// Use this instead of direct `burn_tokens()` when kernel is available.
pub fn burn_tokens_via_kernel(
    kernel: &mut TreasuryKernel,
    contract: &mut TokenContract,
    from: &PublicKey,
    amount: u64,
) -> Result<(), KernelOpError> {
    let caller = kernel.kernel_address().clone();
    kernel.debit(contract, &caller, from, amount, DebitReason::Burn)
}

/// Get account balance
pub fn get_balance(contract: &TokenContract, account: &PublicKey) -> u64 {
    contract.balance_of(account)
}

/// Get spending allowance
pub fn get_allowance(
    contract: &TokenContract,
    owner: &PublicKey,
    spender: &PublicKey,
) -> u64 {
    contract.allowance(owner, spender)
}

/// Get token information
pub fn get_token_info(contract: &TokenContract) -> TokenInfo {
    contract.info()
}

/// Validate token contract
pub fn validate_token(contract: &TokenContract) -> Result<(), String> {
    contract.validate()
}

/// Check if minting amount is possible
pub fn can_mint_amount(contract: &TokenContract, amount: u64) -> bool {
    contract.can_mint(amount)
}

/// Get remaining mintable supply
pub fn get_remaining_supply(contract: &TokenContract) -> u64 {
    contract.remaining_supply()
}

/// Get holder count
pub fn get_holder_count(contract: &TokenContract) -> usize {
    contract.holder_count()
}

/// Calculate market cap with external price
pub fn calculate_market_cap(contract: &TokenContract, price_per_token: f64) -> f64 {
    contract.market_cap(price_per_token)
}

/// Create a new ZHTP native token contract
pub fn create_zhtp_token() -> TokenContract {
    TokenContract::new_zhtp()
}

/// Create a new custom token contract
pub fn create_custom_token(
    name: String,
    symbol: String,
    initial_supply: u64,
    creator: PublicKey,
) -> TokenContract {
    TokenContract::new_custom(name, symbol, initial_supply, creator)
}

/// Create a deflationary token contract
pub fn create_deflationary_token(
    name: String,
    symbol: String,
    decimals: u8,
    max_supply: u64,
    burn_rate: u64,
    initial_supply: u64,
    creator: PublicKey,
) -> TokenContract {
    let token_id = utils::generate_custom_token_id(&name, &symbol);
    let mut token = TokenContract::new(
        token_id,
        name,
        symbol,
        decimals,
        max_supply,
        true, // is_deflationary
        burn_rate,
        creator.clone(),
    );
    
    if initial_supply > 0 {
        let _ = token.mint(&creator, initial_supply);
    }
    
    token
}

/// NOTE: batch_transfer() removed in Phase 3.
/// This function relied on the old transfer(from, to, amount) API.
/// The new transfer(ctx, to, amount) API requires ExecutionContext for capability-bound authorization.
/// Batch transfers should be implemented using the new transfer(ctx, to, amount) API.

/// Get all non-zero balances
pub fn get_all_balances(contract: &TokenContract) -> HashMap<PublicKey, u64> {
    contract.balances
        .iter()
        .filter(|(_, &balance)| balance > 0)
        .map(|(key, &balance)| (key.clone(), balance))
        .collect()
}

/// Get all allowances for an owner
pub fn get_all_allowances(
    contract: &TokenContract,
    owner: &PublicKey,
) -> HashMap<PublicKey, u64> {
    contract.allowances
        .get(owner)
        .map(|allowances| {
            allowances
                .iter()
                .filter(|(_, &amount)| amount > 0)
                .map(|(spender, &amount)| (spender.clone(), amount))
                .collect()
        })
        .unwrap_or_default()
}

/// Calculate total value locked (TVL) in token (requires price)
pub fn calculate_tvl(contract: &TokenContract, price_per_token: f64) -> f64 {
    let total_locked: u64 = contract.balances.values().sum();
    (total_locked as f64 / 10f64.powi(contract.decimals as i32)) * price_per_token
}

/// Get token distribution statistics
pub fn get_distribution_stats(contract: &TokenContract) -> TokenDistributionStats {
    let balances: Vec<u64> = contract.balances
        .values()
        .filter(|&&balance| balance > 0)
        .copied()
        .collect();
    
    if balances.is_empty() {
        return TokenDistributionStats::default();
    }
    
    let total_holders = balances.len();
    let total_supply = contract.total_supply;
    let largest_balance = *balances.iter().max().unwrap_or(&0);
    let smallest_balance = *balances.iter().min().unwrap_or(&0);
    let average_balance = total_supply / total_holders as u64;
    
    // Calculate concentration (percentage held by top holder)
    let concentration = if total_supply > 0 {
        (largest_balance as f64 / total_supply as f64) * 100.0
    } else {
        0.0
    };
    
    TokenDistributionStats {
        total_holders,
        largest_balance,
        smallest_balance,
        average_balance,
        concentration_percentage: concentration,
        total_supply,
    }
}

/// Token distribution statistics
#[derive(Debug, Clone)]
pub struct TokenDistributionStats {
    pub total_holders: usize,
    pub largest_balance: u64,
    pub smallest_balance: u64,
    pub average_balance: u64,
    pub concentration_percentage: f64,
    pub total_supply: u64,
}

impl Default for TokenDistributionStats {
    fn default() -> Self {
        Self {
            total_holders: 0,
            largest_balance: 0,
            smallest_balance: 0,
            average_balance: 0,
            concentration_percentage: 0.0,
            total_supply: 0,
        }
    }
}

/// Advanced token operations for complex scenarios

/// Execute a token swap between two tokens
///
/// **Note**: This function calls `mint()` and `burn()` directly on `TokenContract`.
/// It will fail at runtime for tokens with `kernel_only_mode` enabled.
/// A kernel-aware swap should route through the Treasury Kernel instead.
pub fn token_swap(
    token_a: &mut TokenContract,
    token_b: &mut TokenContract,
    user: &PublicKey,
    amount_a: u64,
    amount_b: u64,
) -> Result<(u64, u64), String> {
    // Check balances
    if token_a.balance_of(user) < amount_a {
        return Err("Insufficient balance in token A".to_string());
    }
    if token_b.balance_of(user) < amount_b {
        return Err("Insufficient balance in token B".to_string());
    }
    
    // Burn tokens from user (simplified swap mechanism)
    token_a.burn(user, amount_a)?;
    token_b.burn(user, amount_b)?;
    
    // Mint swapped amounts (simplified)
    token_a.mint(user, amount_b)?;
    token_b.mint(user, amount_a)?;
    
    Ok((amount_a, amount_b))
}

// NOTE: create_time_lock() and TimeLock removed in Phase 3.
// These relied on the old transfer(from, to, amount) API.
// The new transfer(ctx, to, amount) API requires ExecutionContext for capability-bound authorization.
// Time-lock functionality should be reimplemented using the new transfer(ctx, to, amount) API.

// NOTE: Tests for transfer_tokens(), batch_transfer(), and transfer_from_allowance() removed in Phase 3.
// These tests relied on the old transfer(from, to, amount) API.
// Tests for the new transfer(ctx, to, amount) API with ExecutionContext should be added to the
// contract tests that call transfer through the new API.
