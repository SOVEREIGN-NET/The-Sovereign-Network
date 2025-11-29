use super::core::{TokenContract, TokenInfo};
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::utils;
use std::collections::HashMap;

/// Token operation functions for contract system integration

/// Transfer tokens between accounts
pub fn transfer_tokens(
    contract: &mut TokenContract,
    from: &PublicKey,
    to: &PublicKey,
    amount: u64,
) -> Result<u64, String> {
    contract.transfer(from, to, amount)
}

/// Transfer tokens using allowance
pub fn transfer_from_allowance(
    contract: &mut TokenContract,
    owner: &PublicKey,
    to: &PublicKey,
    amount: u64,
    spender: &PublicKey,
) -> Result<u64, String> {
    contract.transfer_from(owner, to, amount, spender)
}

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
pub fn mint_tokens(
    contract: &mut TokenContract,
    to: &PublicKey,
    amount: u64,
) -> Result<(), String> {
    contract.mint(to, amount)
}

/// Burn tokens from account
pub fn burn_tokens(
    contract: &mut TokenContract,
    from: &PublicKey,
    amount: u64,
) -> Result<(), String> {
    contract.burn(from, amount)
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

/// Batch transfer to multiple recipients
pub fn batch_transfer(
    contract: &mut TokenContract,
    from: &PublicKey,
    transfers: Vec<(PublicKey, u64)>,
) -> Result<Vec<u64>, String> {
    let mut burn_amounts = Vec::new();
    let total_amount: u64 = transfers.iter().map(|(_, amount)| amount).sum();
    
    // Check if sender has enough balance for all transfers
    if contract.balance_of(from) < total_amount {
        return Err("Insufficient balance for batch transfer".to_string());
    }
    
    // Execute all transfers
    for (to, amount) in transfers {
        let burn_amount = contract.transfer(from, &to, amount)?;
        burn_amounts.push(burn_amount);
    }
    
    Ok(burn_amounts)
}

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

/// Create a time-locked token release
pub fn create_time_lock(
    contract: &mut TokenContract,
    from: &PublicKey,
    to: &PublicKey,
    amount: u64,
    unlock_time: u64, // timestamp
) -> Result<TimeLock, String> {
    // Transfer tokens to contract (simplified - in reality would use escrow)
    let burn_amount = contract.transfer(from, to, amount)?;
    
    Ok(TimeLock {
        from: from.clone(),
        to: to.clone(),
        amount,
        unlock_time,
        is_claimed: false,
        burn_amount,
    })
}

/// Time lock structure for delayed token releases
#[derive(Debug, Clone)]
pub struct TimeLock {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub unlock_time: u64,
    pub is_claimed: bool,
    pub burn_amount: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::tokens::core::TokenContract;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    #[test]
    fn test_token_functions() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let mut token = create_custom_token(
            "Test Token".to_string(),
            "TEST".to_string(),
            1000,
            public_key1.clone(),
        );

        // Test balance functions
        assert_eq!(get_balance(&token, &public_key1), 1000);
        assert_eq!(get_balance(&token, &public_key2), 0);

        // Test transfer
        let burn_amount = transfer_tokens(&mut token, &public_key1, &public_key2, 100).unwrap();
        assert_eq!(burn_amount, 0);
        assert_eq!(get_balance(&token, &public_key1), 900);
        assert_eq!(get_balance(&token, &public_key2), 100);

        // Test validation
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_deflationary_token_creation() {
        let public_key = create_test_public_key(1);
        let token = create_deflationary_token(
            "Burn Token".to_string(),
            "BURN".to_string(),
            8,      // decimals
            10000,  // max_supply
            50,     // burn_rate
            1000,   // initial_supply
            public_key.clone(),
        );

        assert!(token.is_deflationary);
        assert_eq!(token.burn_rate, 50);
        assert_eq!(get_balance(&token, &public_key), 1000);
    }

    #[test]
    fn test_batch_transfer() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let public_key3 = create_test_public_key(3);
        let mut token = create_custom_token(
            "Batch Token".to_string(),
            "BATCH".to_string(),
            1000,
            public_key1.clone(),
        );

        let transfers = vec![
            (public_key2.clone(), 100),
            (public_key3.clone(), 200),
        ];

        let burn_amounts = batch_transfer(&mut token, &public_key1, transfers).unwrap();
        assert_eq!(burn_amounts.len(), 2);
        assert_eq!(get_balance(&token, &public_key1), 700);
        assert_eq!(get_balance(&token, &public_key2), 100);
        assert_eq!(get_balance(&token, &public_key3), 200);
    }

    #[test]
    fn test_distribution_stats() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let mut token = create_custom_token(
            "Stats Token".to_string(),
            "STATS".to_string(),
            1000,
            public_key1.clone(),
        );

        // Transfer some tokens to create distribution
        transfer_tokens(&mut token, &public_key1, &public_key2, 200).unwrap();

        let stats = get_distribution_stats(&token);
        assert_eq!(stats.total_holders, 2);
        assert_eq!(stats.largest_balance, 800);
        assert_eq!(stats.smallest_balance, 200);
        assert_eq!(stats.total_supply, 1000);
        assert_eq!(stats.concentration_percentage, 80.0);
    }

    #[test]
    fn test_allowance_functions() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let public_key3 = create_test_public_key(3);
        let mut token = create_custom_token(
            "Allow Token".to_string(),
            "ALLOW".to_string(),
            1000,
            public_key1.clone(),
        );

        // Test approval
        approve_spending(&mut token, &public_key1, &public_key2, 500);
        assert_eq!(get_allowance(&token, &public_key1, &public_key2), 500);

        // Test transfer from allowance
        let burn_amount = transfer_from_allowance(
            &mut token,
            &public_key1,
            &public_key3,
            100,
            &public_key2,
        ).unwrap();
        
        assert_eq!(burn_amount, 0);
        assert_eq!(get_balance(&token, &public_key3), 100);
        assert_eq!(get_allowance(&token, &public_key1, &public_key2), 400);
    }
}
