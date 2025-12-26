//! Pure wallet operation logic
//!
//! Handles wallet validation, metadata, and business rules.
//! No side effects - all functions are pure.

use crate::error::{CliError, CliResult};
use regex::Regex;

/// Wallet metadata
#[derive(Debug, Clone)]
pub struct WalletMetadata {
    pub name: String,
    pub wallet_type: String,
    pub balance: u64,
    pub created_at: u64,
    pub is_active: bool,
}

/// Supported wallet types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletType {
    Standard,
    MultiSig,
    Hardware,
}

impl WalletType {
    pub fn as_str(&self) -> &str {
        match self {
            WalletType::Standard => "standard",
            WalletType::MultiSig => "multisig",
            WalletType::Hardware => "hardware",
        }
    }

    pub fn from_str(s: &str) -> CliResult<Self> {
        match s.to_lowercase().as_str() {
            "standard" => Ok(WalletType::Standard),
            "multisig" => Ok(WalletType::MultiSig),
            "hardware" => Ok(WalletType::Hardware),
            other => Err(CliError::WalletError(format!(
                "Unknown wallet type: '{}'. Supported: standard, multisig, hardware",
                other
            ))),
        }
    }
}

/// Validate wallet name
///
/// Wallet names must:
/// - Be 3-64 characters
/// - Start with alphanumeric
/// - Contain only alphanumeric, dash, underscore
pub fn validate_wallet_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::WalletError(
            "Wallet name cannot be empty".to_string(),
        ));
    }

    if name.len() < 3 {
        return Err(CliError::WalletError(
            "Wallet name must be at least 3 characters".to_string(),
        ));
    }

    if name.len() > 64 {
        return Err(CliError::WalletError(
            "Wallet name must not exceed 64 characters".to_string(),
        ));
    }

    // Must start with alphanumeric
    if !name.chars().next().unwrap().is_alphanumeric() {
        return Err(CliError::WalletError(
            "Wallet name must start with alphanumeric character".to_string(),
        ));
    }

    // Only allow alphanumeric, dash, underscore
    let valid_pattern = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$").unwrap();
    if !valid_pattern.is_match(name) {
        return Err(CliError::WalletError(
            "Wallet name can only contain alphanumeric characters, dashes, and underscores"
                .to_string(),
        ));
    }

    Ok(())
}

/// Validate wallet type
pub fn validate_wallet_type(wallet_type: &str) -> CliResult<()> {
    WalletType::from_str(wallet_type)?;
    Ok(())
}

/// Calculate minimum transaction fee
///
/// Pure function based on transaction size
pub fn calculate_min_fee(transaction_size: u64) -> u64 {
    // Base fee: 1000 satoshis
    // Plus 10 satoshis per byte
    let base_fee = 1000u64;
    let per_byte_fee = 10u64;
    base_fee + (transaction_size * per_byte_fee)
}

/// Validate transaction amount
pub fn validate_transaction_amount(amount: u64) -> CliResult<()> {
    if amount == 0 {
        return Err(CliError::WalletError(
            "Transaction amount must be greater than 0".to_string(),
        ));
    }

    // Max transaction amount: 21,000,000 ZHTP (in satoshis)
    const MAX_AMOUNT: u64 = 21_000_000_00_000_000;
    if amount > MAX_AMOUNT {
        return Err(CliError::WalletError(format!(
            "Transaction amount exceeds maximum of {}",
            MAX_AMOUNT
        )));
    }

    Ok(())
}

/// Validate wallet address format
pub fn validate_wallet_address(address: &str) -> CliResult<()> {
    if address.is_empty() {
        return Err(CliError::WalletError(
            "Wallet address cannot be empty".to_string(),
        ));
    }

    // ZHTP addresses start with 'z' and are 34-42 characters
    if !address.starts_with('z') {
        return Err(CliError::WalletError(
            "Wallet address must start with 'z'".to_string(),
        ));
    }

    if address.len() < 34 || address.len() > 42 {
        return Err(CliError::WalletError(
            "Wallet address must be 34-42 characters".to_string(),
        ));
    }

    Ok(())
}

/// Check if balance is sufficient for transaction
pub fn is_balance_sufficient(balance: u64, amount: u64, fee: u64) -> bool {
    balance >= amount + fee
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_wallet_name_valid() {
        assert!(validate_wallet_name("main-wallet").is_ok());
        assert!(validate_wallet_name("wallet_1").is_ok());
        assert!(validate_wallet_name("MyWallet").is_ok());
    }

    #[test]
    fn test_validate_wallet_name_too_short() {
        assert!(validate_wallet_name("ab").is_err());
    }

    #[test]
    fn test_validate_wallet_name_too_long() {
        let name = "a".repeat(65);
        assert!(validate_wallet_name(&name).is_err());
    }

    #[test]
    fn test_validate_wallet_type_valid() {
        assert!(validate_wallet_type("standard").is_ok());
        assert!(validate_wallet_type("multisig").is_ok());
        assert!(validate_wallet_type("hardware").is_ok());
    }

    #[test]
    fn test_validate_wallet_type_invalid() {
        assert!(validate_wallet_type("invalid").is_err());
    }

    #[test]
    fn test_calculate_min_fee() {
        let fee = calculate_min_fee(100);
        assert_eq!(fee, 1000 + (100 * 10));
    }

    #[test]
    fn test_validate_transaction_amount_valid() {
        assert!(validate_transaction_amount(1000).is_ok());
        assert!(validate_transaction_amount(1_000_000).is_ok());
    }

    #[test]
    fn test_validate_transaction_amount_zero() {
        assert!(validate_transaction_amount(0).is_err());
    }

    #[test]
    fn test_validate_wallet_address_valid() {
        assert!(validate_wallet_address("zaddr1234567890abcdefghijklmnopqrst").is_ok());
    }

    #[test]
    fn test_validate_wallet_address_wrong_prefix() {
        assert!(validate_wallet_address("taddr1234567890abcdefghijklmnopqrst").is_err());
    }

    #[test]
    fn test_validate_wallet_address_too_short() {
        assert!(validate_wallet_address("zaddr").is_err());
    }

    #[test]
    fn test_is_balance_sufficient() {
        assert!(is_balance_sufficient(1000, 500, 100));
        assert!(!is_balance_sufficient(600, 500, 100));
    }

    #[test]
    fn test_wallet_type_as_str() {
        assert_eq!(WalletType::Standard.as_str(), "standard");
        assert_eq!(WalletType::MultiSig.as_str(), "multisig");
    }
}
