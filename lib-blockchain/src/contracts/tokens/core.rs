use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::executor::{ExecutionContext, CallOrigin};

/// Errors for token contract operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Caller is not authorized to perform this operation
    Unauthorized,
    /// Insufficient balance to perform transfer
    InsufficientBalance,
    /// Insufficient allowance for transfer_from
    InsufficientAllowance,
    /// Transfer would exceed maximum supply
    ExceedsMaxSupply,
    /// Insufficient balance to burn
    InsufficientBurn,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unauthorized => write!(f, "Unauthorized: not token owner"),
            Error::InsufficientBalance => write!(f, "Insufficient balance"),
            Error::InsufficientAllowance => write!(f, "Insufficient allowance"),
            Error::ExceedsMaxSupply => write!(f, "Would exceed maximum supply"),
            Error::InsufficientBurn => write!(f, "Insufficient balance to burn"),
        }
    }
}

/// Core token contract structure supporting both ZHTP native and custom tokens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenContract {
    /// Unique token identifier
    pub token_id: [u8; 32],
    /// Human-readable token name
    pub name: String,
    /// Token symbol (e.g., "ZHTP", "WHISPER")
    pub symbol: String,
    /// Number of decimal places
    pub decimals: u8,
    /// Current total supply in circulation
    pub total_supply: u64,
    /// Maximum supply that can ever exist
    pub max_supply: u64,
    /// Whether the token burns on transfer (deflationary)
    pub is_deflationary: bool,
    /// Amount burned per transfer (if deflationary)
    pub burn_rate: u64,
    /// Account balances mapping
    pub balances: HashMap<PublicKey, u64>,
    /// Allowances for third-party transfers
    pub allowances: HashMap<PublicKey, HashMap<PublicKey, u64>>,
    /// Token creator
    pub creator: PublicKey,
    /// Kernel minting authority (for UBI distribution)
    /// If set, only this kernel can mint tokens via mint_kernel_only()
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_mint_authority: Option<PublicKey>,
}

impl TokenContract {
    /// Create a new token contract
    pub fn new(
        token_id: [u8; 32],
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u64,
        is_deflationary: bool,
        burn_rate: u64,
        creator: PublicKey,
    ) -> Self {
        Self {
            token_id,
            name,
            symbol,
            decimals,
            total_supply: 0,
            max_supply,
            is_deflationary,
            burn_rate,
            balances: HashMap::new(),
            allowances: HashMap::new(),
            creator,
            kernel_mint_authority: None,
        }
    }

    /// Create ZHTP native token
    pub fn new_zhtp() -> Self {
        let creator = PublicKey::new(vec![0u8; 1312]); // Mock creator for ZHTP
        Self::new(
            crate::contracts::utils::generate_lib_token_id(),
            crate::contracts::ZHTP_TOKEN_NAME.to_string(),
            crate::contracts::ZHTP_TOKEN_SYMBOL.to_string(),
            crate::contracts::ZHTP_DECIMALS,
            crate::contracts::ZHTP_MAX_SUPPLY,
            false, // ZHTP is not deflationary
            0,     // No burn rate for ZHTP
            creator,
        )
    }

    /// Create SOV token with kernel minting authority
    ///
    /// This is used for UBI distribution. The token is created with a kernel
    /// authority, meaning only the Treasury Kernel can mint tokens via mint_kernel_only().
    ///
    /// # Arguments
    /// * `kernel_authority` - The public key of the Treasury Kernel (only entity that can mint)
    pub fn new_sov_with_kernel_authority(kernel_authority: PublicKey) -> Self {
        let creator = PublicKey::new(vec![0u8; 1312]); // Mock creator for SOV
        let mut token = Self::new(
            crate::contracts::utils::generate_lib_token_id(),
            "SOV Token".to_string(),
            "SOV".to_string(),
            8,
            1_000_000_000 * 100_000_000, // 1B SOV with 8 decimals
            false, // SOV is not deflationary
            0,     // No burn rate for SOV
            creator,
        );
        token.kernel_mint_authority = Some(kernel_authority);
        token
    }

    /// Create a custom token (for dApps)
    pub fn new_custom(
        name: String,
        symbol: String,
        initial_supply: u64,
        creator: PublicKey,
    ) -> Self {
        let token_id = crate::contracts::utils::generate_custom_token_id(&name, &symbol);
        let mut token = Self::new(
            token_id,
            name,
            symbol,
            8, // Default 8 decimals
            u64::MAX, // Very large max supply
            false, // Not deflationary by default
            0,     // No burn rate
            creator.clone(),
        );
        
        // Mint initial supply to creator
        if initial_supply > 0 {
            let _ = token.mint(&creator, initial_supply);
        }
        
        token
    }

    /// Get balance of an account
    pub fn balance_of(&self, account: &PublicKey) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// Get allowance for a spender
    pub fn allowance(&self, owner: &PublicKey, spender: &PublicKey) -> u64 {
        self.allowances
            .get(owner)
            .and_then(|spenders| spenders.get(spender))
            .copied()
            .unwrap_or(0)
    }

    /// Transfer tokens from the execution source to a recipient
    ///
    /// Authorization is determined by the execution context, not user input:
    /// - User calls: debit from ctx.caller
    /// - Contract calls: debit from ctx.contract
    ///
    /// This implements capability-bound authorization where token spending authority
    /// is exclusively derived from the immutable execution context, preventing parameter tampering.
    ///
    /// # Arguments
    /// - `ctx`: Immutable execution context providing authorization information
    /// - `to`: Recipient address (must not be zero)
    /// - `amount`: Amount to transfer
    ///
    /// # Errors
    /// - `Error::Unauthorized`: If call_origin is System (reserved)
    /// - `Error::InsufficientBalance`: If source account has insufficient balance
    pub fn transfer(&mut self, ctx: &ExecutionContext, to: &PublicKey, amount: u64) -> Result<u64, Error> {
        // Determine the source account based on execution context
        let source = match ctx.call_origin {
            CallOrigin::User => ctx.caller.clone(),
            CallOrigin::Contract => ctx.contract.clone(),
            CallOrigin::System => return Err(Error::Unauthorized),
        };

        // Check source balance
        let source_balance = self.balance_of(&source);
        if source_balance < amount {
            return Err(Error::InsufficientBalance);
        }

        // Calculate burn amount if deflationary
        let burn_amount = if self.is_deflationary {
            std::cmp::min(self.burn_rate, amount)
        } else {
            0
        };

        // Perform transfer
        self.balances.insert(source.clone(), source_balance - amount);
        let to_balance = self.balance_of(to);
        self.balances.insert(to.clone(), to_balance + amount);

        // Apply burn
        if burn_amount > 0 {
            self.total_supply = self.total_supply.saturating_sub(burn_amount);
        }

        Ok(burn_amount)
    }

    /// Transfer from an allowance using execution context-based authorization
    ///
    /// The spender is derived from the execution context (ctx.caller or ctx.contract),
    /// and the allowance is checked against the source account (derived from ctx) and the spender.
    ///
    /// # Arguments
    /// - `ctx`: Immutable execution context providing authorization information
    /// - `owner`: The account from which tokens should be transferred
    /// - `to`: Recipient address
    /// - `amount`: Amount to transfer
    ///
    /// # Errors
    /// - `Error::Unauthorized`: If execution context is invalid
    /// - `Error::InsufficientAllowance`: If spender doesn't have enough allowance from owner
    /// - `Error::InsufficientBalance`: If owner doesn't have enough balance
    pub fn transfer_from(
        &mut self,
        ctx: &ExecutionContext,
        owner: &PublicKey,
        to: &PublicKey,
        amount: u64,
    ) -> Result<u64, Error> {
        // Determine the spender from execution context
        let spender = match ctx.call_origin {
            CallOrigin::User => ctx.caller.clone(),
            CallOrigin::Contract => ctx.contract.clone(),
            CallOrigin::System => return Err(Error::Unauthorized),
        };

        // Check allowance from owner to spender
        let allowance = self.allowance(owner, &spender);
        if allowance < amount {
            return Err(Error::InsufficientAllowance);
        }

        // Reduce allowance
        self.allowances
            .entry(owner.clone())
            .or_insert_with(HashMap::new)
            .insert(spender.clone(), allowance - amount);

        // Perform transfer from owner to recipient
        //
        // **Design Note (Workaround for Allowance Pattern):**
        // The capability-bound transfer API requires either ctx.caller or ctx.contract as the source.
        // For transfer_from, we need owner as the source, not ctx.caller or ctx.contract.
        // We work around this by creating a temporary ExecutionContext with:
        // - owner as the pseudo-contract address (CallOrigin::Contract)
        // This makes transfer debit from owner (via the capability-bound logic).
        //
        // This approach is semantically unusual: owner's PublicKey is used as a contract address.
        // If transfer is enhanced with contract-specific logic in the future, this could have
        // unintended consequences. Consider refactoring to support allowance-based transfers
        // natively in the capability-bound model (e.g., add a dedicated transfer_from_allowed method).
        let transfer_ctx = ExecutionContext::with_contract(
            ctx.caller.clone(),
            owner.clone(), // Pseudo-contract: source will be owner via CallOrigin::Contract
            ctx.block_number,
            ctx.timestamp,
            ctx.gas_limit,
            ctx.tx_hash,
        );

        self.transfer(&transfer_ctx, to, amount)
    }

    /// Approve spending allowance
    pub fn approve(&mut self, owner: &PublicKey, spender: &PublicKey, amount: u64) {
        self.allowances
            .entry(owner.clone())
            .or_insert_with(HashMap::new)
            .insert(spender.clone(), amount);
    }

    /// Mint new tokens
    pub fn mint(&mut self, to: &PublicKey, amount: u64) -> Result<(), String> {
        if self.total_supply + amount > self.max_supply {
            return Err("Would exceed maximum supply".to_string());
        }

        let balance = self.balance_of(to);
        self.balances.insert(to.clone(), balance + amount);
        self.total_supply += amount;

        Ok(())
    }

    /// Mint tokens with kernel authority (UBI distribution only)
    ///
    /// This method is used exclusively by the Treasury Kernel for UBI distribution.
    /// Only the kernel specified at token creation can call this method.
    ///
    /// # Arguments
    /// * `caller` - The entity attempting to mint (must match kernel_mint_authority)
    /// * `to` - The recipient of the minted tokens
    /// * `amount` - The amount to mint
    ///
    /// # Errors
    /// * "Only Treasury Kernel can mint" - If caller is not the kernel authority
    /// * "Minting disabled" - If kernel_mint_authority was not set
    /// * "Would exceed maximum supply" - If amount would exceed max_supply
    pub fn mint_kernel_only(
        &mut self,
        caller: &PublicKey,
        to: &PublicKey,
        amount: u64,
    ) -> Result<(), String> {
        // Check kernel authority
        match &self.kernel_mint_authority {
            Some(authority) if caller == authority => {
                // Authorized - proceed with minting
            }
            Some(_) => return Err("Only Treasury Kernel can mint".to_string()),
            None => return Err("Minting disabled".to_string()),
        }

        // Check supply limit
        if self.total_supply + amount > self.max_supply {
            return Err("Would exceed maximum supply".to_string());
        }

        // Mint tokens
        let balance = self.balance_of(to);
        self.balances.insert(to.clone(), balance + amount);
        self.total_supply += amount;

        Ok(())
    }

    /// Burn tokens from an account
    pub fn burn(&mut self, from: &PublicKey, amount: u64) -> Result<(), String> {
        let balance = self.balance_of(from);
        if balance < amount {
            return Err("Insufficient balance to burn".to_string());
        }

        self.balances.insert(from.clone(), balance - amount);
        self.total_supply = self.total_supply.saturating_sub(amount);

        Ok(())
    }

    /// Check if supply can accommodate minting
    pub fn can_mint(&self, amount: u64) -> bool {
        self.total_supply + amount <= self.max_supply
    }

    /// Get remaining mintable supply
    pub fn remaining_supply(&self) -> u64 {
        self.max_supply.saturating_sub(self.total_supply)
    }

    /// Get token information as a summary
    pub fn info(&self) -> TokenInfo {
        TokenInfo {
            token_id: self.token_id,
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            decimals: self.decimals,
            total_supply: self.total_supply,
            max_supply: self.max_supply,
            is_deflationary: self.is_deflationary,
            burn_rate: self.burn_rate,
            creator: self.creator.clone(),
        }
    }

    /// Validate token parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Token name cannot be empty".to_string());
        }

        if self.symbol.is_empty() {
            return Err("Token symbol cannot be empty".to_string());
        }

        if self.symbol.len() > 10 {
            return Err("Token symbol too long (max 10 characters)".to_string());
        }

        if self.decimals > 18 {
            return Err("Too many decimal places (max 18)".to_string());
        }

        if self.max_supply == 0 {
            return Err("Maximum supply must be greater than 0".to_string());
        }

        if self.total_supply > self.max_supply {
            return Err("Total supply cannot exceed maximum supply".to_string());
        }

        if self.is_deflationary && self.burn_rate == 0 {
            return Err("Deflationary token must have burn rate > 0".to_string());
        }

        Ok(())
    }

    /// Get the total number of holders
    pub fn holder_count(&self) -> usize {
        self.balances.iter().filter(|(_, &balance)| balance > 0).count()
    }

    /// Calculate market cap (requires external price data)
    pub fn market_cap(&self, price_per_token: f64) -> f64 {
        (self.total_supply as f64 / 10f64.powi(self.decimals as i32)) * price_per_token
    }
}

/// Token information structure for queries
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    pub token_id: [u8; 32],
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub max_supply: u64,
    pub is_deflationary: bool,
    pub burn_rate: u64,
    pub creator: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::executor::{ExecutionContext, CallOrigin};

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    fn create_test_execution_context(contract: PublicKey, caller: PublicKey) -> ExecutionContext {
        ExecutionContext::with_contract(
            caller,
            contract,
            1,           // block_number
            1000,        // timestamp
            100000,      // gas_limit
            [1u8; 32],   // tx_hash
        )
    }

    #[test]
    fn test_token_creation() {
        let public_key = create_test_public_key(1);
        let token = TokenContract::new_custom(
            "Test Token".to_string(),
            "TEST".to_string(),
            100_000_000, // 1M with 8 decimals
            public_key.clone(),
        );

        assert_eq!(token.name, "Test Token");
        assert_eq!(token.symbol, "TEST");
        assert_eq!(token.decimals, 8);
        assert!(!token.is_deflationary);
        assert_eq!(token.creator, public_key);
        assert_eq!(token.total_supply, 100_000_000);
    }

    #[test]
    fn test_lib_token_creation() {
        let token = TokenContract::new_zhtp();

        assert_eq!(token.name, "ZHTP");
        assert_eq!(token.symbol, "ZHTP");
        assert_eq!(token.decimals, 8);
        assert_eq!(token.max_supply, crate::contracts::ZHTP_MAX_SUPPLY);
        assert!(!token.is_deflationary);
        assert_eq!(token.burn_rate, 0);
    }

    #[test]
    fn test_minting() {
        let public_key = create_test_public_key(1);
        let mut token = TokenContract::new_custom(
            "Mint Token".to_string(),
            "MINT".to_string(),
            0, // Start with 0 supply
            public_key.clone(),
        );

        assert!(token.can_mint(500));
        assert!(token.mint(&public_key, 500).is_ok());
        assert_eq!(token.total_supply, 500);
        assert_eq!(token.balance_of(&public_key), 500);
    }

    #[test]
    fn test_transfer() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let mut token = TokenContract::new(
            [0u8; 32], // token_id
            "Transfer Token".to_string(),
            "XFER".to_string(),
            8,      // decimals
            10000,  // max_supply
            false,  // is_deflationary
            0,      // burn_rate
            public_key1.clone(),
        );

        // Mint some tokens
        token.mint(&public_key1, 500).unwrap();

        // Transfer using ExecutionContext
        let ctx = create_test_execution_context(public_key1.clone(), public_key1.clone());
        let burn_amount = token.transfer(&ctx, &public_key2, 200).unwrap();
        assert_eq!(burn_amount, 0); // Non-deflationary
        assert_eq!(token.balance_of(&public_key1), 300);
        assert_eq!(token.balance_of(&public_key2), 200);

        // Test insufficient balance - try to transfer 301 tokens from public_key1
        // (ctx has public_key1 as contract via CallOrigin::Contract, so debit comes from public_key1)
        // public_key1 only has 300 tokens left, so transfer of 301 should fail
        assert!(token.transfer(&ctx, &public_key1, 301).is_err());
    }

    #[test]
    fn test_deflationary_transfer() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let mut token = TokenContract::new(
            [0u8; 32], // token_id
            "Burn Token".to_string(),
            "BURN".to_string(),
            8,      // decimals
            10000,  // max_supply
            true,   // is_deflationary
            10,     // burn_rate (10%)
            public_key1.clone(),
        );

        token.mint(&public_key1, 500).unwrap();
        let initial_supply = token.total_supply;

        let ctx = create_test_execution_context(public_key1.clone(), public_key1.clone());
        let burn_amount = token.transfer(&ctx, &public_key2, 100).unwrap();
        assert_eq!(burn_amount, 10);
        assert_eq!(token.total_supply, initial_supply - 10);
    }

    #[test]
    fn test_allowances() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let public_key3 = create_test_public_key(3);
        let mut token = TokenContract::new_custom(
            "Allowance Token".to_string(),
            "ALLOW".to_string(),
            1000,
            public_key1.clone(),
        );

        token.mint(&public_key1, 500).unwrap();

        // Approve allowance
        token.approve(&public_key1, &public_key2, 100);
        assert_eq!(token.allowance(&public_key1, &public_key2), 100);

        // Transfer from allowance using ExecutionContext
        let ctx = create_test_execution_context(public_key2.clone(), public_key2.clone());
        let burn_amount = token.transfer_from(
            &ctx,
            &public_key1,
            &public_key3,
            50,
        ).unwrap();
        assert_eq!(burn_amount, 0);
        assert_eq!(token.balance_of(&public_key3), 50);
        assert_eq!(token.allowance(&public_key1, &public_key2), 50);

        // Test insufficient allowance
        assert!(token.transfer_from(
            &ctx,
            &public_key1,
            &public_key3,
            100,
        ).is_err());
    }

    #[test]
    fn test_burning() {
        let public_key = create_test_public_key(1);
        let mut token = TokenContract::new(
            [0u8; 32], // token_id
            "Burnable Token".to_string(),
            "BURNABLE".to_string(),
            8,      // decimals
            10000,  // max_supply
            false,  // is_deflationary
            0,      // burn_rate
            public_key.clone(),
        );

        token.mint(&public_key, 500).unwrap();
        let initial_supply = token.total_supply;

        assert!(token.burn(&public_key, 100).is_ok());
        assert_eq!(token.balance_of(&public_key), 400);
        assert_eq!(token.total_supply, initial_supply - 100);

        // Test insufficient balance for burning
        assert!(token.burn(&public_key, 500).is_err());
    }

    #[test]
    fn test_token_validation() {
        let public_key = create_test_public_key(1);

        // Valid token
        let valid_token = TokenContract::new_custom(
            "Valid Token".to_string(),
            "VALID".to_string(),
            1000,
            public_key.clone(),
        );
        assert!(valid_token.validate().is_ok());

        // Empty name
        let invalid_token = TokenContract::new_custom(
            "".to_string(),
            "INVALID".to_string(),
            1000,
            public_key.clone(),
        );
        assert!(invalid_token.validate().is_err());

        // Empty symbol should fail validation
        let invalid_token = TokenContract::new_custom(
            "Valid Name".to_string(),
            "".to_string(), // Empty symbol
            1000,
            public_key.clone(),
        );
        assert!(invalid_token.validate().is_err());
    }

    #[test]
    fn test_new_sov_with_kernel_authority() {
        let kernel_addr = create_test_public_key(10);
        let token = TokenContract::new_sov_with_kernel_authority(kernel_addr.clone());

        assert_eq!(token.name, "SOV Token");
        assert_eq!(token.symbol, "SOV");
        assert_eq!(token.decimals, 8);
        assert!(!token.is_deflationary);
        assert_eq!(token.kernel_mint_authority, Some(kernel_addr));
    }

    #[test]
    fn test_mint_kernel_only_authorized() {
        let kernel_addr = create_test_public_key(10);
        let recipient = create_test_public_key(20);
        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_addr.clone());

        // Authorized minting should succeed
        let result = token.mint_kernel_only(&kernel_addr, &recipient, 1000);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&recipient), 1000);
        assert_eq!(token.total_supply, 1000);
    }

    #[test]
    fn test_mint_kernel_only_unauthorized() {
        let kernel_addr = create_test_public_key(10);
        let unauthorized = create_test_public_key(15);
        let recipient = create_test_public_key(20);
        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_addr);

        // Unauthorized minting should fail
        let result = token.mint_kernel_only(&unauthorized, &recipient, 1000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Only Treasury Kernel can mint".to_string()
        );
        assert_eq!(token.balance_of(&recipient), 0);
    }

    #[test]
    fn test_mint_kernel_only_no_authority() {
        let regular_token = TokenContract::new_custom(
            "Regular Token".to_string(),
            "REG".to_string(),
            1000,
            create_test_public_key(1),
        );
        let mut token = regular_token;
        let caller = create_test_public_key(10);
        let recipient = create_test_public_key(20);

        // Minting without authority should fail
        let result = token.mint_kernel_only(&caller, &recipient, 1000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Minting disabled".to_string());
    }

    #[test]
    fn test_mint_kernel_only_exceeds_supply() {
        let kernel_addr = create_test_public_key(10);
        let recipient = create_test_public_key(20);

        let mut token = TokenContract::new(
            [1u8; 32],
            "Limited Token".to_string(),
            "LIM".to_string(),
            8,
            1000, // Only 1000 max supply
            false,
            0,
            create_test_public_key(1),
        );
        token.kernel_mint_authority = Some(kernel_addr.clone());

        // Minting within limit should succeed
        assert!(token.mint_kernel_only(&kernel_addr, &recipient, 500).is_ok());

        // Minting beyond limit should fail
        let result = token.mint_kernel_only(&kernel_addr, &recipient, 600);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Would exceed maximum supply".to_string()
        );
    }

    #[test]
    fn test_mint_kernel_only_multiple_recipients() {
        let kernel_addr = create_test_public_key(10);
        let recipient1 = create_test_public_key(20);
        let recipient2 = create_test_public_key(21);
        let recipient3 = create_test_public_key(22);

        let mut token = TokenContract::new_sov_with_kernel_authority(kernel_addr.clone());

        // Mint to multiple recipients
        assert!(token.mint_kernel_only(&kernel_addr, &recipient1, 1000).is_ok());
        assert!(token.mint_kernel_only(&kernel_addr, &recipient2, 2000).is_ok());
        assert!(token.mint_kernel_only(&kernel_addr, &recipient3, 3000).is_ok());

        assert_eq!(token.balance_of(&recipient1), 1000);
        assert_eq!(token.balance_of(&recipient2), 2000);
        assert_eq!(token.balance_of(&recipient3), 3000);
        assert_eq!(token.total_supply, 6000);
    }

    #[test]
    fn test_kernel_authority_field_serialization() {
        let kernel_addr = create_test_public_key(10);
        let token = TokenContract::new_sov_with_kernel_authority(kernel_addr.clone());

        // Test serialization and deserialization
        let serialized = bincode::serialize(&token).expect("serialize");
        let deserialized: TokenContract =
            bincode::deserialize(&serialized).expect("deserialize");

        assert_eq!(deserialized.kernel_mint_authority, Some(kernel_addr));
        assert_eq!(deserialized.name, "SOV Token");
    }
}
