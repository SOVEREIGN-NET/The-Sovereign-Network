//! Multi-wallet management operations

use anyhow::Result;
use crate::wallets::{WalletManager, WalletType, WalletId, WalletSummary};

impl WalletManager {
    /// Create multiple wallets for a new citizen with HD derivation from master seed
    ///
    /// Uses a single master seed phrase to derive all 3 wallets:
    /// - Index 0 → Primary wallet
    /// - Index 1 → UBI wallet
    /// - Index 2 → Savings wallet
    ///
    /// Returns the master seed phrase and derivation indices for recovery.
    pub async fn create_citizen_wallets_with_hd_derivation(&mut self) -> Result<CitizenWalletSetHD> {
        // Generate master seed (64 bytes) for HD derivation
        let mut master_seed = [0u8; 64];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut master_seed);

        // Set master seed for HD derivation
        self.master_seed = Some(master_seed);
        self.next_derivation_index = 0;

        // Create HD wallets at fixed indices
        let (primary_id, _) = self.create_hd_wallet(
            WalletType::Primary,
            "Primary Wallet".to_string(),
            Some("primary".to_string()),
        ).await?;

        let (ubi_id, _) = self.create_hd_wallet(
            WalletType::UBI,
            "UBI Wallet".to_string(),
            Some("ubi".to_string()),
        ).await?;

        let (savings_id, _) = self.create_hd_wallet(
            WalletType::Savings,
            "Savings Wallet".to_string(),
            Some("savings".to_string()),
        ).await?;

        // Generate 24-word master seed phrase from first 32 bytes
        let master_seed_phrase = crate::recovery::RecoveryPhrase::from_entropy(&master_seed[..32])?;

        Ok(CitizenWalletSetHD {
            primary_wallet_id: primary_id,
            ubi_wallet_id: ubi_id,
            savings_wallet_id: savings_id,
            master_seed_phrase,
            derivation_indices: HdDerivationIndices {
                primary: 0,
                ubi: 1,
                savings: 2,
            },
        })
    }

    /// Get all wallet summaries grouped by type
    pub fn get_wallets_by_type_summary(&self) -> WalletTypeSummary {
        let mut primary_wallets = Vec::new();
        let mut ubi_wallets = Vec::new();
        let mut savings_wallets = Vec::new();
        let mut stealth_wallets = Vec::new();
        let mut standard_wallets = Vec::new();
        let mut business_wallets = Vec::new();
        let mut nonprofit_dao_wallets = Vec::new();
        let mut forprofit_dao_wallets = Vec::new();
        
        for wallet in self.wallets.values() {
            let summary = wallet.to_summary();
            match wallet.wallet_type {
                WalletType::Primary => primary_wallets.push(summary),
                WalletType::UBI => ubi_wallets.push(summary),
                WalletType::Savings => savings_wallets.push(summary),
                WalletType::Stealth => stealth_wallets.push(summary),
                WalletType::Standard => standard_wallets.push(summary),
                WalletType::Business => business_wallets.push(summary),
                WalletType::NonProfitDAO => nonprofit_dao_wallets.push(summary),
                WalletType::ForProfitDAO => forprofit_dao_wallets.push(summary),
            }
        }
        
        WalletTypeSummary {
            primary_wallets,
            ubi_wallets,
            savings_wallets,
            stealth_wallets,
            standard_wallets,
            business_wallets,
            nonprofit_dao_wallets,
            forprofit_dao_wallets,
        }
    }
    
    /// Get balance summary by wallet type
    pub fn get_balance_by_type(&self) -> WalletBalanceSummary {
        let mut balances = WalletBalanceSummary::default();
        
        for wallet in self.wallets.values() {
            match wallet.wallet_type {
                WalletType::Primary => balances.primary_balance += wallet.balance,
                WalletType::UBI => balances.ubi_balance += wallet.balance,
                WalletType::Savings => balances.savings_balance += wallet.balance,
                WalletType::Stealth => balances.stealth_balance += wallet.balance,
                WalletType::Standard => balances.standard_balance += wallet.balance,
                WalletType::Business => balances.business_balance += wallet.balance,
                WalletType::NonProfitDAO => balances.nonprofit_dao_balance += wallet.balance,
                WalletType::ForProfitDAO => balances.forprofit_dao_balance += wallet.balance,
            }
        }
        
        balances.total_balance = balances.primary_balance + 
                                balances.ubi_balance + 
                                balances.savings_balance + 
                                balances.stealth_balance + 
                                balances.standard_balance +
                                balances.business_balance +
                                balances.nonprofit_dao_balance +
                                balances.forprofit_dao_balance;
        
        balances
    }
}

/// Set of wallets created for a new citizen with HD derivation from master seed
///
/// This is the preferred struct for new citizen wallet creation.
/// All 3 wallets derive from a single master seed phrase.
#[derive(Debug, Clone)]
pub struct CitizenWalletSetHD {
    pub primary_wallet_id: WalletId,
    pub ubi_wallet_id: WalletId,
    pub savings_wallet_id: WalletId,
    /// Single master seed phrase (24 words) that derives all wallets
    pub master_seed_phrase: crate::recovery::RecoveryPhrase,
    /// Derivation indices for wallet recovery
    pub derivation_indices: HdDerivationIndices,
}

/// HD derivation indices for citizen wallets
#[derive(Debug, Clone)]
pub struct HdDerivationIndices {
    pub primary: u32,
    pub ubi: u32,
    pub savings: u32,
}

/// Summary of wallets grouped by type
#[derive(Debug, Clone)]
pub struct WalletTypeSummary {
    pub primary_wallets: Vec<WalletSummary>,
    pub ubi_wallets: Vec<WalletSummary>,
    pub savings_wallets: Vec<WalletSummary>,
    pub stealth_wallets: Vec<WalletSummary>,
    pub standard_wallets: Vec<WalletSummary>,
    pub business_wallets: Vec<WalletSummary>,
    pub nonprofit_dao_wallets: Vec<WalletSummary>,
    pub forprofit_dao_wallets: Vec<WalletSummary>,
}

/// Balance summary by wallet type
#[derive(Debug, Clone, Default)]
pub struct WalletBalanceSummary {
    pub primary_balance: u64,
    pub ubi_balance: u64,
    pub savings_balance: u64,
    pub stealth_balance: u64,
    pub standard_balance: u64,
    pub business_balance: u64,
    pub nonprofit_dao_balance: u64,
    pub forprofit_dao_balance: u64,
    pub total_balance: u64,
}

impl WalletTypeSummary {
    /// Get total wallet count across all types
    pub fn total_wallet_count(&self) -> usize {
        self.primary_wallets.len() + 
        self.ubi_wallets.len() + 
        self.savings_wallets.len() + 
        self.stealth_wallets.len() + 
        self.standard_wallets.len() +
        self.business_wallets.len() +
        self.nonprofit_dao_wallets.len() +
        self.forprofit_dao_wallets.len()
    }
    
    /// Get total DAO wallet count
    pub fn dao_wallet_count(&self) -> usize {
        self.nonprofit_dao_wallets.len() + self.forprofit_dao_wallets.len()
    }
    
    /// Check if citizen has required wallets
    pub fn has_citizen_wallets(&self) -> bool {
        !self.primary_wallets.is_empty() && 
        !self.ubi_wallets.is_empty() && 
        !self.savings_wallets.is_empty()
    }
}
