//! Multi-wallet management operations

use crate::wallets::{WalletManager, WalletSummary, WalletType};

impl WalletManager {
    /// Get all wallet summaries grouped by type
    pub fn get_wallets_by_type_summary(&self) -> WalletTypeSummary {
        let mut primary_wallets = Vec::new();
        let mut stealth_wallets = Vec::new();
        let mut standard_wallets = Vec::new();
        let mut business_wallets = Vec::new();
        let mut nonprofit_dao_wallets = Vec::new();
        let mut forprofit_dao_wallets = Vec::new();

        for wallet in self.wallets.values() {
            let summary = wallet.to_summary();
            match wallet.wallet_type {
                WalletType::Primary => primary_wallets.push(summary),
                WalletType::Stealth => stealth_wallets.push(summary),
                WalletType::Standard => standard_wallets.push(summary),
                WalletType::Business => business_wallets.push(summary),
                WalletType::NonProfitDAO => nonprofit_dao_wallets.push(summary),
                WalletType::ForProfitDAO => forprofit_dao_wallets.push(summary),
            }
        }

        WalletTypeSummary {
            primary_wallets,
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
                WalletType::Stealth => balances.stealth_balance += wallet.balance,
                WalletType::Standard => balances.standard_balance += wallet.balance,
                WalletType::Business => balances.business_balance += wallet.balance,
                WalletType::NonProfitDAO => balances.nonprofit_dao_balance += wallet.balance,
                WalletType::ForProfitDAO => balances.forprofit_dao_balance += wallet.balance,
            }
        }

        balances.total_balance = balances.primary_balance
            + balances.stealth_balance
            + balances.standard_balance
            + balances.business_balance
            + balances.nonprofit_dao_balance
            + balances.forprofit_dao_balance;

        balances
    }
}

/// Summary of wallets grouped by type
#[derive(Debug, Clone)]
pub struct WalletTypeSummary {
    pub primary_wallets: Vec<WalletSummary>,
    pub stealth_wallets: Vec<WalletSummary>,
    pub standard_wallets: Vec<WalletSummary>,
    pub business_wallets: Vec<WalletSummary>,
    pub nonprofit_dao_wallets: Vec<WalletSummary>,
    pub forprofit_dao_wallets: Vec<WalletSummary>,
}

/// Balance summary by wallet type
#[derive(Debug, Clone, Default)]
pub struct WalletBalanceSummary {
    pub primary_balance: u128,
    pub stealth_balance: u128,
    pub standard_balance: u128,
    pub business_balance: u128,
    pub nonprofit_dao_balance: u128,
    pub forprofit_dao_balance: u128,
    pub total_balance: u128,
}

impl WalletTypeSummary {
    /// Get total wallet count across all types
    pub fn total_wallet_count(&self) -> usize {
        self.primary_wallets.len()
            + self.stealth_wallets.len()
            + self.standard_wallets.len()
            + self.business_wallets.len()
            + self.nonprofit_dao_wallets.len()
            + self.forprofit_dao_wallets.len()
    }

    /// Get total DAO wallet count
    pub fn dao_wallet_count(&self) -> usize {
        self.nonprofit_dao_wallets.len() + self.forprofit_dao_wallets.len()
    }

    /// Check if citizen has required wallets
    pub fn has_citizen_wallets(&self) -> bool {
        !self.primary_wallets.is_empty()
    }
}
