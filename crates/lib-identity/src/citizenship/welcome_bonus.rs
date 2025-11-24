//! Welcome bonus for new citizens from the original identity.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::types::IdentityId;
use crate::wallets::WalletId;
use crate::economics::{EconomicModel, Transaction, TransactionType, Priority};

/// Welcome bonus for new citizens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeBonus {
    /// Citizen's identity ID
    pub identity_id: IdentityId,
    /// Wallet receiving the bonus
    pub wallet_id: WalletId,
    /// Bonus amount (5000 ZHTP)
    pub bonus_amount: u64,
    /// Welcome bonus transaction
    pub bonus_tx: Transaction,
    /// Bonus authenticity proof
    pub bonus_proof: [u8; 32],
    /// Bonus granted timestamp
    pub granted_at: u64,
}

impl WelcomeBonus {
    /// Create a new welcome bonus
    pub fn new(
        identity_id: IdentityId,
        wallet_id: WalletId,
        bonus_amount: u64,
        bonus_tx: Transaction,
        bonus_proof: [u8; 32],
        granted_at: u64,
    ) -> Self {
        Self {
            identity_id,
            wallet_id,
            bonus_amount,
            bonus_tx,
            bonus_proof,
            granted_at,
        }
    }
    
    /// Provide welcome bonus to new citizens - IMPLEMENTATION FROM ORIGINAL
    pub async fn provide_welcome_bonus(
        identity_id: &IdentityId,
        wallet_id: &WalletId,
        economic_model: &mut EconomicModel,
    ) -> Result<Self> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Welcome bonus: 5000 ZHTP tokens to get started
        let bonus_amount = 5000u64;

        // Create welcome bonus transaction
        let bonus_tx = Transaction::new(
            [0u8; 32], // Treasury
            identity_id.0,
            bonus_amount,
            TransactionType::Reward,
            economic_model,
            64, // Transaction size
            Priority::High, // Priority for new citizens
        )?;

        // Generate bonus proof
        let bonus_proof = lib_crypto::hash_blake3(
            &[
                "welcome_bonus".as_bytes(),
                identity_id.0.as_slice(),
                &bonus_amount.to_le_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        );

        tracing::info!(
            "🎁 WELCOME BONUS: Citizen {} received {} ZHTP tokens",
            hex::encode(&identity_id.0[..8]),
            bonus_amount
        );

        Ok(Self::new(
            identity_id.clone(),
            wallet_id.clone(),
            bonus_amount,
            bonus_tx,
            bonus_proof,
            current_time,
        ))
    }

    
    /// Check if bonus is valid
    pub fn is_valid(&self) -> bool {
        self.bonus_amount > 0 && 
        !self.bonus_proof.is_empty() &&
        self.granted_at > 0
    }
    
    /// Get bonus age in seconds
    pub fn bonus_age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.granted_at)
    }
    
    /// Get days since bonus was granted
    pub fn days_since_granted(&self) -> u64 {
        self.bonus_age_seconds() / (24 * 3600)
    }
    
    /// Verify bonus authenticity
    pub fn verify_bonus_proof(&self) -> bool {
        let expected_proof = lib_crypto::hash_blake3(
            &[
                "welcome_bonus".as_bytes(),
                self.identity_id.0.as_slice(),
                &self.bonus_amount.to_le_bytes(),
                &self.granted_at.to_le_bytes(),
            ].concat()
        );
        
        self.bonus_proof == expected_proof
    }
    
    /// Get bonus summary
    pub fn get_summary(&self) -> WelcomeBonusSummary {
        WelcomeBonusSummary {
            identity_id: self.identity_id.clone(),
            wallet_id: self.wallet_id.clone(),
            bonus_amount: self.bonus_amount,
            granted_at: self.granted_at,
            days_since_granted: self.days_since_granted(),
            is_verified: self.verify_bonus_proof(),
        }
    }
}

/// Welcome bonus summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeBonusSummary {
    pub identity_id: IdentityId,
    pub wallet_id: WalletId,
    pub bonus_amount: u64,
    pub granted_at: u64,
    pub days_since_granted: u64,
    pub is_verified: bool,
}
