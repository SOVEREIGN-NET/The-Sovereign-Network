//! UBI registration system from the original identity.rs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::types::IdentityId;
use crate::wallets::WalletId;
use crate::economics::{EconomicModel, Transaction, TransactionType, Priority};

/// UBI registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiRegistration {
    /// Citizen's identity ID
    pub identity_id: IdentityId,
    /// UBI wallet ID for automatic payouts
    pub ubi_wallet_id: WalletId,
    /// UBI registration transaction
    pub registration_tx: Transaction,
    /// Daily UBI amount (~33 ZHTP)
    pub daily_amount: u64,
    /// Monthly UBI amount (1000 ZHTP)
    pub monthly_amount: u64,
    /// UBI eligibility proof
    pub eligibility_proof: [u8; 32],
    /// Registration timestamp
    pub registered_at: u64,
    /// Last UBI payout timestamp
    pub last_payout: Option<u64>,
    /// Total UBI received to date
    pub total_received: u64,
}

impl UbiRegistration {
    /// Create a new UBI registration
    pub fn new(
        identity_id: IdentityId,
        ubi_wallet_id: WalletId,
        registration_tx: Transaction,
        daily_amount: u64,
        monthly_amount: u64,
        eligibility_proof: [u8; 32],
        registered_at: u64,
        last_payout: Option<u64>,
        total_received: u64,
    ) -> Self {
        Self {
            identity_id,
            ubi_wallet_id,
            registration_tx,
            daily_amount,
            monthly_amount,
            eligibility_proof,
            registered_at,
            last_payout,
            total_received,
        }
    }
    
    /// Register identity for Universal Basic Income payouts - IMPLEMENTATION FROM ORIGINAL
    pub async fn register_for_ubi_payouts(
        identity_id: &IdentityId,
        ubi_wallet_id: &WalletId,
        economic_model: &mut EconomicModel,
    ) -> Result<Self> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Calculate monthly UBI amount (1000 ZHTP tokens per month)
        let monthly_ubi_amount = 1000u64;
        let daily_ubi_amount = monthly_ubi_amount / 30; // ~33 ZHTP per day

        // Create UBI registration transaction
        let ubi_tx = Transaction::new(
            [0u8; 32], // UBI treasury
            identity_id.0,
            0, // No cost to register for UBI
            TransactionType::UbiDistribution,
            economic_model,
            128, // Transaction size
            Priority::Normal,
        )?;

        // Generate UBI eligibility proof
        let eligibility_proof = lib_crypto::hash_blake3(
            &[
                identity_id.0.as_slice(),
                ubi_wallet_id.0.as_slice(),
                &daily_ubi_amount.to_le_bytes(),
                &current_time.to_le_bytes(),
            ].concat()
        );

        tracing::info!(
            "UBI REGISTERED: Citizen {} eligible for {} ZHTP daily ({} ZHTP monthly)",
            hex::encode(&identity_id.0[..8]),
            daily_ubi_amount,
            monthly_ubi_amount
        );

        Ok(Self::new(
            identity_id.clone(),
            ubi_wallet_id.clone(),
            ubi_tx,
            daily_ubi_amount,
            monthly_ubi_amount,
            eligibility_proof,
            current_time,
            None,
            0,
        ))
    }
    
    /// Check if eligible for UBI payout
    pub fn is_eligible_for_payout(&self) -> bool {
        self.eligibility_proof != [0u8; 32] && self.daily_amount > 0
    }
    
    /// Check if due for daily payout
    pub fn is_due_for_daily_payout(&self) -> bool {
        if let Some(last_payout) = self.last_payout {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // Check if 24 hours have passed since last payout
            now - last_payout >= 24 * 3600
        } else {
            // Never received payout, eligible immediately
            true
        }
    }
    
    /// Record a UBI payout
    pub fn record_payout(&mut self, amount: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.last_payout = Some(now);
        self.total_received += amount;
    }
    
    /// Get days since registration
    pub fn days_since_registration(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (now - self.registered_at) / (24 * 3600)
    }
    
    /// Calculate expected total UBI based on days since registration
    pub fn expected_total_ubi(&self) -> u64 {
        self.days_since_registration() * self.daily_amount
    }
    
    /// Check if citizen is up to date with UBI payouts
    pub fn is_ubi_up_to_date(&self) -> bool {
        let expected = self.expected_total_ubi();
        // Allow some tolerance (within 2 days worth)
        self.total_received + (2 * self.daily_amount) >= expected
    }
    
    /// Get next payout timestamp
    pub fn next_payout_timestamp(&self) -> Option<u64> {
        if let Some(last_payout) = self.last_payout {
            Some(last_payout + 24 * 3600) // 24 hours later
        } else {
            // Eligible for immediate payout
            Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs())
        }
    }
    
    /// Get time until next payout in seconds
    pub fn seconds_until_next_payout(&self) -> u64 {
        if let Some(next_payout) = self.next_payout_timestamp() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if next_payout > now {
                next_payout - now
            } else {
                0 // Payout is due
            }
        } else {
            0 // Eligible for immediate payout
        }
    }
}
