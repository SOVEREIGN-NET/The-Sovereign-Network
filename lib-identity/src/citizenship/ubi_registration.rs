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
    /// Registration block height (deterministic consensus layer)
    pub registered_at_block: u64,
    /// Last UBI payout block height (deterministic consensus layer)
    pub last_payout_block: Option<u64>,
    /// Total UBI received to date
    pub total_received: u64,
    /// Accumulated remainder from integer division (e.g., 1000 / 30 = 33 remainder 10)
    pub remainder_balance: u64,
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
        registered_at_block: u64,
        last_payout_block: Option<u64>,
        total_received: u64,
    ) -> Self {
        // Calculate remainder from monthly to daily division (1000 / 30 = 33 remainder 10)
        let remainder = monthly_amount % 30;
        Self {
            identity_id,
            ubi_wallet_id,
            registration_tx,
            daily_amount,
            monthly_amount,
            eligibility_proof,
            registered_at_block,
            last_payout_block,
            total_received,
            remainder_balance: remainder,
        }
    }
    
    /// Register identity for Universal Basic Income payouts - IMPLEMENTATION FROM ORIGINAL
    pub async fn register_for_ubi_payouts(
        identity_id: &IdentityId,
        ubi_wallet_id: &WalletId,
        economic_model: &mut EconomicModel,
    ) -> Result<Self> {
        // Use block height for deterministic consensus (not wall-clock time)
        let current_block = economic_model.current_block;

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

        // Generate UBI eligibility proof using block height (deterministic)
        let eligibility_proof = lib_crypto::hash_blake3(
            &[
                identity_id.0.as_slice(),
                ubi_wallet_id.0.as_slice(),
                &daily_ubi_amount.to_le_bytes(),
                &current_block.to_le_bytes(),
            ].concat()
        );

        tracing::info!(
            "UBI REGISTERED: Citizen {} eligible for {} ZHTP daily ({} ZHTP monthly) at block {}",
            hex::encode(&identity_id.0[..8]),
            daily_ubi_amount,
            monthly_ubi_amount,
            current_block
        );

        Ok(Self::new(
            identity_id.clone(),
            ubi_wallet_id.clone(),
            ubi_tx,
            daily_ubi_amount,
            monthly_ubi_amount,
            eligibility_proof,
            current_block,
            None,
            0,
        ))
    }
    
    /// Check if eligible for UBI payout
    pub fn is_eligible_for_payout(&self) -> bool {
        self.eligibility_proof != [0u8; 32] && self.daily_amount > 0
    }
    
    /// Check if due for daily payout (requires being called with current block height)
    pub fn is_due_for_daily_payout(&self, current_block: u64) -> bool {
        if let Some(last_payout_block) = self.last_payout_block {
            // At ~10 second blocks, 24 hours = 8640 blocks (~10 seconds per block)
            // Using approximate daily payout threshold
            current_block - last_payout_block >= 8640
        } else {
            // Never received payout, eligible immediately
            true
        }
    }
    
    /// Record a UBI payout with block height (deterministic)
    /// Accumulates remainder and distributes when threshold reached
    pub fn record_payout(&mut self, amount: u64, block_height: u64) -> u64 {
        let mut actual_payout = amount;

        // Add remainder accumulation - distribute remainder every 30 payouts
        self.remainder_balance = self.remainder_balance.saturating_add(amount % 30);
        if self.remainder_balance >= 30 {
            actual_payout = amount + (self.remainder_balance / 30);
            self.remainder_balance %= 30;
        }

        self.last_payout_block = Some(block_height);
        self.total_received = self.total_received.saturating_add(actual_payout);
        actual_payout
    }
    
    /// Get blocks since registration (at ~10 seconds per block, ~8640 blocks per day)
    pub fn blocks_since_registration(&self, current_block: u64) -> u64 {
        current_block.saturating_sub(self.registered_at_block)
    }

    /// Get estimated days since registration
    pub fn days_since_registration(&self, current_block: u64) -> u64 {
        self.blocks_since_registration(current_block) / 8640 // ~8640 blocks per day
    }
    
    /// Calculate expected total UBI based on blocks since registration
    pub fn expected_total_ubi(&self, current_block: u64) -> u64 {
        self.days_since_registration(current_block).saturating_mul(self.daily_amount)
    }

    /// Check if citizen is up to date with UBI payouts
    pub fn is_ubi_up_to_date(&self, current_block: u64) -> bool {
        let expected = self.expected_total_ubi(current_block);
        // Allow some tolerance (within 2 days worth = 17280 blocks)
        self.total_received + (2 * self.daily_amount) >= expected
    }

    /// Get next payout block height
    pub fn next_payout_block(&self) -> u64 {
        if let Some(last_payout_block) = self.last_payout_block {
            last_payout_block + 8640 // ~24 hours of blocks (~8640 blocks per day)
        } else {
            // Eligible for immediate payout
            0
        }
    }

    /// Get blocks until next payout
    pub fn blocks_until_next_payout(&self, current_block: u64) -> u64 {
        let next_payout = self.next_payout_block();
        if next_payout > 0 && next_payout > current_block {
            next_payout - current_block
        } else {
            0 // Payout is due
        }
    }
}
