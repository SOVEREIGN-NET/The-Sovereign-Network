//! DAO Brokerage System for Token Buyback & Direct Sales
//!
//! Enables DAOs to stabilize token prices through buyback offers and citizens
//! to sell directly to DAOs without using public AMM. Uses TWAP-based price anchoring
//! with deviation bands to prevent arbitrage while supporting price discovery.

use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::PublicKey;
use blake3;

/// A buyback offer from a DAO treasury
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuybackOffer {
    pub offer_id: [u8; 32],
    /// How many DAO tokens to buy
    pub token_amount: u64,
    /// Price per token in SOV (8 decimals)
    pub sov_price_per_token: u64,
    /// Maximum total SOV the DAO will spend
    pub max_sov_total: u64,
    /// Block height when offer was created
    pub created_height: u64,
    /// Block height when offer expires
    pub expires_height: u64,
    /// How many tokens have been bought so far
    pub filled_amount: u64,
    /// TWAP reference price when offer was created
    pub twap_at_creation: u64,
    /// Max allowed deviation in basis points
    pub max_deviation_bp: u16,
}

/// A sell offer from a citizen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SellOffer {
    pub offer_id: [u8; 32],
    pub seller: PublicKey,
    /// How many tokens citizen wants to sell
    pub token_amount: u64,
    /// Minimum acceptable price per token in SOV
    pub min_sov_per_token: u64,
    /// Block height when offer was created
    pub created_height: u64,
    /// Block height when offer expires
    pub expires_height: u64,
}

/// A completed trade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedTrade {
    pub trade_id: [u8; 32],
    pub seller: PublicKey,
    pub token_amount: u64,
    pub sov_amount: u64,
    pub price_per_token: u64,
    pub trade_height: u64,
    pub trade_type: TradeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TradeType {
    /// DAO bought from citizen via buyback offer
    BuybackFilled,
    /// Citizen sold to DAO via sell offer
    DirectSale,
}

/// Market summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketSummary {
    pub active_buyback_offers: u32,
    pub active_sell_offers: u32,
    pub total_buyback_volume: u64,
    pub total_sell_volume: u64,
    pub average_buyback_price: u64,
    pub average_sell_price: u64,
    pub recent_trade_volume_24h: u64,
}

/// Main brokerage contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoBrokerage {
    pub dao_id: [u8; 32],
    pub token_addr: PublicKey,
    pub treasury_addr: PublicKey,

    /// Active buyback offers
    pub active_buyback_offers: Vec<BuybackOffer>,

    /// Active sell offers
    pub active_sell_offers: Vec<SellOffer>,

    /// Completed trades
    pub completed_trades: Vec<CompletedTrade>,

    // === Configuration ===
    /// Whether this is a For-Profit DAO (affects price band constraints)
    pub is_for_profit: bool,

    /// TWAP price reference (SOV per token, 8 decimals)
    pub twap_price: u64,

    /// Last block height when TWAP was updated
    pub twap_last_update: u64,

    /// TWAP window size in blocks (30min for FP, 2-6hr for NP)
    pub twap_window_blocks: u64,
}

impl DaoBrokerage {
    /// Create a new brokerage contract
    pub fn new(
        dao_id: [u8; 32],
        token_addr: PublicKey,
        treasury_addr: PublicKey,
        is_for_profit: bool,
        twap_window_blocks: u64,
    ) -> Self {
        Self {
            dao_id,
            token_addr,
            treasury_addr,
            active_buyback_offers: Vec::new(),
            active_sell_offers: Vec::new(),
            completed_trades: Vec::new(),
            is_for_profit,
            twap_price: 0,
            twap_last_update: 0,
            twap_window_blocks,
        }
    }

    /// Create a buyback offer from DAO treasury
    ///
    /// # TWAP-Based Price Validation
    /// - **For-Profit DAOs**: Price must be within ±3% of TWAP
    /// - **Non-Profit DAOs**: Price must be within +8% / -2% of TWAP (asymmetric)
    ///   - Buying: max +8% above TWAP (DAO pays premium to help citizens)
    ///   - Selling: max -2% below TWAP (tight constraint)
    pub fn create_buyback_offer(
        &mut self,
        token_amount: u64,
        sov_price_per_token: u64,
        duration_blocks: u64,
        caller: &PublicKey,
        current_height: u64,
    ) -> Result<[u8; 32]> {
        // Verify caller is treasury
        if caller.key_id != self.treasury_addr.key_id {
            return Err(anyhow!("Only treasury can create buyback offers"));
        }

        // Validate TWAP exists
        if self.twap_price == 0 {
            return Err(anyhow!("TWAP price not set - cannot validate offer"));
        }

        // Check price is within allowed deviation bands
        self.validate_price_within_bands(sov_price_per_token, self.twap_price, true)?;

        // Validate amounts
        if token_amount == 0 {
            return Err(anyhow!("Token amount must be greater than zero"));
        }

        // Calculate max SOV total from token amount and price
        let max_sov_total = (token_amount as u128)
            .checked_mul(sov_price_per_token as u128)
            .ok_or_else(|| anyhow!("Overflow in SOV calculation"))?
            .checked_div(100000000) // SOV has 8 decimals
            .ok_or_else(|| anyhow!("Division error"))? as u64;

        // Generate offer ID
        let offer_id = derive_offer_id(&self.dao_id, current_height, token_amount);

        // Determine max deviation
        let max_deviation_bp = if self.is_for_profit {
            300 // FP: ±3%
        } else {
            800 // NP: +8% / -2% average (use 8% for storage)
        };

        let offer = BuybackOffer {
            offer_id,
            token_amount,
            sov_price_per_token,
            max_sov_total,
            created_height: current_height,
            expires_height: current_height + duration_blocks,
            filled_amount: 0,
            twap_at_creation: self.twap_price,
            max_deviation_bp,
        };

        self.active_buyback_offers.push(offer);
        Ok(offer_id)
    }

    /// Accept a buyback offer (citizen sells to DAO)
    pub fn accept_buyback_offer(
        &mut self,
        offer_id: [u8; 32],
        token_amount: u64,
        seller: &PublicKey,
        current_height: u64,
    ) -> Result<u64> {
        // Find offer
        let offer_idx = self.active_buyback_offers
            .iter()
            .position(|o| o.offer_id == offer_id)
            .ok_or_else(|| anyhow!("Buyback offer not found"))?;

        // Clone offer data to avoid borrow checker issues
        let offer = self.active_buyback_offers[offer_idx].clone();

        // Check not expired
        if current_height >= offer.expires_height {
            return Err(anyhow!("Buyback offer has expired"));
        }

        // Check within fill amount
        if offer.filled_amount + token_amount > offer.token_amount {
            return Err(anyhow!(
                "Cannot fill {} tokens: would exceed offer amount of {}",
                token_amount,
                offer.token_amount - offer.filled_amount
            ));
        }

        // Calculate SOV payout
        let sov_payout = (token_amount as u128)
            .checked_mul(offer.sov_price_per_token as u128)
            .ok_or_else(|| anyhow!("Overflow in payout calculation"))?
            .checked_div(100000000)
            .ok_or_else(|| anyhow!("Division error"))? as u64;

        // Check treasury has sufficient SOV
        if sov_payout > offer.max_sov_total {
            return Err(anyhow!("Insufficient treasury SOV for payout"));
        }

        // Update offer
        self.active_buyback_offers[offer_idx].filled_amount += token_amount;

        // Record trade
        let trade_id = derive_trade_id(&offer_id, current_height);
        self.completed_trades.push(CompletedTrade {
            trade_id,
            seller: seller.clone(),
            token_amount,
            sov_amount: sov_payout,
            price_per_token: offer.sov_price_per_token,
            trade_height: current_height,
            trade_type: TradeType::BuybackFilled,
        });

        // Remove offer if fully filled
        if self.active_buyback_offers[offer_idx].filled_amount == offer.token_amount {
            self.active_buyback_offers.remove(offer_idx);
        }

        Ok(sov_payout)
    }

    /// Create a sell offer (citizen wants to sell to DAO)
    pub fn create_sell_offer(
        &mut self,
        token_amount: u64,
        min_sov_per_token: u64,
        duration_blocks: u64,
        seller: &PublicKey,
        current_height: u64,
    ) -> Result<[u8; 32]> {
        if token_amount == 0 {
            return Err(anyhow!("Token amount must be greater than zero"));
        }

        let offer_id = derive_offer_id(&self.dao_id, current_height, token_amount);

        let offer = SellOffer {
            offer_id,
            seller: seller.clone(),
            token_amount,
            min_sov_per_token,
            created_height: current_height,
            expires_height: current_height + duration_blocks,
        };

        self.active_sell_offers.push(offer);
        Ok(offer_id)
    }

    /// Fill a sell offer (DAO treasury buys from citizen)
    pub fn fill_sell_offer(
        &mut self,
        offer_id: [u8; 32],
        sov_price_per_token: u64,
        caller: &PublicKey,
        current_height: u64,
    ) -> Result<()> {
        // Verify caller is treasury
        if caller.key_id != self.treasury_addr.key_id {
            return Err(anyhow!("Only treasury can fill sell offers"));
        }

        // Find offer
        let offer_idx = self.active_sell_offers
            .iter()
            .position(|o| o.offer_id == offer_id)
            .ok_or_else(|| anyhow!("Sell offer not found"))?;

        let offer = &self.active_sell_offers[offer_idx];

        // Check not expired
        if current_height >= offer.expires_height {
            return Err(anyhow!("Sell offer has expired"));
        }

        // Check price meets minimum
        if sov_price_per_token < offer.min_sov_per_token {
            return Err(anyhow!(
                "Price {} below minimum {}",
                sov_price_per_token,
                offer.min_sov_per_token
            ));
        }

        // Check price within TWAP bands
        if self.twap_price > 0 {
            self.validate_price_within_bands(sov_price_per_token, self.twap_price, false)?;
        }

        // Record trade
        let trade_id = derive_trade_id(&offer_id, current_height);
        let sov_amount = (offer.token_amount as u128)
            .checked_mul(sov_price_per_token as u128)
            .ok_or_else(|| anyhow!("Overflow in calculation"))?
            .checked_div(100000000)
            .ok_or_else(|| anyhow!("Division error"))? as u64;

        self.completed_trades.push(CompletedTrade {
            trade_id,
            seller: offer.seller.clone(),
            token_amount: offer.token_amount,
            sov_amount,
            price_per_token: sov_price_per_token,
            trade_height: current_height,
            trade_type: TradeType::DirectSale,
        });

        // Remove offer
        self.active_sell_offers.remove(offer_idx);

        Ok(())
    }

    /// Cancel a buyback offer
    pub fn cancel_buyback_offer(
        &mut self,
        offer_id: [u8; 32],
        caller: &PublicKey,
    ) -> Result<()> {
        if caller.key_id != self.treasury_addr.key_id {
            return Err(anyhow!("Only treasury can cancel offers"));
        }

        let idx = self.active_buyback_offers
            .iter()
            .position(|o| o.offer_id == offer_id)
            .ok_or_else(|| anyhow!("Offer not found"))?;

        self.active_buyback_offers.remove(idx);
        Ok(())
    }

    /// Cancel a sell offer
    pub fn cancel_sell_offer(
        &mut self,
        offer_id: [u8; 32],
        caller: &PublicKey,
    ) -> Result<()> {
        let idx = self.active_sell_offers
            .iter()
            .position(|o| o.offer_id == offer_id)
            .ok_or_else(|| anyhow!("Offer not found"))?;

        let offer = &self.active_sell_offers[idx];
        if offer.seller.key_id != caller.key_id {
            return Err(anyhow!("Only offer creator can cancel"));
        }

        self.active_sell_offers.remove(idx);
        Ok(())
    }

    /// Update TWAP price (called by oracle or price feed)
    pub fn update_twap(&mut self, new_price: u64, current_height: u64) {
        self.twap_price = new_price;
        self.twap_last_update = current_height;
    }

    /// Get market summary
    pub fn get_market_summary(&self) -> MarketSummary {
        let mut avg_buyback_price = 0u64;
        if !self.active_buyback_offers.is_empty() {
            let sum: u64 = self.active_buyback_offers.iter().map(|o| o.sov_price_per_token).sum();
            avg_buyback_price = sum / self.active_buyback_offers.len() as u64;
        }

        let mut avg_sell_price = 0u64;
        if !self.active_sell_offers.is_empty() {
            let sum: u64 = self.active_sell_offers.iter().map(|o| o.min_sov_per_token).sum();
            avg_sell_price = sum / self.active_sell_offers.len() as u64;
        }

        let total_buyback_volume: u64 = self.active_buyback_offers.iter().map(|o| o.token_amount).sum();
        let total_sell_volume: u64 = self.active_sell_offers.iter().map(|o| o.token_amount).sum();

        let recent_24h_trades: u64 = self.completed_trades.iter()
            .map(|t| (t.token_amount as u128 * t.price_per_token as u128 / 100000000) as u64)
            .sum();

        MarketSummary {
            active_buyback_offers: self.active_buyback_offers.len() as u32,
            active_sell_offers: self.active_sell_offers.len() as u32,
            total_buyback_volume,
            total_sell_volume,
            average_buyback_price: avg_buyback_price,
            average_sell_price: avg_sell_price,
            recent_trade_volume_24h: recent_24h_trades,
        }
    }

    /// Clean up expired offers to prevent unbounded state growth
    ///
    /// **Note:** Smart contracts should periodically call this to prevent state bloat.
    /// Expired buyback and sell offers are removed, but completed_trades are permanent
    /// for audit trail purposes. Callers should implement their own archival strategy
    /// for historical trades if state becomes too large.
    pub fn cleanup_expired_offers(&mut self, current_height: u64) -> (usize, usize) {
        let buyback_removed = self.active_buyback_offers
            .iter()
            .filter(|o| current_height >= o.expires_height)
            .count();

        let sellback_removed = self.active_sell_offers
            .iter()
            .filter(|o| current_height >= o.expires_height)
            .count();

        // Remove expired buyback offers
        self.active_buyback_offers.retain(|o| current_height < o.expires_height);

        // Remove expired sell offers
        self.active_sell_offers.retain(|o| current_height < o.expires_height);

        (buyback_removed, sellback_removed)
    }

    /// Validate price is within allowed deviation bands
    fn validate_price_within_bands(
        &self,
        price: u64,
        twap: u64,
        is_buyback: bool,
    ) -> Result<()> {
        if twap == 0 {
            return Ok(()); // Skip validation if no TWAP
        }

        if self.is_for_profit {
            // FP DAO: ±3% symmetric band
            let max_deviation = (twap * 3) / 100;
            let min_price = twap.saturating_sub(max_deviation);
            let max_price = twap.saturating_add(max_deviation);

            if price < min_price || price > max_price {
                return Err(anyhow!(
                    "Price {} outside FP band [{}, {}]",
                    price,
                    min_price,
                    max_price
                ));
            }
        } else {
            // NP DAO: Asymmetric bands
            if is_buyback {
                // Buying: +8% above TWAP (DAO pays premium)
                let max_price = twap + (twap * 8) / 100;
                if price > max_price {
                    return Err(anyhow!(
                        "Buyback price {} exceeds NP buy limit {}",
                        price,
                        max_price
                    ));
                }
                // Also allow down to zero (DAO can buy at any discount)
            } else {
                // Selling: -2% below TWAP (tight constraint)
                let min_price = twap.saturating_sub((twap * 2) / 100);
                if price < min_price {
                    return Err(anyhow!(
                        "Sell price {} below NP sell limit {}",
                        price,
                        min_price
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Derive deterministic offer ID
fn derive_offer_id(dao_id: &[u8; 32], height: u64, amount: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"offer");
    hasher.update(dao_id);
    hasher.update(&height.to_le_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.finalize().into()
}

/// Derive deterministic trade ID
fn derive_trade_id(offer_id: &[u8; 32], height: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"trade");
    hasher.update(offer_id);
    hasher.update(&height.to_le_bytes());
    hasher.finalize().into()
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id; 32],
            kyber_pk: vec![id; 32],
            key_id: [id; 32],
        }
    }

    #[test]
    fn test_create_buyback_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false, // NP DAO
            2 * 60 * 60 * 6, // 2hr blocks
        );

        brokerage.twap_price = 1_00000000; // 1 SOV per token
        brokerage.twap_last_update = 100;

        let offer_id = brokerage.create_buyback_offer(
            100_00000000, // 100 tokens
            1_00000000,   // 1 SOV per token
            100,
            &test_public_key(3),
            100,
        );

        assert!(offer_id.is_ok());
        assert_eq!(brokerage.active_buyback_offers.len(), 1);
    }

    #[test]
    fn test_buyback_price_validation_fails() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            true, // FP DAO
            30 * 60 * 6, // 30min blocks
        );

        brokerage.twap_price = 1_00000000; // 1 SOV per token

        // Try to set price 10% above TWAP (exceeds FP 3% limit)
        let result = brokerage.create_buyback_offer(
            100_00000000,
            1_10000000, // 10% above TWAP
            100,
            &test_public_key(3),
            100,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_accept_buyback_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let offer_id = brokerage
            .create_buyback_offer(
                100_00000000,
                1_00000000,
                100,
                &test_public_key(3),
                100,
            )
            .unwrap();

        let sov = brokerage
            .accept_buyback_offer(offer_id, 50_00000000, &test_public_key(4), 101)
            .unwrap();

        assert!(sov > 0);
        assert_eq!(brokerage.completed_trades.len(), 1);
    }

    #[test]
    fn test_create_and_cancel_sell_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        let seller = test_public_key(4);
        let offer_id = brokerage
            .create_sell_offer(
                100_00000000,
                0_50000000, // 0.5 SOV minimum
                100,
                &seller,
                100,
            )
            .unwrap();

        assert_eq!(brokerage.active_sell_offers.len(), 1);

        brokerage.cancel_sell_offer(offer_id, &seller).unwrap();
        assert_eq!(brokerage.active_sell_offers.len(), 0);
    }

    #[test]
    fn test_market_summary() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        brokerage
            .create_buyback_offer(100_00000000, 1_00000000, 100, &test_public_key(3), 100)
            .unwrap();

        brokerage
            .create_sell_offer(50_00000000, 0_90000000, 100, &test_public_key(4), 100)
            .unwrap();

        let summary = brokerage.get_market_summary();
        assert_eq!(summary.active_buyback_offers, 1);
        assert_eq!(summary.active_sell_offers, 1);
    }

    #[test]
    fn test_fill_sell_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let seller = test_public_key(4);
        let offer_id = brokerage
            .create_sell_offer(
                100_00000000,
                0_95000000,  // 0.95 SOV minimum
                100,
                &seller,
                100,
            )
            .unwrap();

        // Treasury fills offer at price within NP -2% limit (0.98 SOV = 98% of 1 SOV TWAP)
        brokerage
            .fill_sell_offer(offer_id, 0_98000000, &test_public_key(3), 101)
            .unwrap();

        assert_eq!(brokerage.active_sell_offers.len(), 0);
        assert_eq!(brokerage.completed_trades.len(), 1);
    }

    #[test]
    fn test_np_asymmetric_bands_buyback() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false, // NP DAO
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        // NP buyback: +8% above TWAP allowed
        let result = brokerage.create_buyback_offer(
            100_00000000,
            1_08000000, // 8% above TWAP
            100,
            &test_public_key(3),
            100,
        );
        assert!(result.is_ok());

        // NP buyback: >8% should fail
        let result = brokerage.create_buyback_offer(
            100_00000000,
            1_10000000, // 10% above TWAP
            100,
            &test_public_key(3),
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_np_asymmetric_bands_sell() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false, // NP DAO
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let seller = test_public_key(4);
        let offer_id = brokerage
            .create_sell_offer(50_00000000, 0_98000000, 100, &seller, 100)
            .unwrap();

        // NP sell: -2% below TWAP allowed
        let result = brokerage.fill_sell_offer(offer_id, 0_98000000, &test_public_key(3), 101);
        assert!(result.is_ok());
    }

    #[test]
    fn test_buyback_offer_expiration() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let offer_id = brokerage
            .create_buyback_offer(100_00000000, 1_00000000, 10, &test_public_key(3), 100)
            .unwrap();

        // Try to fill after expiration
        let result = brokerage.accept_buyback_offer(offer_id, 50_00000000, &test_public_key(4), 110);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_partial_fills() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let offer_id = brokerage
            .create_buyback_offer(100_00000000, 1_00000000, 100, &test_public_key(3), 100)
            .unwrap();

        // First partial fill
        let result1 = brokerage.accept_buyback_offer(offer_id, 30_00000000, &test_public_key(4), 101);
        assert!(result1.is_ok());
        assert_eq!(brokerage.active_buyback_offers.len(), 1);

        // Second partial fill
        let result2 = brokerage.accept_buyback_offer(offer_id, 40_00000000, &test_public_key(5), 102);
        assert!(result2.is_ok());
        assert_eq!(brokerage.active_buyback_offers.len(), 1);

        // Final fill (exactly exhausts offer)
        let result3 = brokerage.accept_buyback_offer(offer_id, 30_00000000, &test_public_key(6), 103);
        assert!(result3.is_ok());
        assert_eq!(brokerage.active_buyback_offers.len(), 0);
        assert_eq!(brokerage.completed_trades.len(), 3);
    }

    #[test]
    fn test_cancel_expired_buyback_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let offer_id = brokerage
            .create_buyback_offer(100_00000000, 1_00000000, 10, &test_public_key(3), 100)
            .unwrap();

        // Cancel before expiration should work
        assert!(brokerage.cancel_buyback_offer(offer_id, &test_public_key(3)).is_ok());
        assert_eq!(brokerage.active_buyback_offers.len(), 0);
    }

    #[test]
    fn test_unauthorized_fill_sell_offer() {
        let mut brokerage = DaoBrokerage::new(
            [1u8; 32],
            test_public_key(2),
            test_public_key(3),
            false,
            2 * 60 * 60 * 6,
        );

        brokerage.twap_price = 1_00000000;
        brokerage.twap_last_update = 100;

        let seller = test_public_key(4);
        let offer_id = brokerage
            .create_sell_offer(100_00000000, 0_50000000, 100, &seller, 100)
            .unwrap();

        // Try to fill with non-treasury account
        let result = brokerage.fill_sell_offer(offer_id, 0_80000000, &test_public_key(99), 101);
        assert!(result.is_err());
    }
}
