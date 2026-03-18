//! Bonding Curve Token Contract
//!
//! Implements the bonding curve token with explicit state machine:
//! Curve → Graduated → AMM
//!
//! # Invariants
//! - Phase transitions are irreversible
//! - Curve pricing is deterministic
//! - Graduation is automatic when threshold met
//! - No minting after graduation

use super::{
    canonical::SCALE,
    events::BondingCurveEvent,
    types::{CurveError, CurveStats, CurveType, Phase, Threshold, MAX_ORACLE_PRICE_AGE_SECONDS, USD_PRICE_SCALE},
};

/// Token scale: 1 whole token = 10^18 atomic units.
/// Re-exported here for convenience.
const TOKEN_SCALE: u128 = SCALE;
use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};

/// Issue #1844: Reserve/treasury split — 40% reserve / 60% treasury.
pub const RESERVE_SPLIT_NUMERATOR: u128 = 2;
pub const RESERVE_SPLIT_DENOMINATOR: u128 = 5;

/// Bonding Curve Token
///
/// Manages token lifecycle from initial curve offering through AMM graduation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveToken {
    // === Identity ===
    /// Unique token identifier
    pub token_id: [u8; 32],
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Token decimals
    pub decimals: u8,

    // === Phase State ===
    /// Current lifecycle phase
    pub phase: Phase,

    // === Curve State ===
    /// Total token supply in circulation
    pub total_supply: u128,
    /// Reserve balance in stablecoin (40% of purchases - backs bonding curve)
    pub reserve_balance: u128,
    /// Curve pricing formula
    pub curve_type: CurveType,
    /// Graduation threshold
    pub threshold: Threshold,
    /// Whether sell is enabled during curve phase
    pub sell_enabled: bool,

    // === AMM State (populated after graduation) ===
    /// AMM pool identifier (if graduated)
    pub amm_pool_id: Option<[u8; 32]>,

    // === Metadata ===
    /// Creator address
    pub creator: PublicKey,
    /// Creator DID (populated when deployer has a registered on-chain identity)
    #[serde(default)]
    pub creator_did: Option<String>,
    /// Block height at deployment
    pub deployed_at_block: u64,
    /// Timestamp at deployment
    pub deployed_at_timestamp: u64,
    /// Treasury balance in stablecoin (60% of purchases - protocol operations)
    /// Issue #1844: Reserve and Treasury 40/60 Split
    /// NOTE: Field is at end of struct intentionally — bincode is positional.
    /// Adding fields mid-struct corrupts deserialization of existing stored tokens.
    #[serde(default)]
    pub treasury_balance: u128,

    // === Issue #1846: Graduation Tracking ===
    /// Block height when graduation threshold was first detected as met.
    /// Used for confirmation period (safety mechanism).
    #[serde(default)]
    pub graduation_pending_since_block: Option<u64>,
    /// Last oracle SOV/USD price used for graduation check (8-decimal fixed-point).
    #[serde(default)]
    pub last_oracle_price: Option<u128>,
    /// Timestamp of last oracle price update.
    #[serde(default)]
    pub last_oracle_price_timestamp: Option<u64>,
}

impl BondingCurveToken {
    /// Deploy a new bonding curve token
    ///
    /// # Arguments
    /// * `token_id` - Unique identifier
    /// * `name` - Token name
    /// * `symbol` - Token symbol
    /// * `curve_type` - Pricing formula
    /// * `threshold` - Graduation condition
    /// * `sell_enabled` - Whether users can sell back to curve
    /// * `creator` - Deployer address
    /// * `deployed_at_block` - Deployment block
    /// * `deployed_at_timestamp` - Deployment timestamp
    pub fn deploy(
        token_id: [u8; 32],
        name: String,
        symbol: String,
        curve_type: CurveType,
        threshold: Threshold,
        sell_enabled: bool,
        creator: PublicKey,
        creator_did: String,
        deployed_at_block: u64,
        deployed_at_timestamp: u64,
    ) -> Result<Self, CurveError> {
        // Validate parameters
        if name.is_empty() {
            return Err(CurveError::InvalidParameters(
                "Name cannot be empty".to_string(),
            ));
        }
        if symbol.is_empty() {
            return Err(CurveError::InvalidParameters(
                "Symbol cannot be empty".to_string(),
            ));
        }
        if symbol.len() > 10 {
            return Err(CurveError::InvalidParameters(
                "Symbol too long (max 10)".to_string(),
            ));
        }

        Ok(Self {
            token_id,
            name,
            symbol,
            decimals: 18,
            phase: Phase::Curve,
            total_supply: 0,
            reserve_balance: 0,
            treasury_balance: 0,
            curve_type,
            threshold,
            sell_enabled,
            amm_pool_id: None,
            creator,
            creator_did: Some(creator_did),
            deployed_at_block,
            deployed_at_timestamp,
            // Issue #1846: Graduation tracking initialized to None
            graduation_pending_since_block: None,
            last_oracle_price: None,
            last_oracle_price_timestamp: None,
        })
    }

    /// Calculate current price based on curve formula
    ///
    /// # Returns
    /// Price per token in stablecoin atomic units
    pub fn current_price(&self) -> u128 {
        self.curve_type.calculate_price(self.total_supply)
    }

    /// Calculate how many tokens can be bought for a given stable amount
    ///
    /// Uses the constant product approximation for simplicity.
    /// For more accurate pricing, integrate over the curve.
    ///
    /// # Arguments
    /// * `stable_amount` - Amount of stablecoin to spend
    ///
    /// # Returns
    /// Token amount to receive
    pub fn calculate_buy(&self, stable_amount: u128) -> Result<u128, CurveError> {
        if stable_amount == 0 {
            return Err(CurveError::ZeroAmount);
        }

        self.require_phase(Phase::Curve)?;

        let price = self.current_price();
        if price == 0 {
            return Err(CurveError::InvalidParameters("Price is zero".to_string()));
        }

        // tokens = stable_amount / price
        // Both in atomic units, result in token atomic units
        let tokens = stable_amount
            .checked_mul(TOKEN_SCALE)
            .ok_or(CurveError::Overflow)?
            .checked_div(price)
            .ok_or(CurveError::Overflow)?;

        if tokens == 0 {
            return Err(CurveError::ZeroAmount);
        }

        Ok(tokens)
    }

    /// Calculate how much stablecoin can be received for selling tokens
    ///
    /// # Arguments
    /// * `token_amount` - Amount of tokens to sell
    ///
    /// # Returns
    /// Stablecoin amount to receive
    pub fn calculate_sell(&self, token_amount: u128) -> Result<u128, CurveError> {
        if token_amount == 0 {
            return Err(CurveError::ZeroAmount);
        }

        self.require_phase(Phase::Curve)?;

        if !self.sell_enabled {
            return Err(CurveError::InvalidParameters(
                "Selling is disabled".to_string(),
            ));
        }

        let price = self.current_price();

        // stable = token_amount × price / token_decimals
        let stable = token_amount
            .checked_mul(price)
            .ok_or(CurveError::Overflow)?
            .checked_div(TOKEN_SCALE)
            .ok_or(CurveError::Overflow)?;

        if stable > self.reserve_balance {
            return Err(CurveError::InsufficientReserve);
        }

        Ok(stable)
    }

    /// Buy tokens from the curve
    ///
    /// # Arguments
    /// * `buyer` - Address of buyer
    /// * `stable_amount` - Amount of stablecoin to spend
    /// * `block_height` - Current block height
    /// * `timestamp` - Current timestamp
    ///
    /// # Returns
    /// (token_amount, event)
    /// Buy tokens from the curve
    ///
    /// Implements Issue #1844: 40%/60% split between reserve and treasury
    /// - 40% goes to reserve pool (backs the bonding curve)
    /// - 60% goes to treasury (protocol operations)
    pub fn buy(
        &mut self,
        buyer: PublicKey,
        stable_amount: u128,
        block_height: u64,
        timestamp: u64,
    ) -> Result<(u128, BondingCurveEvent), CurveError> {
        let token_amount = self.calculate_buy(stable_amount)?;

        // Issue #1844: Split purchase 40% reserve / 60% treasury.
        // Use u128 intermediate to prevent u64 overflow on large stable_amount values;
        // use try_into() to explicitly guard the final cast back to u64.
        let to_reserve = stable_amount
                .checked_mul(RESERVE_SPLIT_NUMERATOR)
                .ok_or(CurveError::Overflow)?
                .checked_div(RESERVE_SPLIT_DENOMINATOR)
                .ok_or(CurveError::Overflow)?;
        let to_treasury = stable_amount - to_reserve;

        // Update state
        self.reserve_balance = self
            .reserve_balance
            .checked_add(to_reserve)
            .ok_or(CurveError::Overflow)?;
        self.treasury_balance = self
            .treasury_balance
            .checked_add(to_treasury)
            .ok_or(CurveError::Overflow)?;
        self.total_supply = self
            .total_supply
            .checked_add(token_amount)
            .ok_or(CurveError::Overflow)?;

        let price = self.current_price();

        let event = BondingCurveEvent::TokenPurchased {
            token_id: self.token_id,
            buyer: buyer.key_id,
            stable_amount,
            token_amount,
            price,
            block_height,
            timestamp,
        };

        Ok((token_amount, event))
    }

    /// Sell tokens back to the curve (if enabled)
    ///
    /// # Arguments
    /// * `seller` - Address of seller
    /// * `token_amount` - Amount of tokens to sell
    /// * `block_height` - Current block height
    /// * `timestamp` - Current timestamp
    ///
    /// # Returns
    /// (stable_amount, event)
    pub fn sell(
        &mut self,
        seller: PublicKey,
        token_amount: u128,
        block_height: u64,
        timestamp: u64,
    ) -> Result<(u128, BondingCurveEvent), CurveError> {
        let stable_amount = self.calculate_sell(token_amount)?;

        // Update state
        self.reserve_balance = self
            .reserve_balance
            .checked_sub(stable_amount)
            .ok_or(CurveError::Overflow)?;
        self.total_supply = self
            .total_supply
            .checked_sub(token_amount)
            .ok_or(CurveError::Overflow)?;

        let price = self.current_price();

        let event = BondingCurveEvent::TokenSold {
            token_id: self.token_id,
            seller: seller.key_id,
            token_amount,
            stable_amount,
            price,
            block_height,
            timestamp,
        };

        Ok((stable_amount, event))
    }

    /// Check if graduation threshold is met (for non-USD thresholds).
    ///
    /// For USD-based thresholds, use `check_graduation_with_oracle`.
    ///
    /// # Arguments
    /// * `current_timestamp` - Current timestamp for time-based checks
    pub fn can_graduate(&self, current_timestamp: u64, current_block: u64) -> bool {
        if self.phase != Phase::Curve {
            return false;
        }

        // For USD-based thresholds, require:
        //   1. A fresh oracle price (not stale)
        //   2. Reserve value still above threshold (sells may have reduced it)
        //   3. Confirmation period elapsed
        if let Threshold::ReserveValueUsd { .. } = self.threshold {
            // Require a non-stale oracle price
            let (price, price_ts) = match (self.last_oracle_price, self.last_oracle_price_timestamp) {
                (Some(p), Some(ts)) => (p, ts),
                _ => return false,
            };
            let price_age = current_timestamp.saturating_sub(price_ts);
            if price_age > MAX_ORACLE_PRICE_AGE_SECONDS {
                return false;
            }
            // Require threshold still met at current reserve (price_age=0 and pending_blocks=0
            // to skip the staleness/confirmation sub-checks — we handle those ourselves above)
            if !self.threshold.is_met_with_oracle(self.reserve_balance, price, 0, 0) {
                return false;
            }
            // Require confirmation period elapsed
            return match self.graduation_pending_since_block {
                Some(pending_since) => {
                    if let Threshold::ReserveValueUsd { confirmation_blocks, .. } = self.threshold {
                        current_block.saturating_sub(pending_since) >= confirmation_blocks
                    } else {
                        false
                    }
                }
                None => false,
            };
        }

        let elapsed = current_timestamp.saturating_sub(self.deployed_at_timestamp);
        self.threshold
            .is_met(self.reserve_balance, self.total_supply, elapsed)
    }

    /// Issue #1846: Check graduation status with oracle price.
    ///
    /// This method should be called on every buy transaction to track
    /// graduation status for USD-based thresholds.
    ///
    /// # Arguments
    /// * `sov_usd_price` - Current SOV/USD oracle price (8-decimal)
    /// * `price_timestamp` - Timestamp of oracle price
    /// * `current_block` - Current block height
    /// * `current_timestamp` - Current timestamp
    ///
    /// # Returns
    /// `true` if graduation threshold is met and all safety checks pass
    pub fn check_graduation_with_oracle(
        &mut self,
        sov_usd_price: u128,
        price_timestamp: u64,
        current_block: u64,
        current_timestamp: u64,
    ) -> bool {
        if self.phase != Phase::Curve {
            return false;
        }

        let Threshold::ReserveValueUsd {
            threshold_usd: _,
            max_price_age_seconds,
            confirmation_blocks,
        } = self.threshold else {
            // Non-USD thresholds use standard can_graduate
            return self.can_graduate(current_timestamp, current_block);
        };

        // Calculate price age
        let price_age_seconds = current_timestamp.saturating_sub(price_timestamp);

        // Safety check 1: Oracle price must not be stale
        if price_age_seconds > max_price_age_seconds {
            // Price is stale - reset pending status
            self.graduation_pending_since_block = None;
            return false;
        }

        // Check if reserve value meets threshold (ignoring confirmation period for now)
        // We pass 0 for pending_blocks to check threshold only
        let threshold_value_met = self.threshold.is_met_with_oracle(
            self.reserve_balance,
            sov_usd_price,
            price_age_seconds,
            0, // Ignore confirmation period for threshold check
        );

        if !threshold_value_met {
            // Threshold not met - reset pending status
            self.graduation_pending_since_block = None;
            self.last_oracle_price = None;
            self.last_oracle_price_timestamp = None;
            return false;
        }

        // Threshold is met - update or set pending status
        if self.graduation_pending_since_block.is_none() {
            // First time threshold is met - set pending
            self.graduation_pending_since_block = Some(current_block);
            self.last_oracle_price = Some(sov_usd_price);
            self.last_oracle_price_timestamp = Some(price_timestamp);
        }

        // Check if confirmation period is met
        let pending_blocks = current_block.saturating_sub(self.graduation_pending_since_block.unwrap_or(current_block));
        pending_blocks >= confirmation_blocks
    }

    /// Graduate the token to the next phase
    ///
    /// This is irreversible. Can be called automatically when threshold met,
    /// or manually if threshold is satisfied.
    ///
    /// # Arguments
    /// * `current_timestamp` - Current timestamp
    /// * `block_height` - Current block height
    ///
    /// # Returns
    /// Graduation event
    pub fn graduate(
        &mut self,
        current_timestamp: u64,
        block_height: u64,
    ) -> Result<BondingCurveEvent, CurveError> {
        if !self.can_graduate(current_timestamp, block_height) {
            return Err(CurveError::ThresholdNotMet);
        }

        self.phase = Phase::Graduated;

        // Clear graduation tracking fields
        self.graduation_pending_since_block = None;
        self.last_oracle_price = None;
        self.last_oracle_price_timestamp = None;

        let event = BondingCurveEvent::Graduated {
            token_id: self.token_id,
            final_reserve: self.reserve_balance,
            final_supply: self.total_supply,
            threshold_met: self.threshold.description(),
            block_height,
            timestamp: current_timestamp,
        };

        Ok(event)
    }

    /// Complete migration to AMM
    ///
    /// Called after AMM pool is seeded with liquidity.
    ///
    /// # Arguments
    /// * `amm_pool_id` - AMM pool identifier
    pub fn complete_migration(&mut self, amm_pool_id: [u8; 32]) -> Result<(), CurveError> {
        self.require_phase(Phase::Graduated)?;

        self.phase = Phase::AMM;
        self.amm_pool_id = Some(amm_pool_id);

        Ok(())
    }

    /// Get current statistics
    ///
    /// # Arguments
    /// * `current_timestamp` - Current timestamp
    pub fn get_stats(&self, current_timestamp: u64, current_block: u64) -> CurveStats {
        let elapsed = current_timestamp.saturating_sub(self.deployed_at_timestamp);

        // Calculate graduation progress
        let progress = match self.threshold {
            Threshold::ReserveAmount(target) => {
                if target == 0 {
                    100
                } else {
                    ((self.reserve_balance as u128 * 100) / target as u128) as u8
                }
            }
            Threshold::SupplyAmount(target) => {
                if target == 0 {
                    100
                } else {
                    ((self.total_supply as u128 * 100) / target as u128) as u8
                }
            }
            Threshold::ReserveValueUsd { threshold_usd, .. } => {
                // For USD thresholds, calculate progress based on last known oracle price.
                // Multiply first to preserve sub-SOV precision.
                if let Some(sov_usd_price) = self.last_oracle_price {
                    let reserve_value_usd = self.reserve_balance
                        .saturating_mul(sov_usd_price)
                        .saturating_div(TOKEN_SCALE * USD_PRICE_SCALE);
                    // Compute percent in u128, clamp to 100 before casting to u8 to prevent wrap
                    let percent = if threshold_usd == 0 {
                        100u128
                    } else {
                        (reserve_value_usd.saturating_mul(100)) / threshold_usd
                    };
                    percent.min(100) as u8
                } else {
                    0
                }
            }
            _ => 0, // Complex thresholds simplified
        };

        CurveStats {
            total_supply: self.total_supply,
            reserve_balance: self.reserve_balance,
            treasury_balance: self.treasury_balance,
            current_price: self.current_price(),
            elapsed_seconds: elapsed,
            graduation_progress_percent: progress.min(100),
            can_graduate: self.can_graduate(current_timestamp, current_block),
        }
    }

    /// Issue #1846: Calculate reserve value in USD using oracle price.
    ///
    /// # Arguments
    /// * `sov_usd_price` - SOV/USD oracle price (8-decimal fixed-point, where $1.00 = 100_000_000)
    ///
    /// # Returns
    /// Reserve value in USD (whole dollars)
    ///
    /// # Calculation
    /// reserve_value_usd = (reserve_sov_atomic * sov_usd_price) / (TOKEN_SCALE * USD_PRICE_SCALE)
    ///                   = reserve_sov_atomic * sov_usd_price / 10^16
    ///
    /// Returns `Err(CurveError::Overflow)` if intermediate or final values exceed their types.
    pub fn reserve_value_usd(&self, sov_usd_price: u128) -> Result<u128, CurveError> {
        let numerator = self.reserve_balance
            .checked_mul(sov_usd_price)
            .ok_or(CurveError::Overflow)?;
        let denominator = TOKEN_SCALE * USD_PRICE_SCALE;
        Ok(numerator / denominator)
    }

    /// Issue #1846: Check if graduation is pending (confirmation period active).
    pub fn is_graduation_pending(&self) -> bool {
        self.graduation_pending_since_block.is_some()
    }

    /// Issue #1846: Get blocks until graduation can proceed (0 if ready).
    pub fn blocks_until_graduation(&self, current_block: u64) -> u64 {
        let Threshold::ReserveValueUsd { confirmation_blocks, .. } = self.threshold else {
            return 0;
        };

        if let Some(pending_since) = self.graduation_pending_since_block {
            let pending_blocks = current_block.saturating_sub(pending_since);
            confirmation_blocks.saturating_sub(pending_blocks)
        } else {
            0
        }
    }

    /// Require a specific phase
    fn require_phase(&self, required: Phase) -> Result<(), CurveError> {
        if self.phase != required {
            Err(CurveError::InvalidPhase {
                current: self.phase,
                required,
            })
        } else {
            Ok(())
        }
    }

    /// Check if the token can be traded on the curve
    pub fn is_curve_trading_active(&self) -> bool {
        self.phase == Phase::Curve
    }

    /// Get the AMM pool ID (if graduated)
    pub fn amm_pool_id(&self) -> Option<[u8; 32]> {
        self.amm_pool_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: [id; 32],
        }
    }

    fn find_reserve_safe_sell_amount(token: &BondingCurveToken, max_amount: u128) -> u128 {
        let mut candidate = max_amount;
        while candidate > 0 {
            if token.calculate_sell(candidate).is_ok() {
                return candidate;
            }
            candidate /= 2;
        }
        0
    }

    #[test]
    fn test_deploy_token() {
        let token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000, // $0.10
                slope: 10_000,          // $0.0001
            },
            Threshold::ReserveAmount(100_000_000), // $1M
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        );

        assert!(token.is_ok());
        let token = token.unwrap();
        assert_eq!(token.phase, Phase::Curve);
        assert_eq!(token.total_supply, 0);
        assert_eq!(token.reserve_balance, 0);
        assert!(token.sell_enabled);
    }

    #[test]
    fn test_buy_tokens() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000, // $0.10
                slope: 0,               // Constant price for simplicity
            },
            Threshold::ReserveAmount(1_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);
        // Buy with $1 at a constant $0.10 price.
        let buy_amount = 100_000_000u128;
        let (tokens, event) = token.buy(buyer, buy_amount, 101, 1_600_000_001).unwrap();

        assert_eq!(tokens, 10 * TOKEN_SCALE); // 10 tokens
        assert_eq!(token.total_supply, tokens);

        // Issue #1844: Verify 40/60 split
        let expected_reserve = buy_amount * RESERVE_SPLIT_NUMERATOR / RESERVE_SPLIT_DENOMINATOR;
        let expected_treasury = buy_amount - expected_reserve;
        assert_eq!(token.reserve_balance, expected_reserve, "Reserve should get 40%");
        assert_eq!(token.treasury_balance, expected_treasury, "Treasury should get 60%");

        match event {
            BondingCurveEvent::TokenPurchased { stable_amount, .. } => {
                assert_eq!(stable_amount, 100_000_000);
            }
            _ => panic!("Expected TokenPurchased event"),
        }
    }

    #[test]
    fn test_buy_reserve_treasury_split_1844() {
        // Issue #1844: Test the 40/60 reserve/treasury split
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Split Test".to_string(),
            "SPLIT".to_string(),
            CurveType::Linear {
                base_price: 1_000_000, // $0.01
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Test multiple purchases accumulate correctly
        let buy_1 = 10_000_000_000u128;
        let _ = token.buy(buyer.clone(), buy_1, 101, 1_600_000_001).unwrap();
        let expected_reserve_1 = buy_1 * RESERVE_SPLIT_NUMERATOR / RESERVE_SPLIT_DENOMINATOR;
        let expected_treasury_1 = buy_1 - expected_reserve_1;
        assert_eq!(token.reserve_balance, expected_reserve_1, "Reserve should be 40% of buy_1");
        assert_eq!(token.treasury_balance, expected_treasury_1, "Treasury should be 60% of buy_1");

        let buy_2 = 5_000_000_000u128;
        let _ = token.buy(buyer, buy_2, 102, 1_600_000_002).unwrap();
        let expected_reserve_2 = expected_reserve_1 + buy_2 * RESERVE_SPLIT_NUMERATOR / RESERVE_SPLIT_DENOMINATOR;
        let expected_treasury_2 = expected_treasury_1 + (buy_2 - buy_2 * RESERVE_SPLIT_NUMERATOR / RESERVE_SPLIT_DENOMINATOR);
        assert_eq!(token.reserve_balance, expected_reserve_2, "Reserve should accumulate 40% of each buy");
        assert_eq!(token.treasury_balance, expected_treasury_2, "Treasury should accumulate 60% of each buy");

        // Verify total collected equals sum of all purchases
        let total_bought = buy_1 + buy_2;
        assert_eq!(
            token.reserve_balance + token.treasury_balance,
            total_bought,
            "Total should equal sum of purchases"
        );

        // Verify split ratio is exactly 40/60 using integer arithmetic
        let total = token.reserve_balance + token.treasury_balance;
        assert_eq!(token.reserve_balance * 10000 / total, 4000, "Reserve should be exactly 40%");
        assert_eq!(token.treasury_balance * 10000 / total, 6000, "Treasury should be exactly 60%");
    }

    #[test]
    fn test_cannot_buy_after_graduation() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(100), // Very low threshold
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy enough to trigger graduation (need 250 total for 100 reserve at 40% split)
        let _ = token.buy(test_pubkey(2), 500, 101, 1_600_000_001).unwrap();
        assert!(token.can_graduate(1_600_000_001, 101));

        // Graduate
        let _ = token.graduate(1_600_000_002, 102).unwrap();

        // Try to buy after graduation
        let result = token.buy(test_pubkey(3), 100, 103, 1_600_000_003);
        assert!(result.is_err());
        assert!(matches!(result, Err(CurveError::InvalidPhase { .. })));
    }

    #[test]
    fn test_graduation_threshold() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(1_000_000_000), // $10M reserve required
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Issue #1844: With 40% split, need 2.5x total purchases to reach reserve threshold
        // Not enough reserve (100M purchase → 40M reserve)
        let _ = token
            .buy(test_pubkey(2), 100_000_000, 101, 1_600_000_001)
            .unwrap();
        assert!(!token.can_graduate(1_600_000_001, 101));

        // Add more to reach threshold (need 2.5B total purchases for 1B reserve)
        let _ = token
            .buy(test_pubkey(3), 2_400_000_000, 102, 1_600_000_002)
            .unwrap();
        assert!(token.can_graduate(1_600_000_002, 102));
        assert_eq!(token.reserve_balance, 1_000_000_000, "Reserve should be exactly at threshold");

        // Graduate
        let result = token.graduate(1_600_000_003, 103);
        assert!(result.is_ok());
        assert_eq!(token.phase, Phase::Graduated);
    }

    #[test]
    fn test_complete_migration_to_amm() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(100),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Graduate first (need 250 purchases to reach 100 reserve at 40% split;
        // buying 500 to reach 200 reserve — 2x threshold for safety margin)
        let _ = token.buy(test_pubkey(2), 500, 101, 1_600_000_001).unwrap();
        let _ = token.graduate(1_600_000_002, 102).unwrap();

        // Complete migration
        let pool_id = [99u8; 32];
        let result = token.complete_migration(pool_id);
        assert!(result.is_ok());
        assert_eq!(token.phase, Phase::AMM);
        assert_eq!(token.amm_pool_id, Some(pool_id));
    }

    #[test]
    fn test_cannot_migrate_before_graduation() {
        let mut token = BondingCurveToken::deploy(
            [1u8; 32],
            "Test Token".to_string(),
            "TEST".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(1_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Try to migrate before graduation
        let pool_id = [99u8; 32];
        let result = token.complete_migration(pool_id);
        assert!(result.is_err());
        assert!(matches!(result, Err(CurveError::InvalidPhase { .. })));
    }

    /// Full lifecycle integration test: Deploy → Buy → Graduate → Migrate to AMM
    #[test]
    fn test_full_lifecycle_curve_to_amm() {
        // 1. DEPLOY: Token creator deploys bonding curve token
        let mut token = BondingCurveToken::deploy(
            [42u8; 32],
            "Lifecycle Token".to_string(),
            "LIFE".to_string(),
            CurveType::Linear {
                base_price: 5_000_000, // $0.05 starting price
                slope: 1_000,          // $0.00001 per token
            },
            Threshold::ReserveAmount(7_000_000_000), // $7,000 graduation threshold
            true,                                    // Sell enabled
            test_pubkey(1),
            String::new(),
            100,           // deployed_at_block
            1_700_000_000, // deployed_at_timestamp
        )
        .unwrap();

        assert_eq!(token.phase, Phase::Curve);
        assert_eq!(token.total_supply, 0);
        assert_eq!(token.reserve_balance, 0);
        assert_eq!(token.current_price(), 5_000_000); // $0.05

        // 2. BUY PHASE: Multiple users buy tokens
        // Issue #1844: With 40% split, need 2.5x purchases to reach same reserve
        let buyer1 = test_pubkey(10);
        let buyer2 = test_pubkey(20);
        let buyer3 = test_pubkey(30);

        // Buyer 1: $5000 → $2000 reserve (40%), ~100,000 tokens at $0.05
        let (tokens1, event1) = token
            .buy(buyer1.clone(), 5_000_000_000, 101, 1_700_000_100)
            .unwrap();
        assert!(tokens1 > 0);
        assert_eq!(token.reserve_balance, 2_000_000_000, "Reserve gets 40% = $2K");
        assert_eq!(token.treasury_balance, 3_000_000_000, "Treasury gets 60% = $3K");
        assert!(!token.can_graduate(1_700_000_100, 101)); // Not enough for graduation (need $7K reserve)

        // Buyer 2: $10000 → $4000 more reserve, total $6000
        let (tokens2, _event2) = token
            .buy(buyer2, 10_000_000_000, 102, 1_700_000_200)
            .unwrap();
        assert!(tokens2 > 0);
        assert_eq!(token.reserve_balance, 6_000_000_000, "Reserve = $6K");
        assert!(!token.can_graduate(1_700_000_200, 102)); // Still not graduated (need $7K)

        // Buyer 3: $12500 → $5000 more reserve, total $11000
        let (tokens3, _event3) = token
            .buy(buyer3, 12_500_000_000, 103, 1_700_000_300)
            .unwrap();
        assert!(tokens3 > 0);
        assert_eq!(token.reserve_balance, 11_000_000_000, "Reserve = $11K");
        assert!(token.can_graduate(1_700_000_300, 103), "NOW ready to graduate!");

        // Verify events
        match event1 {
            BondingCurveEvent::TokenPurchased {
                buyer,
                stable_amount,
                ..
            } => {
                assert_eq!(buyer, buyer1.key_id);
                assert_eq!(stable_amount, 5_000_000_000); // 40/60 split test
            }
            _ => panic!("Expected TokenPurchased event"),
        }

        // 3. GRADUATION: Threshold met, token graduates
        let grad_event = token.graduate(1_700_000_400, 104).unwrap();
        assert_eq!(token.phase, Phase::Graduated);
        assert!(token.amm_pool_id.is_none());

        match grad_event {
            BondingCurveEvent::Graduated {
                final_reserve,
                final_supply,
                threshold_met,
                ..
            } => {
                assert_eq!(final_reserve, 11_000_000_000);
                assert_eq!(final_supply, token.total_supply);
                assert!(threshold_met.contains("Reserve"));
            }
            _ => panic!("Expected Graduated event"),
        }

        // Cannot buy after graduation
        let buy_result = token.buy(test_pubkey(99), 100, 105, 1_700_000_500);
        assert!(buy_result.is_err());
        assert!(matches!(buy_result, Err(CurveError::InvalidPhase { .. })));

        // 4. MIGRATION TO AMM: Pool is seeded
        let amm_pool_id = [99u8; 32];
        let migrate_result = token.complete_migration(amm_pool_id);
        assert!(migrate_result.is_ok());
        assert_eq!(token.phase, Phase::AMM);
        assert_eq!(token.amm_pool_id, Some(amm_pool_id));

        // Final state verification
        assert!(token.total_supply > 0);
        assert_eq!(token.reserve_balance, 11_000_000_000);
        assert!(token.current_price() > 5_000_000); // Price increased due to curve

        // Verify stats
        let stats = token.get_stats(1_700_000_600, 106);
        assert_eq!(stats.total_supply, token.total_supply);
        assert_eq!(stats.reserve_balance, 11_000_000_000);
        assert_eq!(stats.graduation_progress_percent, 100);
        // can_graduate is false because token already graduated (phase is AMM)
        assert!(!stats.can_graduate);
    }

    /// Test sell functionality during curve phase
    #[test]
    fn test_sell_tokens_during_curve() {
        let mut token = BondingCurveToken::deploy(
            [5u8; 32],
            "Sellable Token".to_string(),
            "SELL".to_string(),
            CurveType::Linear {
                base_price: 10_000_000, // $0.10
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000), // High threshold
            true,                                     // Sell ENABLED
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy $12.5, then sell a reserve-safe fraction back to the curve.
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 1_250_000_000, 101, 1_600_000_100)
            .unwrap();
        assert_eq!(tokens_bought, 125 * TOKEN_SCALE, "Should get 125 tokens");
        assert_eq!(token.reserve_balance, 500_000_000, "Reserve should be 40% of $12.5 = $5");
        assert_eq!(token.treasury_balance, 750_000_000, "Treasury should be 60% of $12.5 = $7.50");

        let tokens_to_sell = find_reserve_safe_sell_amount(&token, 50 * TOKEN_SCALE);
        let (stable_received, sell_event) = token
            .sell(buyer.clone(), tokens_to_sell, 102, 1_600_000_200)
            .unwrap();
        assert!(stable_received > 0, "Should receive stablecoin on sell");
        assert_eq!(token.total_supply, tokens_bought - tokens_to_sell, "Supply should decrease");
        assert_eq!(token.reserve_balance, 500_000_000 - stable_received, "Reserve should decrease");

        match sell_event {
            BondingCurveEvent::TokenSold {
                seller,
                token_amount,
                stable_amount,
                ..
            } => {
                assert_eq!(seller, buyer.key_id);
                assert_eq!(token_amount, tokens_to_sell);
                assert_eq!(stable_amount, stable_received);
            }
            _ => panic!("Expected TokenSold event"),
        }
    }

    /// Test sell disabled
    #[test]
    fn test_sell_disabled() {
        let mut token = BondingCurveToken::deploy(
            [6u8; 32],
            "No Sell Token".to_string(),
            "NOSELL".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000),
            false, // Sell DISABLED
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 1_000_000_000, 101, 1_600_000_100)
            .unwrap();

        // Try to sell - should fail
        let sell_result = token.sell(buyer, tokens_bought, 102, 1_600_000_200);
        assert!(sell_result.is_err());
        assert!(matches!(sell_result, Err(CurveError::InvalidParameters(_))));
    }

    /// Issue #1845: Test sell with PiecewiseLinear curve type
    /// Verifies sell functionality works with document-compliant piecewise linear curve
    /// 
    /// NOTE: Due to the 40/60 split (Issue #1844), the reserve only has 40% of SOV paid.
    /// The bonding curve pricing means tokens may be worth more than 40% of purchase price,
    /// so we must sell only a small portion to stay within reserve limits.
    #[test]
    fn test_sell_tokens_with_piecewise_linear_curve() {
        use crate::contracts::bonding_curve::pricing::PiecewiseLinearCurve;

        let mut token = BondingCurveToken::deploy(
            [7u8; 32],
            "Piecewise Sell Token".to_string(),
            "PSELL".to_string(),
            CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(10_000_000_000_000), // High threshold
            true,                                         // Sell ENABLED
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens with PiecewiseLinear curve
        let buy_amount = 100_000_000_000; // 1000 SOV
        let (tokens_bought, _) = token
            .buy(buyer.clone(), buy_amount, 101, 1_600_000_100)
            .unwrap();

        // Verify initial state after buy
        assert!(tokens_bought > 0, "Should receive tokens");
        assert_eq!(
            token.reserve_balance,
            buy_amount * RESERVE_SPLIT_NUMERATOR / RESERVE_SPLIT_DENOMINATOR,
            "Reserve should be 40% of buy amount"
        );
        assert_eq!(
            token.treasury_balance,
            buy_amount * (RESERVE_SPLIT_DENOMINATOR - RESERVE_SPLIT_NUMERATOR) / RESERVE_SPLIT_DENOMINATOR,
            "Treasury should be 60% of buy amount"
        );

        // IMPORTANT: Due to 40/60 split, we can only sell a small % of tokens.
        // The reserve only has 40% of SOV, but tokens are priced at current market rate.
        // We sell just 5% of purchased tokens to ensure reserve can cover.
        let tokens_to_sell = find_reserve_safe_sell_amount(&token, tokens_bought / 20);
        let initial_supply = token.total_supply;
        let initial_reserve = token.reserve_balance;

        let (sov_received, sell_event) = token
            .sell(buyer.clone(), tokens_to_sell, 102, 1_600_000_200)
            .unwrap();

        // Verify sell behavior per Issue #1845:
        // 1. Tokens are burned (supply decreases)
        assert_eq!(token.total_supply, initial_supply - tokens_to_sell, "Supply should decrease after sell (burn)");
        // 2. Reserve decreases (SOV returned from reserve only)
        assert_eq!(token.reserve_balance, initial_reserve - sov_received, "Reserve should decrease by returned SOV");
        // 3. Treasury unchanged (no SOV from treasury)
        assert_eq!(token.treasury_balance, buy_amount * 3 / 5, "Treasury should remain unchanged after sell");
        // 4. Verify SOV received is reasonable (not zero, less than reserve)
        assert!(sov_received > 0, "Should receive some SOV");
        assert!(sov_received < initial_reserve, "Should receive less than reserve balance");

        // Verify event
        match sell_event {
            BondingCurveEvent::TokenSold {
                seller,
                token_amount,
                stable_amount,
                ..
            } => {
                assert_eq!(seller, buyer.key_id);
                assert_eq!(token_amount, tokens_to_sell);
                assert_eq!(stable_amount, sov_received);
            }
            _ => panic!("Expected TokenSold event"),
        }
    }

    /// Issue #1845: Test sell fails after graduation
    /// Verifies sell is disabled once token graduates from curve phase
    #[test]
    fn test_sell_fails_after_graduation() {
        // Use Linear curve with known pricing for predictable test
        let mut token = BondingCurveToken::deploy(
            [8u8; 32],
            "Graduated Token".to_string(),
            "GRAD".to_string(),
            CurveType::Linear {
                base_price: 1_000_000, // $0.01 per token for easier calculation
                slope: 0,
            },
            Threshold::ReserveAmount(500_000_000), // 5 SOV threshold
            true,                                  // Sell ENABLED
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens - with 40/60 split, buying 25 SOV puts 10 SOV in reserve (exceeds 5 SOV threshold)
        // With $0.01 per token, 25 SOV buys 2500 tokens
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 25_000_000_000, 101, 1_600_000_100)
            .unwrap();

        // Verify still in curve phase (buy doesn't auto-graduate)
        assert_eq!(token.reserve_balance, 10_000_000_000, "Reserve should be 10 SOV (40% of 25)");
        assert!(matches!(token.phase, Phase::Curve), "Should still be in curve phase after buy");

        // Graduate the token manually
        token.graduate(1_600_000_200, 102).unwrap();
        assert!(matches!(token.phase, Phase::Graduated), "Should be graduated after calling graduate()");

        // Try to sell after graduation - should fail with InvalidPhase
        // Note: Even though reserve has 5 SOV and tokens are worth $0.01 each,
        // sell is not allowed in Graduated phase - tokens must be traded on AMM
        let sell_result = token.sell(buyer, tokens_bought, 103, 1_600_000_300);
        assert!(sell_result.is_err(), "Sell should fail after graduation");
        assert!(
            matches!(sell_result, Err(CurveError::InvalidPhase { .. })),
            "Should fail with InvalidPhase error"
        );
    }

    /// Issue #1845: Test sell fails with insufficient reserve
    /// Verifies sell fails when there's not enough SOV in reserve to pay seller
    #[test]
    fn test_sell_fails_with_insufficient_reserve() {
        let mut token = BondingCurveToken::deploy(
            [9u8; 32],
            "Low Reserve Token".to_string(),
            "LOWRES".to_string(),
            CurveType::Linear {
                base_price: 1_000_000, // $0.01 (low price)
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000_000), // Very high threshold
            true,                                         // Sell ENABLED
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens - small amount
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 100_000_000, 101, 1_600_000_100)
            .unwrap();

        // Reserve is 40% of buy = 40 SOV cents
        assert_eq!(token.reserve_balance, 40_000_000);

        // Try to sell all tokens - should fail because reserve can't cover
        // The sell value would exceed reserve (20 cents reserve, but trying to sell ~$1 worth)
        let sell_result = token.sell(buyer, tokens_bought, 102, 1_600_000_200);
        assert!(sell_result.is_err(), "Sell should fail with insufficient reserve");
        assert!(
            matches!(sell_result, Err(CurveError::InsufficientReserve)),
            "Should fail with InsufficientReserve error"
        );
    }

    /// Issue #1845: Test complete burn on sell (100% burn)
    /// Verifies that sold tokens are fully burned (supply decreases by exact amount)
    /// 
    /// NOTE: Due to 40/60 split, we can only sell ~40% of tokens back before reserve is depleted.
    #[test]
    fn test_sell_100_percent_burn() {
        let mut token = BondingCurveToken::deploy(
            [10u8; 32],
            "Burn Test Token".to_string(),
            "BURN".to_string(),
            CurveType::Linear {
                base_price: 100_000, // $0.001 for large token amounts
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens with large amount so reserve can cover sells
        let buy_amount = 100_000_000_000; // 1000 SOV
        let (tokens_bought, _) = token
            .buy(buyer.clone(), buy_amount, 101, 1_600_000_100)
            .unwrap();

        let initial_supply = token.total_supply;

        // Sell tokens in small portions that reserve can cover
        // Reserve is 200 SOV. At $0.001/token, we can sell up to 200,000 tokens.
        // We sell in small chunks to test burn behavior.
        let sell_portion = tokens_bought / 50; // Small 2% chunks
        let mut total_sold: u128 = 0;
        for i in 0..5 {
            let remaining_reserve = token.reserve_balance;
            let current_price = token.current_price();
            // Calculate max tokens we can sell with remaining reserve
            let max_tokens = remaining_reserve
                .saturating_mul(100_000_000)
                .saturating_div(current_price.max(1));
            if max_tokens == 0 {
                break;
            }
            let to_sell = sell_portion.min(max_tokens);
            
            let _ = token
                .sell(buyer.clone(), to_sell, 102 + i as u64, 1_600_000_200 + i as u64 * 100)
                .unwrap();
            total_sold += to_sell;
        }

        // Verify 100% burn - supply should decrease by total amount sold
        assert_eq!(
            initial_supply - token.total_supply,
            total_sold,
            "All sold tokens should be burned (supply decrease = amount sold)"
        );
    }

    /// Issue #1845: Test sell returns SOV from reserve only (not treasury)
    /// Verifies sell only draws from reserve pool, not treasury
    ///
    /// NOTE: Due to 40/60 split, reserve only has 40% of SOV paid.
    #[test]
    fn test_sell_returns_sov_from_reserve_only() {
        let mut token = BondingCurveToken::deploy(
            [11u8; 32],
            "Reserve Test Token".to_string(),
            "RES".to_string(),
            CurveType::Linear {
                base_price: 100_000, // $0.001
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy with large amount so reserve can cover sells
        let buy_amount = 100_000_000_000; // 1000 SOV
        let (tokens_bought, _) = token
            .buy(buyer.clone(), buy_amount, 101, 1_600_000_100)
            .unwrap();

        let initial_reserve = token.reserve_balance;
        let initial_treasury = token.treasury_balance;

        // Sell a small portion of tokens (must be small enough for reserve to cover)
        // With 40% in reserve, we can sell at most ~40% of tokens (at constant price)
        let tokens_to_sell = tokens_bought / 25; // Sell 4% - well within reserve limits
        let (sov_received, _) = token
            .sell(buyer, tokens_to_sell, 102, 1_600_000_200)
            .unwrap();

        // Verify: SOV comes ONLY from reserve
        assert_eq!(
            token.reserve_balance,
            initial_reserve - sov_received,
            "Reserve should decrease by returned SOV"
        );
        assert_eq!(
            token.treasury_balance, initial_treasury,
            "Treasury should NOT decrease after sell"
        );
        assert!(sov_received > 0, "Should receive positive SOV amount");
    }

    /// Issue #1845: Test sell with piecewise linear curve within a single band
    /// Verifies sell works correctly with a piecewise linear curve (CBE default).
    ///
    /// NOTE: Due to 40/60 split, reserve only has 40% of SOV paid.
    /// Must sell small amounts to stay within reserve limits.
    #[test]
    fn test_sell_with_piecewise_linear_curve_single_band() {
        use crate::contracts::bonding_curve::pricing::PiecewiseLinearCurve;

        let mut token = BondingCurveToken::deploy(
            [12u8; 32],
            "Boundary Sell Token".to_string(),
            "BSELL".to_string(),
            CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default()),
            Threshold::ReserveAmount(100_000_000_000_000), // Very high threshold
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy tokens with large amount
        let buy_amount = 100_000_000_000; // 1000 SOV
        let (tokens_bought, _) = token
            .buy(buyer.clone(), buy_amount, 101, 1_600_000_100)
            .unwrap();

        // Verify we're in a valid band
        if let CurveType::PiecewiseLinear(ref curve) = token.curve_type {
            let band = curve.band_index_for_supply(u64::try_from(token.total_supply).unwrap_or(u64::MAX));
            assert!(
                (1..=curve.bands.len()).contains(&band),
                "Should resolve to a valid band index"
            );
        }

        let initial_supply = token.total_supply;
        let initial_reserve = token.reserve_balance;

        // Sell a small portion to ensure reserve can cover (5% of purchased tokens)
        let tokens_to_sell = find_reserve_safe_sell_amount(&token, tokens_bought / 20);
        let (sov_received, _) = token
            .sell(buyer.clone(), tokens_to_sell, 102, 1_600_000_200)
            .unwrap();

        // Verify proper burn and reserve decrease
        assert_eq!(
            token.total_supply,
            initial_supply - tokens_to_sell,
            "Supply should decrease by sold amount (burn)"
        );
        assert_eq!(
            token.reserve_balance,
            initial_reserve - sov_received,
            "Reserve should decrease by returned SOV"
        );
        assert!(sov_received > 0, "Should receive positive SOV");

        // Can sell more if reserve allows
        let remaining_owned = tokens_bought - tokens_to_sell;
        let tokens_to_sell_2 = find_reserve_safe_sell_amount(&token, remaining_owned / 25);
        let (sov_received_2, _) = token
            .sell(buyer, tokens_to_sell_2, 103, 1_600_000_300)
            .unwrap();

        assert!(sov_received_2 > 0, "Should receive SOV from second sell");
    }

    /// Issue #1845: Test sell with zero amount fails
    #[test]
    fn test_sell_zero_amount_fails() {
        let mut token = BondingCurveToken::deploy(
            [13u8; 32],
            "Zero Sell Token".to_string(),
            "ZSELL".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy some tokens first
        token.buy(buyer.clone(), 1_000_000_000, 101, 1_600_000_100).unwrap();

        // Try to sell zero tokens
        let result = token.sell(buyer, 0, 102, 1_600_000_200);
        assert!(result.is_err(), "Selling zero should fail");
        assert!(
            matches!(result, Err(CurveError::ZeroAmount)),
            "Should fail with ZeroAmount"
        );
    }

    /// Issue #1845: Test sell with excessive amount fails
    #[test]
    fn test_sell_excessive_amount_fails() {
        let mut token = BondingCurveToken::deploy(
            [14u8; 32],
            "Excessive Sell Token".to_string(),
            "ESELL".to_string(),
            CurveType::Linear {
                base_price: 10_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(10_000_000_000),
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy some tokens
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 1_000_000_000, 101, 1_600_000_100)
            .unwrap();

        // Try to sell more than bought (also exceeds reserve, so fails)
        let result = token.sell(buyer, tokens_bought + 1_000_000_000, 102, 1_600_000_200);
        assert!(result.is_err(), "Selling more than owned should fail");
        assert!(
            matches!(result, Err(CurveError::InsufficientReserve)),
            "Should fail with InsufficientReserve error"
        );
    }

    // ============================================================================
    // Issue #1846: Graduation Threshold Detection Tests
    // ============================================================================

    /// Issue #1846: Test USD-based graduation threshold with oracle.
    /// Verifies graduation triggers at exactly $269K USD reserve value.
    #[test]
    fn test_usd_graduation_threshold_269k() {
        use crate::contracts::bonding_curve::types::GRADUATION_THRESHOLD_USD;

        let mut token = BondingCurveToken::deploy(
            [20u8; 32],
            "USD Threshold Token".to_string(),
            "USDT".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveValueUsd {
                threshold_usd: GRADUATION_THRESHOLD_USD, // $269,000
                max_price_age_seconds: 300,              // 5 minutes
                confirmation_blocks: 3,                  // 3 blocks
            },
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Oracle price: $1 SOV = 100_000_000 (8-decimal)
        let sov_usd_price = 100_000_000; // $1.00

        // Calculate SOV needed for $269K USD
        // reserve_value_usd = (reserve_sov / TOKEN_SCALE) * sov_usd_price / USD_PRICE_SCALE
        // For $269K at $1 SOV: need 269,000 SOV = 26,900,000,000,000 atomic units
        let target_reserve_sov = GRADUATION_THRESHOLD_USD * TOKEN_SCALE; // 26,900,000,000,000

        // Verify the math using the actual token method
        let mut test_token = BondingCurveToken::deploy(
            [99u8; 32],
            "Test".to_string(),
            "TEST".to_string(),
            CurveType::Linear { base_price: 1, slope: 0 },
            Threshold::ReserveAmount(1),
            true,
            test_pubkey(1),
            String::new(),
            1,
            1,
        ).unwrap();
        test_token.reserve_balance = target_reserve_sov;
        let calculated_usd = test_token.reserve_value_usd(sov_usd_price).unwrap();
        assert_eq!(calculated_usd, GRADUATION_THRESHOLD_USD, "Math check failed: got ${}", calculated_usd);

        token.reserve_balance = target_reserve_sov - 1;

        // Verify reserve is just below threshold
        assert!(
            token.reserve_balance < target_reserve_sov,
            "Reserve should be below threshold: {} < {}",
            token.reserve_balance,
            target_reserve_sov
        );

        // Check graduation with oracle - should not meet threshold yet
        let can_graduate = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_100, // Price timestamp
            101,           // Current block
            1_600_000_100, // Current timestamp
        );
        assert!(!can_graduate, "Should not graduate below threshold");

        token.reserve_balance = target_reserve_sov;
        assert!(
            token.reserve_balance >= target_reserve_sov,
            "Reserve should be at or above threshold: {} >= {}",
            token.reserve_balance,
            target_reserve_sov
        );

        // First check - should set pending but not graduate yet (confirmation period)
        let can_graduate = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_200,
            102,
            1_600_000_200,
        );
        assert!(!can_graduate, "Should not graduate immediately (confirmation period)");
        assert!(token.is_graduation_pending(), "Graduation should be pending");

        // Check at block 105 (3 blocks after pending started)
        let can_graduate = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_500,
            105,
            1_600_000_500,
        );
        assert!(can_graduate, "Should graduate after confirmation period");
    }

    /// Issue #1846: Test stale oracle price prevents graduation.
    /// Safety mechanism: Graduation fails if oracle price is too old.
    #[test]
    fn test_usd_graduation_rejects_stale_oracle_price() {
        use crate::contracts::bonding_curve::types::MAX_ORACLE_PRICE_AGE_SECONDS;

        let mut token = BondingCurveToken::deploy(
            [21u8; 32],
            "Stale Price Token".to_string(),
            "STALE".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveValueUsd {
                threshold_usd: 100_000,     // $100K for easier testing
                max_price_age_seconds: 300, // 5 minutes max
                confirmation_blocks: 1,
            },
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token.reserve_balance = 100_000 * TOKEN_SCALE;

        let sov_usd_price = 100_000_000; // $1.00

        // Price is fresh - should work (confirmation period of 1 block)
        // First call sets pending
        let _ = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_100,                  // Price timestamp (fresh)
            102,                            // Current block
            1_600_000_100, // Fresh timestamp
        );
        // Second call at block 103 should graduate
        let can_graduate = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_100 + MAX_ORACLE_PRICE_AGE_SECONDS - 10, // Fresh
            103,                                               // Next block
            1_600_000_100 + MAX_ORACLE_PRICE_AGE_SECONDS - 10,
        );
        assert!(can_graduate, "Should graduate with fresh price");

        // Reset pending state
        token.graduation_pending_since_block = None;

        // Price is stale - should fail
        let can_graduate = token.check_graduation_with_oracle(
            sov_usd_price,
            1_600_000_100,                      // Price timestamp (old)
            104,                                // Current block
            1_600_000_100 + MAX_ORACLE_PRICE_AGE_SECONDS + 10, // Over max age
        );
        assert!(!can_graduate, "Should NOT graduate with stale price");
    }

    /// Issue #1846: Test confirmation period prevents premature graduation.
    /// Safety mechanism: Must wait N blocks after threshold detected.
    #[test]
    fn test_usd_graduation_confirmation_period() {
        use crate::contracts::bonding_curve::types::GRADUATION_CONFIRMATION_BLOCKS;

        let mut token = BondingCurveToken::deploy(
            [22u8; 32],
            "Confirmation Token".to_string(),
            "CONF".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveValueUsd {
                threshold_usd: 100_000,
                max_price_age_seconds: 300,
                confirmation_blocks: GRADUATION_CONFIRMATION_BLOCKS, // 3 blocks
            },
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token.reserve_balance = 100_000 * TOKEN_SCALE;

        let sov_usd_price = 100_000_000; // $1.00
        let price_timestamp = 1_600_000_100;

        // Block 102 - First detection (pending set)
        let can_graduate =
            token.check_graduation_with_oracle(sov_usd_price, price_timestamp, 102, price_timestamp);
        assert!(!can_graduate, "Should not graduate at first detection");
        assert!(token.is_graduation_pending(), "Should be pending");
        assert_eq!(token.blocks_until_graduation(102), 3, "Should need 3 more blocks");

        // Block 103 - 1 block later
        let can_graduate =
            token.check_graduation_with_oracle(sov_usd_price, price_timestamp, 103, price_timestamp);
        assert!(!can_graduate, "Should not graduate after 1 block");
        assert_eq!(token.blocks_until_graduation(103), 2, "Should need 2 more blocks");

        // Block 104 - 2 blocks later
        let can_graduate =
            token.check_graduation_with_oracle(sov_usd_price, price_timestamp, 104, price_timestamp);
        assert!(!can_graduate, "Should not graduate after 2 blocks");
        assert_eq!(token.blocks_until_graduation(104), 1, "Should need 1 more block");

        // Block 105 - 3 blocks later (confirmation met)
        let can_graduate =
            token.check_graduation_with_oracle(sov_usd_price, price_timestamp, 105, price_timestamp);
        assert!(can_graduate, "Should graduate after confirmation period");
        assert_eq!(token.blocks_until_graduation(105), 0, "Should be ready");
    }

    /// Issue #1846: Test reserve value calculation with different oracle prices.
    #[test]
    fn test_reserve_value_usd_calculation() {
        let token = BondingCurveToken::deploy(
            [23u8; 32],
            "Value Calc Token".to_string(),
            "VAL".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveValueUsd {
                threshold_usd: 269_000,
                max_price_age_seconds: 300,
                confirmation_blocks: 3,
            },
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Test with different oracle prices
        // reserve_value_usd = (reserve_sov * sov_usd_price) / USD_PRICE_SCALE

        // Empty reserve = $0
        let value1 = token.reserve_value_usd(100_000_000).unwrap(); // $1.00
        assert_eq!(value1, 0, "Empty reserve = $0");

        let mut token2 = token;
        token2.reserve_balance = 4_000 * TOKEN_SCALE;

        // Check reserve balance
        let reserve_sov = token2.reserve_balance;
        assert_eq!(reserve_sov, 4_000 * TOKEN_SCALE, "Reserve should be 4000 SOV");

        // $1.00 SOV price, 4000 SOV reserve = $4,000
        let value2 = token2.reserve_value_usd(100_000_000).unwrap();
        assert_eq!(value2, 4000, "4000 SOV at $1 = $4,000");

        // $2.00 SOV price, 4000 SOV reserve = $8,000
        let value3 = token2.reserve_value_usd(200_000_000).unwrap();
        assert_eq!(value3, 8000, "4000 SOV at $2 = $8,000");

        // $0.50 SOV price, 4000 SOV reserve = $2,000
        let value4 = token2.reserve_value_usd(50_000_000).unwrap();
        assert_eq!(value4, 2000, "4000 SOV at $0.50 = $2,000");
    }

    /// Issue #1846: Test graduation clears pending state.
    #[test]
    fn test_graduation_clears_pending_state() {
        let mut token = BondingCurveToken::deploy(
            [24u8; 32],
            "Clear Pending Token".to_string(),
            "CLR".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveValueUsd {
                threshold_usd: 100_000,
                max_price_age_seconds: 300,
                confirmation_blocks: 1,
            },
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        token.reserve_balance = 100_000 * TOKEN_SCALE;

        // Trigger graduation (block 102 sets pending, block 103 graduates)
        let _ = token.check_graduation_with_oracle(100_000_000, 1_600_000_100, 102, 1_600_000_100);
        assert!(
            token.check_graduation_with_oracle(100_000_000, 1_600_000_100, 103, 1_600_000_100),
            "Should be able to graduate"
        );

        // Verify pending state exists
        assert!(token.is_graduation_pending(), "Should be pending");
        assert!(token.graduation_pending_since_block.is_some(), "Should have pending block");

        // Graduate
        token.graduate(1_600_000_200, 103).unwrap();

        // Verify pending state is cleared
        assert!(!token.is_graduation_pending(), "Should not be pending after graduation");
        assert!(token.graduation_pending_since_block.is_none(), "Pending block should be cleared");
        assert!(matches!(token.phase, Phase::Graduated), "Should be graduated");
    }

    /// Issue #1846: Test non-USD threshold still works.
    #[test]
    fn test_non_usd_threshold_unchanged() {
        let mut token = BondingCurveToken::deploy(
            [25u8; 32],
            "Non-USD Token".to_string(),
            "NONUSD".to_string(),
            CurveType::Linear {
                base_price: 1_000_000,
                slope: 0,
            },
            Threshold::ReserveAmount(5_000_000_000), // 5000 SOV
            true,
            test_pubkey(1),
            String::new(),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);

        // Buy enough to reach threshold (need 12,500 SOV at 40% split)
        token.buy(buyer.clone(), 10_000_000_000, 101, 1_600_000_100).unwrap();
        assert!(!token.can_graduate(1_600_000_100, 101), "Should not graduate yet");

        token.buy(buyer, 3_000_000_000, 102, 1_600_000_200).unwrap();
        assert!(token.can_graduate(1_600_000_200, 102), "Should graduate at reserve threshold");

        // Oracle check should delegate to standard can_graduate for non-USD thresholds
        let can_graduate = token.check_graduation_with_oracle(
            100_000_000,   // SOV price
            1_600_000_200, // Price timestamp
            103,           // Current block
            1_600_000_300, // Current timestamp
        );
        assert!(can_graduate, "Oracle check should work for non-USD thresholds");
    }

    // ============================================================================
    // Issue #1846: Staleness and sub-SOV precision tests
    // ============================================================================

    /// Verifies that `is_met_with_oracle` returns false when `price_age_seconds`
    /// exceeds `max_price_age_seconds`, regardless of whether the reserve value
    /// would otherwise satisfy the threshold.
    #[test]
    fn test_is_met_with_oracle_stale_price_rejected() {
        let threshold = Threshold::ReserveValueUsd {
            threshold_usd: 100_000,   // $100K
            max_price_age_seconds: 300,
            confirmation_blocks: 3,
        };

        // Reserve at exactly $100K worth at $1.00: 100_000 SOV atomic = 10_000_000_000_000
        let reserve_sov: u128 = 100_000 * TOKEN_SCALE;
        let sov_usd_price: u128 = 100_000_000; // $1.00 (8-decimal)

        // Fresh price — threshold met
        assert!(
            threshold.is_met_with_oracle(reserve_sov, sov_usd_price, 0, 0),
            "fresh price at exact threshold should be met"
        );

        // Price age exactly at limit — still fresh
        assert!(
            threshold.is_met_with_oracle(reserve_sov, sov_usd_price, 300, 0),
            "price at max_price_age_seconds boundary should be met"
        );

        // Price age one second past limit — stale, must be rejected
        assert!(
            !threshold.is_met_with_oracle(reserve_sov, sov_usd_price, 301, 0),
            "price one second past max_price_age_seconds must be rejected (StalePrice)"
        );

        // Stale price far in the past — also rejected
        assert!(
            !threshold.is_met_with_oracle(reserve_sov, sov_usd_price, 86_400, 0),
            "day-old price must be rejected (StalePrice)"
        );
    }

    /// Verifies that the USD-value calculation does not truncate fractional SOV
    /// before multiplying by the oracle price.
    ///
    /// At $1.50 / SOV:
    ///   exact threshold reserve = ⌈$100_000 × 1e16 / 150_000_000⌉ = 6_666_666_666_667 atomic SOV
    ///
    /// The old divide-first formula truncated to 66_666 whole SOV → $99_999, which is
    /// below the threshold even though the reserve held sufficient atomic units.
    /// The full-precision formula (multiply first) yields $100_000 exactly.
    #[test]
    fn test_is_met_with_oracle_sub_sov_precision_at_boundary() {
        let threshold = Threshold::ReserveValueUsd {
            threshold_usd: 100_000,    // $100K
            max_price_age_seconds: 300,
            confirmation_blocks: 0,
        };

        // $1.50 / SOV in 8-decimal fixed-point
        let sov_usd_price: u128 = 150_000_000;

        // Minimum atomic reserve that meets $100K at $1.50:
        //   100_000 * (1e18 * 1e8) / 150_000_000 = 66_666_666_666_666_666_666_666.67
        //   → ceil = 66_666_666_666_666_666_666_667
        let exact_reserve: u128 = 66_666_666_666_666_666_666_667;
        // One atomic unit less — must NOT meet threshold
        let below_reserve: u128 = exact_reserve - 1;

        // below_reserve falls one atomic unit short of the threshold
        assert!(
            !threshold.is_met_with_oracle(below_reserve, sov_usd_price, 0, 0),
            "reserve one atomic unit below threshold should NOT meet threshold"
        );

        // exact_reserve is the first atomic unit count that reaches the threshold
        assert!(
            threshold.is_met_with_oracle(exact_reserve, sov_usd_price, 0, 0),
            "reserve at exact atomic boundary should meet threshold (no sub-SOV truncation)"
        );

        // The old truncating formula would yield the same result for both cases
        // (both truncate to 66_666 whole SOV → $99_999 → false), demonstrating
        // that it incorrectly rejected the exact_reserve case.
        let old_formula_exact = {
            let whole_sov = exact_reserve / TOKEN_SCALE; // 66_666 (truncated)
            (whole_sov as u128 * sov_usd_price as u128) / USD_PRICE_SCALE
        };
        assert_eq!(
            old_formula_exact, 99_999,
            "old divide-first formula truncates 6_666_666_666_667 to 66_666 SOV → $99,999"
        );
        // Confirm the new formula gives the correct $100,000
        let new_formula_exact = {
            (exact_reserve as u128 * sov_usd_price as u128)
                / (TOKEN_SCALE as u128 * USD_PRICE_SCALE)
        };
        assert_eq!(
            new_formula_exact, 100_000,
            "full-precision formula correctly yields $100,000 for the exact atomic boundary"
        );
    }
}
