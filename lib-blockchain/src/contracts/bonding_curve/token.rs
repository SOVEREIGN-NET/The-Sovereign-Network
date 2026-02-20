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

use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use super::{
    types::{CurveError, CurveStats, CurveType, Phase, Threshold},
    events::{BondingCurveEvent, ReserveUpdateReason},
};

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
    /// Token decimals (typically 8)
    pub decimals: u8,

    // === Phase State ===
    /// Current lifecycle phase
    pub phase: Phase,

    // === Curve State ===
    /// Total token supply in circulation
    pub total_supply: u64,
    /// Reserve balance in stablecoin (e.g., USDC)
    pub reserve_balance: u64,
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
    /// Block height at deployment
    pub deployed_at_block: u64,
    /// Timestamp at deployment
    pub deployed_at_timestamp: u64,
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
        deployed_at_block: u64,
        deployed_at_timestamp: u64,
    ) -> Result<Self, CurveError> {
        // Validate parameters
        if name.is_empty() {
            return Err(CurveError::InvalidParameters("Name cannot be empty".to_string()));
        }
        if symbol.is_empty() {
            return Err(CurveError::InvalidParameters("Symbol cannot be empty".to_string()));
        }
        if symbol.len() > 10 {
            return Err(CurveError::InvalidParameters("Symbol too long (max 10)".to_string()));
        }

        Ok(Self {
            token_id,
            name,
            symbol,
            decimals: 8,
            phase: Phase::Curve,
            total_supply: 0,
            reserve_balance: 0,
            curve_type,
            threshold,
            sell_enabled,
            amm_pool_id: None,
            creator,
            deployed_at_block,
            deployed_at_timestamp,
        })
    }

    /// Calculate current price based on curve formula
    ///
    /// # Returns
    /// Price per token in stablecoin atomic units
    pub fn current_price(&self) -> u64 {
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
    pub fn calculate_buy(&self, stable_amount: u64) -> Result<u64, CurveError> {
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
        let tokens = (stable_amount as u128)
            .checked_mul(100_000_000) // Token decimals
            .ok_or(CurveError::Overflow)?
            .checked_div(price as u128)
            .ok_or(CurveError::Overflow)? as u64;

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
    pub fn calculate_sell(&self, token_amount: u64) -> Result<u64, CurveError> {
        if token_amount == 0 {
            return Err(CurveError::ZeroAmount);
        }

        self.require_phase(Phase::Curve)?;

        if !self.sell_enabled {
            return Err(CurveError::InvalidParameters("Selling is disabled".to_string()));
        }

        let price = self.current_price();

        // stable = token_amount × price / token_decimals
        let stable = (token_amount as u128)
            .checked_mul(price as u128)
            .ok_or(CurveError::Overflow)?
            .checked_div(100_000_000)
            .ok_or(CurveError::Overflow)? as u64;

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
    pub fn buy(
        &mut self,
        buyer: PublicKey,
        stable_amount: u64,
        block_height: u64,
        timestamp: u64,
    ) -> Result<(u64, BondingCurveEvent), CurveError> {
        let token_amount = self.calculate_buy(stable_amount)?;

        // Update state
        self.reserve_balance = self
            .reserve_balance
            .checked_add(stable_amount)
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
        token_amount: u64,
        block_height: u64,
        timestamp: u64,
    ) -> Result<(u64, BondingCurveEvent), CurveError> {
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

    /// Check if graduation threshold is met
    ///
    /// # Arguments
    /// * `current_timestamp` - Current timestamp for time-based checks
    pub fn can_graduate(&self, current_timestamp: u64) -> bool {
        if self.phase != Phase::Curve {
            return false;
        }

        let elapsed = current_timestamp.saturating_sub(self.deployed_at_timestamp);
        self.threshold.is_met(self.reserve_balance, self.total_supply, elapsed)
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
        if !self.can_graduate(current_timestamp) {
            return Err(CurveError::ThresholdNotMet);
        }

        self.phase = Phase::Graduated;

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
    pub fn get_stats(&self, current_timestamp: u64) -> CurveStats {
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
            _ => 0, // Complex thresholds simplified
        };

        CurveStats {
            total_supply: self.total_supply,
            reserve_balance: self.reserve_balance,
            current_price: self.current_price(),
            elapsed_seconds: elapsed,
            graduation_progress_percent: progress.min(100),
            can_graduate: self.can_graduate(current_timestamp),
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
                base_price: 10_000_000,
                slope: 0, // Constant price for simplicity
            },
            Threshold::ReserveAmount(1_000_000_000),
            true,
            test_pubkey(1),
            100,
            1_600_000_000,
        )
        .unwrap();

        let buyer = test_pubkey(2);
        let (tokens, event) = token.buy(buyer, 100_000_000, 101, 1_600_000_001).unwrap();

        // At $0.10 price, $1 = 10 tokens
        assert_eq!(tokens, 1_000 * 100_000_000); // 1000 tokens
        assert_eq!(token.total_supply, tokens);
        assert_eq!(token.reserve_balance, 100_000_000);

        match event {
            BondingCurveEvent::TokenPurchased { stable_amount, .. } => {
                assert_eq!(stable_amount, 100_000_000);
            }
            _ => panic!("Expected TokenPurchased event"),
        }
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
            100,
            1_600_000_000,
        )
        .unwrap();

        // Buy enough to trigger graduation
        let _ = token.buy(test_pubkey(2), 200, 101, 1_600_000_001).unwrap();

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
            Threshold::ReserveAmount(1_000_000_000), // $10M
            true,
            test_pubkey(1),
            100,
            1_600_000_000,
        )
        .unwrap();

        // Not enough reserve
        let _ = token.buy(test_pubkey(2), 100_000_000, 101, 1_600_000_001).unwrap();
        assert!(!token.can_graduate(1_600_000_001));

        // Add more to reach threshold
        let _ = token.buy(test_pubkey(3), 900_000_000, 102, 1_600_000_002).unwrap();
        assert!(token.can_graduate(1_600_000_002));

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
            100,
            1_600_000_000,
        )
        .unwrap();

        // Graduate first
        let _ = token.buy(test_pubkey(2), 200, 101, 1_600_000_001).unwrap();
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
}
