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
    events::BondingCurveEvent,
    types::{CurveError, CurveStats, CurveType, Phase, Threshold},
};
use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};

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
    /// Reserve balance in stablecoin (20% of purchases - backs bonding curve)
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
    /// Creator DID (populated when deployer has a registered on-chain identity)
    #[serde(default)]
    pub creator_did: Option<String>,
    /// Block height at deployment
    pub deployed_at_block: u64,
    /// Timestamp at deployment
    pub deployed_at_timestamp: u64,
    /// Treasury balance in stablecoin (80% of purchases - protocol operations)
    /// Issue #1844: Reserve and Treasury 20/80 Split
    /// NOTE: Field is at end of struct intentionally — bincode is positional.
    /// Adding fields mid-struct corrupts deserialization of existing stored tokens.
    #[serde(default)]
    pub treasury_balance: u64,
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
            decimals: 8,
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
            return Err(CurveError::InvalidParameters(
                "Selling is disabled".to_string(),
            ));
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
    /// Buy tokens from the curve
    ///
    /// Implements Issue #1844: 20%/80% split between reserve and treasury
    /// - 20% goes to reserve pool (backs the bonding curve)
    /// - 80% goes to treasury (protocol operations)
    pub fn buy(
        &mut self,
        buyer: PublicKey,
        stable_amount: u64,
        block_height: u64,
        timestamp: u64,
    ) -> Result<(u64, BondingCurveEvent), CurveError> {
        let token_amount = self.calculate_buy(stable_amount)?;

        // Issue #1844: Split purchase 20% reserve / 80% treasury
        let to_reserve = stable_amount / 5;           // 20% - overflow-safe
        let to_treasury = stable_amount - to_reserve; // 80%

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
        self.threshold
            .is_met(self.reserve_balance, self.total_supply, elapsed)
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
            treasury_balance: self.treasury_balance,
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
        // Buy with $1 (100_000_000 in stable atomic units with 6 decimals)
        let (tokens, event) = token.buy(buyer, 100_000_000, 101, 1_600_000_001).unwrap();

        // At $0.10 price, $1 buys 10 tokens
        // tokens = stable_amount / price * token_decimals
        // tokens = 100_000_000 / 10_000_000 * 100_000_000 = 1_000_000_000 (10 tokens)
        assert_eq!(tokens, 1_000_000_000); // 10 tokens
        assert_eq!(token.total_supply, tokens);
        
        // Issue #1844: Verify 20/80 split
        // Reserve gets 20%: 100_000_000 * 0.20 = 20_000_000
        // Treasury gets 80%: 100_000_000 * 0.80 = 80_000_000
        assert_eq!(token.reserve_balance, 20_000_000, "Reserve should get 20%");
        assert_eq!(token.treasury_balance, 80_000_000, "Treasury should get 80%");

        match event {
            BondingCurveEvent::TokenPurchased { stable_amount, .. } => {
                assert_eq!(stable_amount, 100_000_000);
            }
            _ => panic!("Expected TokenPurchased event"),
        }
    }

    #[test]
    fn test_buy_reserve_treasury_split_1844() {
        // Issue #1844: Test the 20/80 reserve/treasury split
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
        // Purchase 1: $100 (10_000_000_000 in micro-USD)
        let _ = token.buy(buyer.clone(), 10_000_000_000, 101, 1_600_000_001).unwrap();
        assert_eq!(token.reserve_balance, 2_000_000_000, "20% of $100");
        assert_eq!(token.treasury_balance, 8_000_000_000, "80% of $100");
        
        // Purchase 2: $50 (5_000_000_000 in micro-USD)
        let _ = token.buy(buyer, 5_000_000_000, 102, 1_600_000_002).unwrap();
        assert_eq!(token.reserve_balance, 3_000_000_000, "20% of $150");
        assert_eq!(token.treasury_balance, 12_000_000_000, "80% of $150");
        
        // Verify total collected equals sum of all purchases
        assert_eq!(
            token.reserve_balance + token.treasury_balance,
            15_000_000_000,
            "Total should equal sum of purchases"
        );
        
        // Verify split ratio is exactly 20/80 using integer arithmetic
        let total = token.reserve_balance + token.treasury_balance;
        assert_eq!(token.reserve_balance * 10000 / total, 2000, "Reserve should be exactly 20%");
        assert_eq!(token.treasury_balance * 10000 / total, 8000, "Treasury should be exactly 80%");
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

        // Buy enough to trigger graduation (need 500 total for 100 reserve at 20% split)
        let _ = token.buy(test_pubkey(2), 500, 101, 1_600_000_001).unwrap();
        assert!(token.can_graduate(1_600_000_001));

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

        // Issue #1844: With 20% split, need 5x more purchases to reach reserve threshold
        // Not enough reserve (100M purchase → 20M reserve)
        let _ = token
            .buy(test_pubkey(2), 100_000_000, 101, 1_600_000_001)
            .unwrap();
        assert!(!token.can_graduate(1_600_000_001));

        // Add more to reach threshold (need 5B total purchases for 1B reserve)
        let _ = token
            .buy(test_pubkey(3), 4_900_000_000, 102, 1_600_000_002)
            .unwrap();
        assert!(token.can_graduate(1_600_000_002));
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

        // Graduate first (need 500 for 100 reserve at 20% split)
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
            Threshold::ReserveAmount(5_000_000_000), // $5,000 graduation threshold
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
        // Issue #1844: With 20% split, need 5x purchases to reach same reserve
        let buyer1 = test_pubkey(10);
        let buyer2 = test_pubkey(20);
        let buyer3 = test_pubkey(30);

        // Buyer 1: $5000 → $1000 reserve, ~100,000 tokens at $0.05
        let (tokens1, event1) = token
            .buy(buyer1.clone(), 5_000_000_000, 101, 1_700_000_100)
            .unwrap();
        assert!(tokens1 > 0);
        assert_eq!(token.reserve_balance, 1_000_000_000, "Reserve gets 20% = $1K");
        assert_eq!(token.treasury_balance, 4_000_000_000, "Treasury gets 80% = $4K");
        assert!(!token.can_graduate(1_700_000_100)); // Not enough for graduation (need $5K reserve)

        // Buyer 2: $10000 → $2000 more reserve, total $3000
        let (tokens2, _event2) = token
            .buy(buyer2, 10_000_000_000, 102, 1_700_000_200)
            .unwrap();
        assert!(tokens2 > 0);
        assert_eq!(token.reserve_balance, 3_000_000_000, "Reserve = $3K");
        assert!(!token.can_graduate(1_700_000_200)); // Still not graduated (need $5K)

        // Buyer 3: $12500 → $2500 more reserve, total $5500
        let (tokens3, _event3) = token
            .buy(buyer3, 12_500_000_000, 103, 1_700_000_300)
            .unwrap();
        assert!(tokens3 > 0);
        assert_eq!(token.reserve_balance, 5_500_000_000, "Reserve = $5.5K");
        assert!(token.can_graduate(1_700_000_300), "NOW ready to graduate!");

        // Verify events
        match event1 {
            BondingCurveEvent::TokenPurchased {
                buyer,
                stable_amount,
                ..
            } => {
                assert_eq!(buyer, buyer1.key_id);
                assert_eq!(stable_amount, 5_000_000_000); // Updated for 20/80 split test
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
                assert_eq!(final_reserve, 5_500_000_000);
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
        assert_eq!(token.reserve_balance, 5_500_000_000);
        assert!(token.current_price() > 5_000_000); // Price increased due to curve

        // Verify stats
        let stats = token.get_stats(1_700_000_600);
        assert_eq!(stats.total_supply, token.total_supply);
        assert_eq!(stats.reserve_balance, 5_500_000_000);
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

        // Issue #1844: With 20% split, need to buy more to have enough reserve for selling
        // Buy 250 tokens ($25) → need $25 purchase = 2_500_000_000
        // Reserve gets 20% = 500_000_000
        // To sell 50 tokens ($5), need 500_000_000 in reserve
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 2_500_000_000, 101, 1_600_000_100)
            .unwrap();
        // At $0.10, $25 buys 250 tokens
        assert_eq!(tokens_bought, 25_000_000_000, "Should get 250 tokens");
        assert_eq!(token.reserve_balance, 500_000_000, "Reserve should be 20% of $25 = $5");
        assert_eq!(token.treasury_balance, 2_000_000_000, "Treasury should be 80% of $25 = $20");

        // Sell 50 tokens back ($5)
        let (stable_received, sell_event) = token
            .sell(buyer.clone(), 5_000_000_000, 102, 1_600_000_200)
            .unwrap();
        assert_eq!(stable_received, 500_000_000, "Should receive $5");
        assert_eq!(token.total_supply, 20_000_000_000, "200 tokens remaining");
        assert_eq!(token.reserve_balance, 0, "Reserve depleted after sell");

        match sell_event {
            BondingCurveEvent::TokenSold {
                seller,
                token_amount,
                stable_amount,
                ..
            } => {
                assert_eq!(seller, buyer.key_id);
                assert_eq!(token_amount, 5_000_000_000);
                assert_eq!(stable_amount, 500_000_000);
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
    /// NOTE: Due to the 20/80 split (Issue #1844), the reserve only has 20% of SOV paid.
    /// The bonding curve pricing means tokens may be worth more than 20% of purchase price,
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
        assert_eq!(token.reserve_balance, buy_amount / 5, "Reserve should be 20% of buy amount");
        assert_eq!(token.treasury_balance, buy_amount * 4 / 5, "Treasury should be 80% of buy amount");

        // IMPORTANT: Due to 20/80 split, we can only sell a small % of tokens.
        // The reserve only has 20% of SOV, but tokens are priced at current market rate.
        // We sell just 5% of purchased tokens to ensure reserve can cover.
        let tokens_to_sell = tokens_bought / 20;
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
        assert_eq!(token.treasury_balance, buy_amount * 4 / 5, "Treasury should remain unchanged after sell");
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

        // Buy tokens - with 20/80 split, need 25 SOV to put 5 SOV in reserve (for graduation)
        // With $0.01 per token, 25 SOV buys 2500 tokens
        let (tokens_bought, _) = token
            .buy(buyer.clone(), 25_000_000_000, 101, 1_600_000_100)
            .unwrap();

        // Verify still in curve phase (buy doesn't auto-graduate)
        assert_eq!(token.reserve_balance, 5_000_000_000, "Reserve should be 5 SOV");
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

        // Reserve is only 20% of buy = 20 SOV cents
        assert_eq!(token.reserve_balance, 20_000_000);

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
    /// NOTE: Due to 20/80 split, we can only sell ~20% of tokens back before reserve is depleted.
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
        let mut total_sold: u64 = 0;
        for i in 0..5 {
            let remaining_reserve = token.reserve_balance;
            let current_price = token.current_price();
            // Calculate max tokens we can sell with remaining reserve
            let max_tokens = (remaining_reserve as u128 * 100_000_000 / current_price.max(1) as u128) as u64;
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
    /// NOTE: Due to 20/80 split, reserve only has 20% of SOV paid.
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
        // With 20% in reserve, we can sell at most ~20% of tokens (at constant price)
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
    /// NOTE: Due to 20/80 split, reserve only has 20% of SOV paid.
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
            let band = curve.band_index_for_supply(token.total_supply);
            assert_eq!(band, 1, "Should be in band 1 with moderate buy amount");
        }

        let initial_supply = token.total_supply;
        let initial_reserve = token.reserve_balance;

        // Sell a small portion to ensure reserve can cover (5% of purchased tokens)
        let tokens_to_sell = tokens_bought / 20;
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
        let tokens_to_sell_2 = remaining_owned / 25; // Another 4%
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
}
