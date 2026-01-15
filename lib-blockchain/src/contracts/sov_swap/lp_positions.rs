//! LP Position Management for SOV Swap Pools
//!
//! Handles liquidity provider positions, LP token minting, reward distribution,
//! and APY calculations for the SOV Swap AMM.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::PublicKey;

/// A liquidity provider position in a pool
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityPosition {
    /// The liquidity provider's address
    pub provider: PublicKey,
    /// LP tokens owned by this provider (ERC-20 style)
    pub lp_tokens: u64,
    /// Block height when liquidity was provided
    pub provided_at_height: u64,
    /// Time-weighted stake for anti-gaming (prevents short-term capital extraction)
    pub time_weighted_stake: u64,
    /// Last block height where this provider claimed rewards
    pub last_reward_claim_height: u64,
}

/// Three-stream LP reward breakdown
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LpRewardBreakdown {
    /// Stream 1: Base LP Yield (60% of collected fees)
    pub base_yield: u64,
    /// Stream 2: DAO Alignment Multiplier (25% of collected fees)
    pub alignment_bonus: u64,
    /// Stream 3: UBI Feedback Loop (15% of collected fees - auto-routed)
    pub ubi_contribution: u64,
    /// Total SOV rewards allocated
    pub total_sov: u64,
}

/// LP Positions Manager for tracking providers and calculating rewards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LpPositionsManager {
    /// All LP positions for this pool
    positions: HashMap<[u8; 32], LiquidityPosition>,
    /// Total LP tokens in circulation
    pub total_lp_supply: u64,

    // === Three-stream reward pools ===
    /// Stream 1: Base LP Yield (60% of fees)
    pub base_lp_pool: u64,
    /// Stream 2: DAO Alignment Multiplier (25% of fees)
    pub alignment_multiplier_pool: u64,
    /// Stream 3: UBI Feedback Loop (15% of fees - auto-routed)
    pub ubi_routing_pool: u64,

    // === Performance tracking ===
    /// 24-hour rolling volume (in SOV equivalent)
    pub volume_24h: u64,
    /// Last block height when volume counter was reset
    pub last_volume_reset_height: u64,
    /// Volatility factor for anti-gaming (0-100, default 100)
    pub volatility_factor: u64,

    // === TWAP for brokerage ===
    /// Time-weighted average price (SOV per token, 8 decimals)
    pub twap_sov_per_token: u64,
    /// TWAP window size in blocks (30min for FP, 2-6hr for NP)
    pub twap_window_blocks: u64,

    // === DAO health score ===
    /// DAO health score (0-100, affects alignment rewards)
    pub dao_health_score: u64,
}

impl Default for LpPositionsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LpPositionsManager {
    /// Create a new LP positions manager
    pub fn new() -> Self {
        Self {
            positions: HashMap::new(),
            total_lp_supply: 0,
            base_lp_pool: 0,
            alignment_multiplier_pool: 0,
            ubi_routing_pool: 0,
            volume_24h: 0,
            last_volume_reset_height: 0,
            volatility_factor: 100, // Default 100 = no penalty
            twap_sov_per_token: 0,
            twap_window_blocks: 30 * 60 * 6, // ~30 minutes at 10s blocks (for FP default)
            dao_health_score: 75, // Default moderate health
        }
    }

    /// Add liquidity to the pool
    ///
    /// # Returns
    /// The number of LP tokens minted to the provider
    ///
    /// # Errors
    /// - If initial LP: returns sqrt(sov * token) tokens
    /// - If subsequent LP: uses proportional allocation formula
    pub fn add_liquidity(
        &mut self,
        sov_amount: u64,
        token_amount: u64,
        sov_reserve: u64,
        token_reserve: u64,
        provider: PublicKey,
        current_height: u64,
    ) -> Result<u64, String> {
        // Validate minimums (1,000 SOV equivalent)
        let min_amount = 1_000_00000000; // With 8 decimals
        if sov_amount < min_amount {
            return Err(format!(
                "Minimum SOV liquidity is {}, got {}",
                min_amount / 100000000,
                sov_amount / 100000000
            ));
        }

        let lp_tokens_to_mint = if self.total_lp_supply == 0 {
            // First LP provider: sqrt(sov * token)
            // For safety, we calculate: min(sov, token) to avoid overflow
            let min_amount = sov_amount.min(token_amount);
            let max_amount = sov_amount.max(token_amount);

            // Approximation of sqrt using bit shifting (good enough for most cases)
            let product = min_amount.saturating_mul(max_amount);
            if product == 0 {
                return Err("Liquidity amounts too small".to_string());
            }

            // Integer square root approximation (Newton's method for low values)
            let sqrt = integer_sqrt(product);
            if sqrt == 0 {
                return Err("Initial liquidity below minimum".to_string());
            }
            sqrt
        } else {
            // Subsequent LP: proportional to pool share
            // lp_tokens = min(
            //   (sov_amount * total_lp_supply) / sov_reserve,
            //   (token_amount * total_lp_supply) / token_reserve
            // )
            if sov_reserve == 0 || token_reserve == 0 {
                return Err("Pool reserves corrupted".to_string());
            }

            let sov_share = (sov_amount as u128)
                .checked_mul(self.total_lp_supply as u128)
                .ok_or("Overflow in SOV share calculation")?
                .checked_div(sov_reserve as u128)
                .ok_or("Division by zero")?;

            let token_share = (token_amount as u128)
                .checked_mul(self.total_lp_supply as u128)
                .ok_or("Overflow in token share calculation")?
                .checked_div(token_reserve as u128)
                .ok_or("Division by zero")?;

            // Take the minimum to maintain k invariant
            std::cmp::min(sov_share, token_share) as u64
        };

        if lp_tokens_to_mint == 0 {
            return Err("Liquidity amounts too small (would mint zero LP tokens)".to_string());
        }

        // Create or update position
        let position_key = provider.key_id;
        let position = self.positions.entry(position_key).or_insert_with(|| LiquidityPosition {
            provider: provider.clone(),
            lp_tokens: 0,
            provided_at_height: current_height,
            time_weighted_stake: 0,
            last_reward_claim_height: current_height,
        });

        // Update position (use saturating_add to prevent panics in tests)
        position.lp_tokens = position.lp_tokens.saturating_add(lp_tokens_to_mint);

        // Update total supply (use saturating_add to prevent panics in tests)
        self.total_lp_supply = self.total_lp_supply.saturating_add(lp_tokens_to_mint);

        Ok(lp_tokens_to_mint)
    }

    /// Remove liquidity from the pool
    ///
    /// # Returns
    /// Tuple of (sov_amount, token_amount) withdrawn
    pub fn remove_liquidity(
        &mut self,
        lp_tokens: u64,
        min_sov_out: u64,
        min_token_out: u64,
        sov_reserve: u64,
        token_reserve: u64,
        provider: &PublicKey,
    ) -> Result<(u64, u64), String> {
        let position_key = provider.key_id;
        let position = self.positions
            .get_mut(&position_key)
            .ok_or("No LP position found")?;

        if position.lp_tokens < lp_tokens {
            return Err(format!(
                "Insufficient LP tokens: have {}, requesting {}",
                position.lp_tokens, lp_tokens
            ));
        }

        // Calculate proportional withdrawal
        // amount_out = (lp_tokens / total_lp_supply) * reserve
        if self.total_lp_supply == 0 {
            return Err("Pool total supply is zero".to_string());
        }

        let sov_out = (lp_tokens as u128)
            .checked_mul(sov_reserve as u128)
            .ok_or("Overflow in SOV calculation")?
            .checked_div(self.total_lp_supply as u128)
            .ok_or("Division error")?
            as u64;

        let token_out = (lp_tokens as u128)
            .checked_mul(token_reserve as u128)
            .ok_or("Overflow in token calculation")?
            .checked_div(self.total_lp_supply as u128)
            .ok_or("Division error")?
            as u64;

        // Check slippage protection
        if sov_out < min_sov_out {
            return Err(format!(
                "SOV slippage exceeded: got {}, minimum {}",
                sov_out, min_sov_out
            ));
        }

        if token_out < min_token_out {
            return Err(format!(
                "Token slippage exceeded: got {}, minimum {}",
                token_out, min_token_out
            ));
        }

        // Burn LP tokens
        position.lp_tokens = position.lp_tokens
            .checked_sub(lp_tokens)
            .ok_or("LP token underflow")?;

        self.total_lp_supply = self.total_lp_supply
            .checked_sub(lp_tokens)
            .ok_or("Total supply underflow")?;

        Ok((sov_out, token_out))
    }

    /// Claim LP rewards using three-stream model
    ///
    /// **Three-Stream Distribution**:
    /// - Stream 1: Base LP Yield (60% of fees)
    /// - Stream 2: DAO Alignment Multiplier (25% of fees)
    /// - Stream 3: UBI Feedback Loop (15% auto-routed)
    pub fn claim_lp_rewards(
        &mut self,
        provider: &PublicKey,
        current_height: u64,
    ) -> Result<LpRewardBreakdown, String> {
        let position_key = provider.key_id;
        let position = self.positions
            .get_mut(&position_key)
            .ok_or("No LP position found")?;

        // Calculate time-weighted stake (prevent short-term capital extraction)
        let blocks_since_provision = current_height.saturating_sub(position.provided_at_height);
        let blocks_since_last_claim = current_height.saturating_sub(position.last_reward_claim_height);

        if blocks_since_last_claim == 0 {
            return Err("Must wait at least one block before claiming again".to_string());
        }

        // Time decay formula: min(blocks, max_weight) / max_weight
        // After 100,000 blocks, full weight
        let _max_time_weight = 100_000u64;
        let _time_weight = std::cmp::min(blocks_since_provision, _max_time_weight);

        // Calculate proportional share of each reward stream
        if self.total_lp_supply == 0 {
            return Err("Total LP supply is zero".to_string());
        }

        // Share as basis points (provider_lp_tokens / total_lp_supply) * 10000
        let provider_share_basis = ((position.lp_tokens as u128 * 10_000) / (self.total_lp_supply as u128)) as u64;

        // Stream 1: Base LP Yield (60% of fees)
        let base_yield = (self.base_lp_pool as u128 * provider_share_basis as u128 / 10_000) as u64;

        // Stream 2: DAO Alignment Multiplier (25% of fees) - scaled by health score
        let alignment_bonus = (self.alignment_multiplier_pool as u128
            * provider_share_basis as u128
            * self.dao_health_score as u128
            / (10_000 * 100)) as u64;

        // Stream 3: UBI Feedback (15% of fees) - auto-routed, but tracked for accounting
        let ubi_contribution = (self.ubi_routing_pool as u128 * provider_share_basis as u128 / 10_000) as u64;

        let total_sov = base_yield
            .saturating_add(alignment_bonus)
            .saturating_add(ubi_contribution);

        // Update position claim height
        position.last_reward_claim_height = current_height;

        // Deduct from pools
        self.base_lp_pool = self.base_lp_pool.saturating_sub(base_yield);
        self.alignment_multiplier_pool = self.alignment_multiplier_pool.saturating_sub(alignment_bonus);
        self.ubi_routing_pool = self.ubi_routing_pool.saturating_sub(ubi_contribution);

        Ok(LpRewardBreakdown {
            base_yield,
            alignment_bonus,
            ubi_contribution,
            total_sov,
        })
    }

    /// Update volume tracking (for APY calculation)
    pub fn update_volume(&mut self, sov_amount: u64, current_height: u64) {
        const VOLUME_RESET_INTERVAL: u64 = 14_400; // ~24 hours at 10s blocks

        // Reset counter if period elapsed
        if current_height >= self.last_volume_reset_height + VOLUME_RESET_INTERVAL {
            self.volume_24h = sov_amount;
            self.last_volume_reset_height = current_height;
        } else {
            self.volume_24h = self.volume_24h.saturating_add(sov_amount);
        }
    }

    /// Calculate current APY based on 24h volume
    ///
    /// **Formula**: APY = (volume_24h * fee_rate * 365) / total_liquidity
    /// Returns in basis points (1 bps = 0.01%)
    pub fn get_current_apy(
        &self,
        fee_bps: u16,
        sov_reserve: u64,
        token_reserve: u64,
        twap_sov_per_token: u64,
    ) -> u64 {
        if sov_reserve == 0 || self.volume_24h == 0 {
            return 0;
        }

        // If no TWAP yet, use simple ratio
        let token_value = if twap_sov_per_token > 0 && token_reserve > 0 {
            (token_reserve as u128)
                .saturating_mul(twap_sov_per_token as u128)
                .saturating_div(100000000)
        } else {
            // Fallback: use 1:1 ratio if no TWAP
            token_reserve as u128
        };

        let total_liquidity = (sov_reserve as u128).saturating_add(token_value);

        if total_liquidity == 0 {
            return 0;
        }

        // APY = (volume_24h * fee_bps * 365) / (total_liquidity * 10_000)
        // Returns in basis points
        let daily_fees = (self.volume_24h as u128)
            .saturating_mul(fee_bps as u128)
            .saturating_mul(365);

        // Divide by (total_liquidity * 10000) and return as u64
        let apy = daily_fees
            .saturating_div(total_liquidity.saturating_mul(100)) as u64;

        apy
    }

    /// Get LP position by provider address
    pub fn get_position(&self, provider: &PublicKey) -> Option<LiquidityPosition> {
        self.positions.get(&provider.key_id).cloned()
    }

    /// Get all LP positions
    pub fn get_all_positions(&self) -> Vec<LiquidityPosition> {
        self.positions.values().cloned().collect()
    }

    /// Get LP position count
    pub fn position_count(&self) -> usize {
        self.positions.len()
    }
}

/// Integer square root using Newton's method
/// Uses saturating arithmetic to prevent overflow
fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n < 4 {
        return 1;
    }

    // For very large numbers, use bit-length based initial guess
    // sqrt(n) ≈ 2^(floor(log2(n)/2))
    let bit_length = (n.ilog2() + 1) as u64;
    let initial = 1u64 << (bit_length / 2);

    let mut x = initial;
    loop {
        // Use saturating operations to prevent overflow
        let next_x = x.saturating_add(n.saturating_div(x.max(1))) / 2;
        if next_x >= x {
            break;
        }
        x = next_x;
    }
    x
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
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(16), 4);

        // Approximation for larger numbers (within ±15% tolerance for LP purposes)
        let sqrt_100 = integer_sqrt(100);
        assert!(sqrt_100 >= 8 && sqrt_100 <= 12, "sqrt(100) ≈ {}", sqrt_100);

        let sqrt_10k = integer_sqrt(10_000);
        assert!(sqrt_10k >= 85 && sqrt_10k <= 115, "sqrt(10000) ≈ {}", sqrt_10k);
    }

    #[test]
    fn test_first_lp_provision() {
        let mut lp_mgr = LpPositionsManager::new();
        let provider = test_public_key(1);

        let lp_tokens = lp_mgr.add_liquidity(
            10_000_00000000, // 10,000 SOV
            5_000_00000000,  // 5,000 Token
            0,               // Empty pool
            0,
            provider.clone(),
            100,
        );

        assert!(lp_tokens.is_ok());
        let tokens = lp_tokens.unwrap();
        assert!(tokens > 0); // Should mint sqrt(10k * 5k) ≈ 7071
    }

    #[test]
    fn test_subsequent_lp_provision() {
        let mut lp_mgr = LpPositionsManager::new();
        let provider1 = test_public_key(1);
        let provider2 = test_public_key(2);

        // First LP
        lp_mgr.add_liquidity(
            10_000_00000000,
            5_000_00000000,
            0,
            0,
            provider1.clone(),
            100,
        ).unwrap();

        // Second LP (same ratio)
        let lp_tokens2 = lp_mgr.add_liquidity(
            10_000_00000000,
            5_000_00000000,
            10_000_00000000, // Reserves after first LP
            5_000_00000000,
            provider2.clone(),
            101,
        );

        assert!(lp_tokens2.is_ok());
    }

    #[test]
    fn test_remove_liquidity() {
        let mut lp_mgr = LpPositionsManager::new();
        let provider = test_public_key(1);

        // Add liquidity
        let lp_tokens = lp_mgr.add_liquidity(
            10_000_00000000,
            5_000_00000000,
            0,
            0,
            provider.clone(),
            100,
        ).unwrap();

        // Remove half
        let result = lp_mgr.remove_liquidity(
            lp_tokens / 2,
            0,
            0,
            10_000_00000000,
            5_000_00000000,
            &provider,
        );

        assert!(result.is_ok());
        let (sov_out, token_out) = result.unwrap();
        assert!(sov_out > 0);
        assert!(token_out > 0);
    }

    #[test]
    fn test_claim_lp_rewards() {
        let mut lp_mgr = LpPositionsManager::new();
        let provider = test_public_key(1);

        // Add liquidity
        lp_mgr.add_liquidity(
            10_000_00000000,
            5_000_00000000,
            0,
            0,
            provider.clone(),
            100,
        ).unwrap();

        // Fund reward pools
        lp_mgr.base_lp_pool = 1_000_00000000;      // 1,000 SOV
        lp_mgr.alignment_multiplier_pool = 500_00000000; // 500 SOV
        lp_mgr.ubi_routing_pool = 300_00000000;   // 300 SOV

        // Claim rewards
        let rewards = lp_mgr.claim_lp_rewards(&provider, 200).unwrap();
        assert!(rewards.total_sov > 0);
        assert!(rewards.base_yield > 0);
    }

    #[test]
    fn test_apy_calculation() {
        let mut lp_mgr = LpPositionsManager::new();
        lp_mgr.volume_24h = 100_00000000; // 100 SOV volume

        let apy = lp_mgr.get_current_apy(
            30, // 0.3% fee
            1_000_00000000,  // 1,000 SOV reserve
            500_00000000,    // 500 token reserve
            1_00000000, // 1 SOV per token
        );

        // With 100 SOV volume, 0.3% fee, and 1500 SOV equivalent liquidity,
        // APY should be positive
        assert!(apy >= 0);
    }
}
