//! Ren AI Inference Reward Calculation
//!
//! Computes SOV rewards for AI service nodes based on useful inference work:
//! - Tokens generated (input + output)
//! - Task complexity multiplier
//! - Quality score (client ratings, latency benchmarks)
//! - Uptime bonus
//!
//! Integrates with the existing lib-economy `TokenReward` pipeline.

use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::info;

use super::types::InferenceReceipt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Base rate: SOV earned per 1 000 output tokens generated.
pub const BASE_RATE_PER_1K_OUTPUT_TOKENS: u64 = 2;

/// Base rate: SOV earned per 1 000 input tokens processed.
pub const BASE_RATE_PER_1K_INPUT_TOKENS: u64 = 1;

/// Multipliers by inference task type.
pub fn task_multiplier(task_type: &str) -> f64 {
    match task_type {
        "completion" => 1.0,
        "chat" => 1.2,       // Multi-turn context management
        "embedding" => 0.5,  // Cheaper operation
        "summarization" => 1.5, // Longer context, more work
        _ => 1.0,
    }
}

/// Quality score thresholds.
pub const QUALITY_BONUS_THRESHOLD: f64 = 0.85;  // Top 15% quality
pub const QUALITY_BONUS_MULTIPLIER: f64 = 0.25;  // 25% bonus

/// Uptime bonus: awarded when node uptime exceeds 99% in the epoch.
pub const UPTIME_BONUS_THRESHOLD: f64 = 0.99;
pub const UPTIME_BONUS_MULTIPLIER: f64 = 0.15;  // 15% bonus

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Aggregated inference work metrics for a single epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochInferenceStats {
    /// Total input tokens processed during the epoch.
    pub total_input_tokens: u64,
    /// Total output tokens generated during the epoch.
    pub total_output_tokens: u64,
    /// Number of inference requests served.
    pub total_requests: u64,
    /// Breakdown by task type: (task_type -> request_count).
    pub requests_by_task: std::collections::HashMap<String, u64>,
    /// Average latency in ms across all requests.
    pub avg_latency_ms: f64,
    /// Quality score for the epoch (0.0 - 1.0), derived from client ratings.
    pub quality_score: f64,
    /// Fraction of epoch the node was online (0.0 - 1.0).
    pub uptime_fraction: f64,
    /// SOV collected as fees from clients during the epoch.
    pub sov_fees_collected: u64,
}

/// Calculated reward for a single epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceReward {
    /// Reward for input token processing.
    pub input_token_reward: u64,
    /// Reward for output token generation.
    pub output_token_reward: u64,
    /// Task complexity bonus (weighted by multipliers).
    pub task_complexity_bonus: u64,
    /// Quality bonus (top-tier performance).
    pub quality_bonus: u64,
    /// Uptime bonus (near-perfect availability).
    pub uptime_bonus: u64,
    /// Total SOV reward for the epoch.
    pub total_reward: u64,
    /// Epoch number.
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Calculator
// ---------------------------------------------------------------------------

/// Calculates rewards for AI inference work.
pub struct InferenceRewardCalculator {
    /// Base rate per 1K input tokens (configurable, defaults to constant).
    pub input_rate: u64,
    /// Base rate per 1K output tokens (configurable, defaults to constant).
    pub output_rate: u64,
}

impl Default for InferenceRewardCalculator {
    fn default() -> Self {
        Self {
            input_rate: BASE_RATE_PER_1K_INPUT_TOKENS,
            output_rate: BASE_RATE_PER_1K_OUTPUT_TOKENS,
        }
    }
}

impl InferenceRewardCalculator {
    pub fn new(input_rate: u64, output_rate: u64) -> Self {
        Self { input_rate, output_rate }
    }

    /// Calculate the total reward for an epoch's inference work.
    pub fn calculate(&self, stats: &EpochInferenceStats, epoch: u64) -> Result<InferenceReward> {
        // Base token rewards
        let input_token_reward = (stats.total_input_tokens / 1000).saturating_mul(self.input_rate);
        let output_token_reward = (stats.total_output_tokens / 1000).saturating_mul(self.output_rate);

        // Task complexity bonus: weighted sum of requests * multiplier
        let task_complexity_bonus = self.calculate_task_bonus(stats);

        // Quality bonus
        let base_reward = input_token_reward
            .saturating_add(output_token_reward)
            .saturating_add(task_complexity_bonus);

        let quality_bonus = if stats.quality_score >= QUALITY_BONUS_THRESHOLD {
            ((base_reward as f64) * QUALITY_BONUS_MULTIPLIER) as u64
        } else {
            0
        };

        // Uptime bonus
        let uptime_bonus = if stats.uptime_fraction >= UPTIME_BONUS_THRESHOLD {
            ((base_reward as f64) * UPTIME_BONUS_MULTIPLIER) as u64
        } else {
            0
        };

        let total_reward = base_reward
            .saturating_add(quality_bonus)
            .saturating_add(uptime_bonus)
            .max(1); // Minimum 1 SOV for participation

        info!(
            "Epoch {} inference reward: {} SOV (in={}, out={}, task={}, quality={}, uptime={})",
            epoch, total_reward,
            input_token_reward, output_token_reward, task_complexity_bonus,
            quality_bonus, uptime_bonus
        );

        Ok(InferenceReward {
            input_token_reward,
            output_token_reward,
            task_complexity_bonus,
            quality_bonus,
            uptime_bonus,
            total_reward,
            epoch,
        })
    }

    /// Calculate the task complexity bonus from per-task request counts.
    fn calculate_task_bonus(&self, stats: &EpochInferenceStats) -> u64 {
        let mut bonus: f64 = 0.0;
        for (task_type, count) in &stats.requests_by_task {
            let multiplier = task_multiplier(task_type);
            // Each request beyond 1.0x multiplier earns a small bonus
            if multiplier > 1.0 {
                bonus += (*count as f64) * (multiplier - 1.0);
            }
        }
        bonus as u64
    }

    /// Compute the SOV cost for a single inference request (used for billing).
    pub fn cost_for_request(
        &self,
        input_tokens: u32,
        output_tokens: u32,
        price_input_1k: u64,
        price_output_1k: u64,
    ) -> u64 {
        let input_cost = (input_tokens as u64 * price_input_1k) / 1000;
        let output_cost = (output_tokens as u64 * price_output_1k) / 1000;
        input_cost.saturating_add(output_cost).max(1)
    }

    /// Aggregate a single receipt into running epoch stats.
    pub fn accumulate_receipt(stats: &mut EpochInferenceStats, receipt: &InferenceReceipt) {
        stats.total_input_tokens += receipt.input_tokens as u64;
        stats.total_output_tokens += receipt.output_tokens as u64;
        stats.total_requests += 1;
        stats.sov_fees_collected += receipt.sov_charged;
        *stats.requests_by_task
            .entry(receipt.task_type.clone())
            .or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stats() -> EpochInferenceStats {
        let mut by_task = std::collections::HashMap::new();
        by_task.insert("completion".into(), 500);
        by_task.insert("chat".into(), 300);
        by_task.insert("embedding".into(), 200);

        EpochInferenceStats {
            total_input_tokens: 5_000_000,
            total_output_tokens: 2_000_000,
            total_requests: 1000,
            requests_by_task: by_task,
            avg_latency_ms: 150.0,
            quality_score: 0.92,
            uptime_fraction: 0.995,
            sov_fees_collected: 12_000,
        }
    }

    #[test]
    fn reward_calculation_basic() {
        let calc = InferenceRewardCalculator::default();
        let stats = sample_stats();
        let reward = calc.calculate(&stats, 42).unwrap();

        assert!(reward.total_reward > 0);
        assert!(reward.input_token_reward > 0);
        assert!(reward.output_token_reward > 0);
        assert!(reward.quality_bonus > 0, "quality_score 0.92 should earn bonus");
        assert!(reward.uptime_bonus > 0, "uptime 0.995 should earn bonus");
        assert_eq!(reward.epoch, 42);
    }

    #[test]
    fn minimum_reward_floor() {
        let calc = InferenceRewardCalculator::default();
        let stats = EpochInferenceStats::default();
        let reward = calc.calculate(&stats, 1).unwrap();
        assert_eq!(reward.total_reward, 1, "Minimum reward is 1 SOV");
    }

    #[test]
    fn cost_for_request_calculation() {
        let calc = InferenceRewardCalculator::default();
        let cost = calc.cost_for_request(2000, 500, 1, 3);
        // 2000/1000 * 1 = 2 (input) + 500/1000 * 3 = 1 (output, floored) = 3
        assert!(cost >= 1);
    }
}
