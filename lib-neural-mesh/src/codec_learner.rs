//! Adaptive Codec Parameter Learner
//!
//! Learns optimal SovereignCodec parameters per content type using
//! reinforcement learning. The neural mesh observes compression outcomes
//! (ratio, throughput) and adjusts the codec's range coder parameters
//! to maximize compression performance for each content category.
//!
//! ## Architecture
//!
//! ```text
//! ContentProfile ──► ParamNetwork ──► CodecParams (SFC9)
//!       8-dim            8→64→3         rescale_limit
//!    state vector       actor net       freq_step
//!                                       init_freq_zero
//!                    ┌─────────────┐
//!                    │  Critic Net │ ──► Value estimate
//!                    │   8→64→1    │
//!                    └─────────────┘
//!
//! After compression:
//!   CompressionFeedback.rl_reward() ──► policy gradient update
//! ```
//!
//! ## Per-Content-Type Caching
//!
//! In addition to the neural network (which generalizes across content features),
//! the learner maintains a per-content-type cache of best-known params. This
//! gives zero-overhead exploitation once good params are found, while the network
//! handles cold-start for unseen content profiles.
//!
//! ## Exploration
//!
//! Uses epsilon-greedy exploration with decay. During exploration, the network's
//! output is perturbed with Gaussian noise to discover better parameter settings.

use ndarray::{Array1, Array2};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::content::{CompressionFeedback, ContentProfile, ContentType};

// ──────────────────────────────────────────────────────────
//  CodecParams — re-exported from lib-compression's type
//  We define a local mirror to avoid a circular dependency
//  (lib-compression depends on lib-neural-mesh).
// ──────────────────────────────────────────────────────────

/// Codec parameters predicted by the learner.
///
/// These map 1:1 to `lib_compression::CodecParams` and are converted
/// at the call site. We keep a local copy to avoid circular deps.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LearnedCodecParams {
    /// Rescale threshold for adaptive frequency model (multiple of 4, 1024..262140).
    pub rescale_limit: u32,
    /// Frequency increment per symbol (1..16).
    pub freq_step: u8,
    /// Initial frequency for symbol 0 (1..255).
    pub init_freq_zero: u8,
}

impl Default for LearnedCodecParams {
    fn default() -> Self {
        Self {
            rescale_limit: 65536,
            freq_step: 2,
            init_freq_zero: 128,
        }
    }
}

impl LearnedCodecParams {
    /// Clamp all fields to valid ranges.
    pub fn clamp(&mut self) {
        self.rescale_limit = (self.rescale_limit / 4 * 4).clamp(1024, 262140);
        self.freq_step = self.freq_step.clamp(1, 16);
        self.init_freq_zero = self.init_freq_zero.max(1);
    }

    /// Create from raw network outputs (3 floats in [0, 1]).
    fn from_network_output(raw: &[f32; 3]) -> Self {
        // Map [0,1] → parameter ranges
        let rescale = 1024.0 + raw[0] * (262140.0 - 1024.0);
        let step = 1.0 + raw[1] * 15.0;
        let f0 = 1.0 + raw[2] * 254.0;

        let mut p = Self {
            rescale_limit: (rescale as u32 / 4) * 4,
            freq_step: step as u8,
            init_freq_zero: f0 as u8,
        };
        p.clamp();
        p
    }

    /// Convert to raw [0,1] representation for the network.
    fn to_network_input(&self) -> [f32; 3] {
        [
            (self.rescale_limit as f32 - 1024.0) / (262140.0 - 1024.0),
            (self.freq_step as f32 - 1.0) / 15.0,
            (self.init_freq_zero as f32 - 1.0) / 254.0,
        ]
    }
}

// ──────────────────────────────────────────────────────────
//  Parameter Prediction Network (Actor-Critic)
// ──────────────────────────────────────────────────────────

/// Small actor-critic network for continuous codec parameter prediction.
///
/// - Actor: 8 → 64 → 3 (sigmoid output → param ranges)
/// - Critic: 8 → 64 → 1 (value estimate for baseline subtraction)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParamNetwork {
    // Actor weights
    actor_w1: Array2<f32>,
    actor_b1: Array1<f32>,
    actor_w2: Array2<f32>,
    actor_b2: Array1<f32>,
    // Critic weights
    critic_w1: Array2<f32>,
    critic_b1: Array1<f32>,
    critic_w2: Array2<f32>,
    critic_b2: Array1<f32>,
}

const STATE_DIM: usize = 8;
const HIDDEN_DIM: usize = 64;
const ACTION_DIM: usize = 3; // rescale_limit, freq_step, init_freq_zero

impl ParamNetwork {
    fn new() -> Self {
        let mut rng = rand::thread_rng();

        // Xavier initialization
        let xavier = |fan_in: usize| -> f32 { (2.0 / fan_in as f32).sqrt() };

        let actor_w1 = Array2::from_shape_fn((HIDDEN_DIM, STATE_DIM), |_| {
            rng.gen_range(-1.0..1.0) * xavier(STATE_DIM)
        });
        let actor_w2 = Array2::from_shape_fn((ACTION_DIM, HIDDEN_DIM), |_| {
            rng.gen_range(-1.0..1.0) * xavier(HIDDEN_DIM)
        });
        let critic_w1 = Array2::from_shape_fn((HIDDEN_DIM, STATE_DIM), |_| {
            rng.gen_range(-1.0..1.0) * xavier(STATE_DIM)
        });
        let critic_w2 = Array2::from_shape_fn((1, HIDDEN_DIM), |_| {
            rng.gen_range(-1.0..1.0) * xavier(HIDDEN_DIM)
        });

        Self {
            actor_w1,
            actor_b1: Array1::zeros(HIDDEN_DIM),
            actor_w2,
            actor_b2: Array1::from_elem(ACTION_DIM, 0.5), // bias toward middle of [0,1]
            critic_w1,
            critic_b1: Array1::zeros(HIDDEN_DIM),
            critic_w2,
            critic_b2: Array1::zeros(1),
        }
    }

    /// Actor forward pass → 3 values in [0, 1] (sigmoid output).
    fn predict_params(&self, state: &[f32]) -> [f32; 3] {
        let s = Array1::from_vec(state.to_vec());

        // Hidden: ReLU(W1 · s + b1)
        let h = (self.actor_w1.dot(&s) + &self.actor_b1).mapv(|x| x.max(0.0));
        // Output: sigmoid(W2 · h + b2)
        let logits = self.actor_w2.dot(&h) + &self.actor_b2;
        let out: Vec<f32> = logits.iter().map(|&x| 1.0 / (1.0 + (-x).exp())).collect();

        [out[0], out[1], out[2]]
    }

    /// Critic forward pass → scalar value estimate.
    fn predict_value(&self, state: &[f32]) -> f32 {
        let s = Array1::from_vec(state.to_vec());
        let h = (self.critic_w1.dot(&s) + &self.critic_b1).mapv(|x| x.max(0.0));
        let v = self.critic_w2.dot(&h) + &self.critic_b2;
        v[0]
    }
}

// ──────────────────────────────────────────────────────────
//  Per-Content-Type Cache
// ──────────────────────────────────────────────────────────

/// Cached optimal params for a specific content type.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypeCache {
    /// Best params found so far
    best_params: LearnedCodecParams,
    /// Exponential moving average of reward with best params
    best_reward: f32,
    /// Number of observations
    sample_count: u32,
}

impl Default for TypeCache {
    fn default() -> Self {
        Self {
            best_params: LearnedCodecParams::default(),
            best_reward: 0.0,
            sample_count: 0,
        }
    }
}

// ──────────────────────────────────────────────────────────
//  Experience Tuple
// ──────────────────────────────────────────────────────────

/// A single (state, action, reward) experience for training.
#[derive(Debug, Clone)]
struct ParamExperience {
    /// Content profile state vector (8-dim)
    state: Vec<f32>,
    /// Raw network output [0,1]^3 that produced the params
    action_raw: [f32; 3],
    /// Reward from CompressionFeedback
    reward: f32,
    /// Critic's value estimate at decision time
    value: f32,
}

// ──────────────────────────────────────────────────────────
//  AdaptiveCodecLearner
// ──────────────────────────────────────────────────────────

/// Configuration for the adaptive codec learner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecLearnerConfig {
    /// Learning rate for network updates
    pub learning_rate: f32,
    /// Exploration rate (probability of adding noise to params)
    pub epsilon: f32,
    /// Epsilon decay per training step (multiplicative)
    pub epsilon_decay: f32,
    /// Minimum epsilon (exploration floor)
    pub epsilon_min: f32,
    /// Exploration noise standard deviation (in [0,1] space)
    pub noise_std: f32,
    /// Batch size for training updates
    pub batch_size: usize,
    /// Exponential moving average decay for reward tracking
    pub ema_alpha: f32,
}

impl Default for CodecLearnerConfig {
    fn default() -> Self {
        Self {
            learning_rate: 1e-3,
            epsilon: 0.3,
            epsilon_decay: 0.995,
            epsilon_min: 0.05,
            noise_std: 0.15,
            batch_size: 16,
            ema_alpha: 0.1,
        }
    }
}

/// Adaptive Codec Parameter Learner — learns optimal SovereignCodec
/// parameters per content type using reinforcement learning.
///
/// # Usage
///
/// ```ignore
/// let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
///
/// // Before compression:
/// let profile = ContentProfile::analyze(&data);
/// let params = learner.predict_params(&profile);
/// let compressed = SovereignCodec::encode_with_params(&data, &params.into());
///
/// // After compression — feed back the result:
/// let feedback = CompressionFeedback { profile, ratio: 5.2, ... };
/// learner.observe_result(&feedback);
/// ```
pub struct AdaptiveCodecLearner {
    /// Actor-critic network for parameter prediction
    network: ParamNetwork,
    /// Per-content-type cache of best-known params
    type_cache: [TypeCache; 6],
    /// Experience replay buffer
    buffer: VecDeque<ParamExperience>,
    /// Configuration
    config: CodecLearnerConfig,
    /// Current exploration rate
    epsilon: f32,
    /// Training step counter
    step: u64,
    /// Last predicted action (for pairing with reward)
    last_action: Option<([f32; 3], Vec<f32>, f32)>, // (raw_action, state, value)
}

impl std::fmt::Debug for AdaptiveCodecLearner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveCodecLearner")
            .field("step", &self.step)
            .field("epsilon", &self.epsilon)
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

impl AdaptiveCodecLearner {
    /// Create a new learner with the given configuration.
    pub fn new(config: CodecLearnerConfig) -> Self {
        let epsilon = config.epsilon;
        Self {
            network: ParamNetwork::new(),
            type_cache: Default::default(),
            buffer: VecDeque::new(),
            config,
            epsilon,
            step: 0,
            last_action: None,
        }
    }

    /// Predict optimal codec parameters for the given content profile.
    ///
    /// Returns `LearnedCodecParams` which can be converted to
    /// `lib_compression::CodecParams` at the call site.
    ///
    /// During exploration (with probability `epsilon`), adds Gaussian noise
    /// to discover potentially better parameter settings.
    pub fn predict_params(&mut self, profile: &ContentProfile) -> LearnedCodecParams {
        let state = profile.to_state_vector();
        let type_idx = content_type_index(profile.content_type);

        // Check if we have a well-established cache for this content type
        let cache = &self.type_cache[type_idx];
        let use_cache = cache.sample_count >= 10 && self.epsilon < 0.10;

        let mut rng = rand::thread_rng();
        let exploring = rng.gen::<f32>() < self.epsilon;

        let (raw_action, params) = if use_cache && !exploring {
            // Exploit: use cached best params directly (zero network overhead)
            let raw = cache.best_params.to_network_input();
            (raw, cache.best_params)
        } else {
            // Predict from network
            let mut raw = self.network.predict_params(&state);

            if exploring {
                // Add exploration noise
                for v in raw.iter_mut() {
                    let noise: f32 = rng.gen::<f32>() * 2.0 - 1.0; // [-1, 1]
                    *v = (*v + noise * self.config.noise_std).clamp(0.0, 1.0);
                }
            }

            let p = LearnedCodecParams::from_network_output(&raw);
            (raw, p)
        };

        // Store for pairing with reward later
        let value = self.network.predict_value(&state);
        self.last_action = Some((raw_action, state, value));

        params
    }

    /// Observe the compression result and update the learner.
    ///
    /// Call this after `predict_params` + compression + building the
    /// `CompressionFeedback`. The reward signal drives learning.
    pub fn observe_result(&mut self, feedback: &CompressionFeedback) {
        let reward = feedback.rl_reward();
        let type_idx = content_type_index(feedback.profile.content_type);

        // Update per-type cache
        let cache = &mut self.type_cache[type_idx];
        let alpha = self.config.ema_alpha;

        if let Some((raw_action, state, value)) = self.last_action.take() {
            let action_params = LearnedCodecParams::from_network_output(&raw_action);

            if cache.sample_count == 0 {
                cache.best_reward = reward;
                cache.best_params = action_params;
            } else {
                // Exponential moving average of reward
                let ema_reward = cache.best_reward * (1.0 - alpha) + reward * alpha;

                if reward > cache.best_reward {
                    // New best — adopt these params
                    cache.best_params = action_params;
                    cache.best_reward = ema_reward;
                } else {
                    cache.best_reward = ema_reward;
                }
            }
            cache.sample_count += 1;

            // Store experience for network training
            self.buffer.push_back(ParamExperience {
                state,
                action_raw: raw_action,
                reward,
                value,
            });

            // Limit buffer size
            if self.buffer.len() > 5000 {
                self.buffer.pop_front();
            }
        }
    }

    /// Run a training update on the actor-critic network.
    ///
    /// Uses REINFORCE with baseline (critic) for variance reduction.
    /// Returns the average loss, or `None` if not enough experiences.
    pub fn train(&mut self) -> Option<f32> {
        if self.buffer.len() < self.config.batch_size {
            return None;
        }

        // Sample a batch
        let batch: Vec<ParamExperience> = self.buffer.drain(..self.config.batch_size).collect();

        let lr = self.config.learning_rate;
        let eps = 1e-3f32; // perturbation for numerical gradient

        // Compute advantages (reward - baseline)
        let advantages: Vec<f32> = batch.iter().map(|e| e.reward - e.value).collect();

        // Normalize advantages
        let mean_adv = advantages.iter().sum::<f32>() / advantages.len() as f32;
        let std_adv = (advantages.iter().map(|a| (a - mean_adv).powi(2)).sum::<f32>()
            / advantages.len() as f32)
            .sqrt()
            + 1e-8;
        let norm_advs: Vec<f32> = advantages.iter().map(|a| (a - mean_adv) / std_adv).collect();

        let mut total_loss = 0.0f32;

        // ── Actor update via numerical gradient ──
        // Loss = -advantage * log_prob(action|state)
        // For continuous actions with sigmoid output, we use the deviation from
        // the predicted action as a proxy log-probability.
        let actor_loss_fn = |net: &ParamNetwork| -> f32 {
            let mut loss = 0.0f32;
            for (i, exp) in batch.iter().enumerate() {
                let pred = net.predict_params(&exp.state);
                // Negative log-likelihood proxy: MSE between predicted and taken action
                // weighted by advantage
                let mse: f32 = pred.iter().zip(&exp.action_raw)
                    .map(|(p, a)| (p - a).powi(2))
                    .sum::<f32>();
                loss += mse * norm_advs[i];
            }
            loss / batch.len() as f32
        };

        use crate::ml::gradient::{update_matrix_fd, update_bias_fd};

        // Update actor weights & biases
        update_matrix_fd!(self.network.actor_w1, eps, lr, actor_loss_fn(&self.network));
        update_matrix_fd!(self.network.actor_w2, eps, lr, actor_loss_fn(&self.network));
        update_bias_fd!(self.network.actor_b1, eps, lr, actor_loss_fn(&self.network));
        update_bias_fd!(self.network.actor_b2, eps, lr, actor_loss_fn(&self.network));

        total_loss += actor_loss_fn(&self.network);

        // ── Critic update: minimize MSE(predicted_value, actual_reward) ──
        let critic_loss_fn = |net: &ParamNetwork| -> f32 {
            let mut loss = 0.0f32;
            for exp in &batch {
                let pred_v = net.predict_value(&exp.state);
                loss += (pred_v - exp.reward).powi(2);
            }
            loss / batch.len() as f32
        };

        // Update critic weights & biases
        update_matrix_fd!(self.network.critic_w1, eps, lr, critic_loss_fn(&self.network));
        update_matrix_fd!(self.network.critic_w2, eps, lr, critic_loss_fn(&self.network));
        update_bias_fd!(self.network.critic_b1, eps, lr, critic_loss_fn(&self.network));
        update_bias_fd!(self.network.critic_b2, eps, lr, critic_loss_fn(&self.network));

        total_loss += critic_loss_fn(&self.network);

        // Decay exploration
        self.epsilon = (self.epsilon * self.config.epsilon_decay).max(self.config.epsilon_min);
        self.step += 1;

        Some(total_loss)
    }

    /// Get the current best-known params for a content type.
    pub fn best_params_for(&self, ct: ContentType) -> LearnedCodecParams {
        self.type_cache[content_type_index(ct)].best_params
    }

    /// Get current exploration rate.
    pub fn exploration_rate(&self) -> f32 {
        self.epsilon
    }

    /// Get training step count.
    pub fn training_steps(&self) -> u64 {
        self.step
    }

    /// Get per-type sample counts (for monitoring).
    pub fn type_sample_counts(&self) -> [u32; 6] {
        let mut counts = [0u32; 6];
        for (i, c) in self.type_cache.iter().enumerate() {
            counts[i] = c.sample_count;
        }
        counts
    }

    /// Get per-type best rewards (for monitoring).
    pub fn type_best_rewards(&self) -> [f32; 6] {
        let mut rewards = [0.0f32; 6];
        for (i, c) in self.type_cache.iter().enumerate() {
            rewards[i] = c.best_reward;
        }
        rewards
    }

    /// Serialize the learner's state for persistence.
    pub fn save(&self) -> Result<Vec<u8>, String> {
        // Save network + type caches
        let state = SavedState {
            network: self.network.clone(),
            type_cache: self.type_cache.clone(),
            epsilon: self.epsilon,
            step: self.step,
        };
        bincode::serialize(&state).map_err(|e| format!("codec learner save: {}", e))
    }

    /// Restore the learner's state from saved bytes.
    pub fn load(&mut self, data: &[u8]) -> Result<(), String> {
        let state: SavedState =
            bincode::deserialize(data).map_err(|e| format!("codec learner load: {}", e))?;
        self.network = state.network;
        self.type_cache = state.type_cache;
        self.epsilon = state.epsilon;
        self.step = state.step;
        Ok(())
    }

    /// Number of experiences in the buffer.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }
}

// ──────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────

/// Map ContentType to a 0-based index.
fn content_type_index(ct: ContentType) -> usize {
    match ct {
        ContentType::Json => 0,
        ContentType::Text => 1,
        ContentType::Markup => 2,
        ContentType::Compressed => 3,
        ContentType::Binary => 4,
        ContentType::Unknown => 5,
    }
}

/// Serializable state for persistence.
#[derive(Serialize, Deserialize)]
struct SavedState {
    network: ParamNetwork,
    type_cache: [TypeCache; 6],
    epsilon: f32,
    step: u64,
}

// ──────────────────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(ct: ContentType, entropy: f32, text_ratio: f32, size: usize) -> ContentProfile {
        ContentProfile {
            content_type: ct,
            entropy,
            size,
            text_ratio,
            unique_bytes: 128,
            avg_delta: 40.0,
        }
    }

    fn make_feedback(profile: ContentProfile, ratio: f64, throughput: f64) -> CompressionFeedback {
        CompressionFeedback {
            profile,
            ratio,
            total_ratio: ratio * 0.95,
            time_secs: 0.1,
            throughput_mbps: throughput,
            integrity_ok: true,
            shard_count: 1,
            shards_compressed: 1,
        }
    }

    #[test]
    fn test_default_params() {
        let params = LearnedCodecParams::default();
        assert_eq!(params.rescale_limit, 65536);
        assert_eq!(params.freq_step, 2);
        assert_eq!(params.init_freq_zero, 128);
    }

    #[test]
    fn test_params_clamp() {
        let mut p = LearnedCodecParams {
            rescale_limit: 500,
            freq_step: 0,
            init_freq_zero: 0,
        };
        p.clamp();
        assert_eq!(p.rescale_limit, 1024);
        assert_eq!(p.freq_step, 1);
        assert_eq!(p.init_freq_zero, 1);

        let mut p2 = LearnedCodecParams {
            rescale_limit: 999999,
            freq_step: 255,
            init_freq_zero: 255,
        };
        p2.clamp();
        assert_eq!(p2.rescale_limit, 262140);
        assert_eq!(p2.freq_step, 16);
        assert_eq!(p2.init_freq_zero, 255); // max is fine
    }

    #[test]
    fn test_learner_creation() {
        let learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        assert_eq!(learner.step, 0);
        assert!(learner.epsilon > 0.0);
        assert_eq!(learner.buffer.len(), 0);
    }

    #[test]
    fn test_predict_params_returns_valid() {
        let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        let profile = make_profile(ContentType::Json, 4.5, 0.95, 100_000);

        let params = learner.predict_params(&profile);
        assert!(params.rescale_limit >= 1024);
        assert!(params.rescale_limit <= 262140);
        assert!(params.freq_step >= 1 && params.freq_step <= 16);
        assert!(params.init_freq_zero >= 1);
    }

    #[test]
    fn test_observe_result_updates_cache() {
        let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        let profile = make_profile(ContentType::Json, 4.5, 0.95, 100_000);

        let _params = learner.predict_params(&profile);
        let feedback = make_feedback(profile, 5.0, 80.0);
        learner.observe_result(&feedback);

        assert_eq!(learner.type_cache[0].sample_count, 1);
        assert!(learner.type_cache[0].best_reward > 0.0);
    }

    #[test]
    fn test_train_requires_batch() {
        let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        // Not enough data for training
        assert!(learner.train().is_none());
    }

    #[test]
    fn test_train_with_enough_data() {
        let config = CodecLearnerConfig {
            batch_size: 4,
            ..Default::default()
        };
        let mut learner = AdaptiveCodecLearner::new(config);

        // Generate enough experiences
        for i in 0..8 {
            let profile = make_profile(
                ContentType::Json, 
                3.0 + i as f32 * 0.2,
                0.9,
                50_000 + i * 10_000,
            );
            let _params = learner.predict_params(&profile);
            let feedback = make_feedback(profile, 4.0 + i as f64, 60.0);
            learner.observe_result(&feedback);
        }

        let loss = learner.train();
        assert!(loss.is_some());
        assert!(loss.unwrap().is_finite());
        assert_eq!(learner.step, 1);
    }

    #[test]
    fn test_different_content_types_get_different_caches() {
        let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());

        // JSON compression
        let json_profile = make_profile(ContentType::Json, 4.0, 0.95, 100_000);
        let _p = learner.predict_params(&json_profile);
        learner.observe_result(&make_feedback(json_profile, 6.0, 90.0));

        // Binary compression
        let bin_profile = make_profile(ContentType::Binary, 7.5, 0.1, 100_000);
        let _p = learner.predict_params(&bin_profile);
        learner.observe_result(&make_feedback(bin_profile, 1.5, 200.0));

        assert_eq!(learner.type_cache[0].sample_count, 1); // JSON
        assert_eq!(learner.type_cache[4].sample_count, 1); // Binary
        assert!(learner.type_cache[0].best_reward > learner.type_cache[4].best_reward);
    }

    #[test]
    fn test_save_and_load() {
        let mut learner = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        let profile = make_profile(ContentType::Text, 5.0, 0.85, 50_000);
        let _p = learner.predict_params(&profile);
        learner.observe_result(&make_feedback(profile, 3.0, 70.0));

        let saved = learner.save().unwrap();
        assert!(!saved.is_empty());

        let mut loaded = AdaptiveCodecLearner::new(CodecLearnerConfig::default());
        loaded.load(&saved).unwrap();
        assert_eq!(loaded.step, learner.step);
        assert_eq!(loaded.type_cache[1].sample_count, 1);
    }

    #[test]
    fn test_exploration_decays() {
        let config = CodecLearnerConfig {
            batch_size: 2,
            epsilon: 0.5,
            epsilon_decay: 0.9,
            epsilon_min: 0.05,
            ..Default::default()
        };
        let mut learner = AdaptiveCodecLearner::new(config);

        // Generate enough experiences for a training step
        for i in 0..4 {
            let profile = make_profile(ContentType::Json, 4.0, 0.9, 50_000 + i * 10_000);
            let _p = learner.predict_params(&profile);
            learner.observe_result(&make_feedback(profile, 4.0, 60.0));
        }

        let eps_before = learner.epsilon;
        learner.train();
        assert!(learner.epsilon < eps_before);
    }

    #[test]
    fn test_from_network_output_roundtrip() {
        let params = LearnedCodecParams {
            rescale_limit: 32768,
            freq_step: 4,
            init_freq_zero: 64,
        };
        let raw = params.to_network_input();
        assert!(raw[0] >= 0.0 && raw[0] <= 1.0);
        assert!(raw[1] >= 0.0 && raw[1] <= 1.0);
        assert!(raw[2] >= 0.0 && raw[2] <= 1.0);

        let recovered = LearnedCodecParams::from_network_output(&raw);
        // Allow small rounding differences due to integer truncation
        assert!((recovered.rescale_limit as i64 - params.rescale_limit as i64).unsigned_abs() <= 4);
        assert_eq!(recovered.freq_step, params.freq_step);
        assert!((recovered.init_freq_zero as i16 - params.init_freq_zero as i16).unsigned_abs() <= 1);
    }
}
