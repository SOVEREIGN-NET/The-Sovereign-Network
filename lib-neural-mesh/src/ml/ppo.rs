//! PPO (Proximal Policy Optimization) implementation for RL-Router
//! 
//! This module implements reinforcement learning for network routing decisions.

use ndarray::{Array1, Array2};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// PPO hyperparameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpoConfig {
    /// Learning rate for policy network
    pub learning_rate: f32,
    /// Discount factor (gamma)
    pub discount: f32,
    /// GAE lambda parameter
    pub gae_lambda: f32,
    /// PPO clipping parameter (epsilon)
    pub clip_epsilon: f32,
    /// Entropy coefficient
    pub entropy_coef: f32,
    /// Value loss coefficient
    pub value_coef: f32,
    /// Batch size for training
    pub batch_size: usize,
    /// Number of epochs per update
    pub epochs: usize,
}

impl Default for PpoConfig {
    fn default() -> Self {
        Self {
            learning_rate: 3e-4,
            discount: 0.99,
            gae_lambda: 0.95,
            clip_epsilon: 0.2,
            entropy_coef: 0.01,
            value_coef: 0.5,
            batch_size: 64,
            epochs: 10,
        }
    }
}

/// Experience tuple for training
#[derive(Debug, Clone)]
pub struct Experience {
    pub state: Vec<f32>,
    pub action: usize,
    pub reward: f32,
    pub next_state: Vec<f32>,
    pub done: bool,
    pub log_prob: f32,
    pub value: f32,
}

/// Simple neural network for policy and value estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValueNetwork {
    /// Input size (state dimension)
    input_size: usize,
    /// Hidden layer size
    hidden_size: usize,
    /// Output size (number of actions)
    output_size: usize,
    /// Policy network weights (input -> hidden)
    policy_w1: Array2<f32>,
    /// Policy network weights (hidden -> output)
    policy_w2: Array2<f32>,
    /// Value network weights (input -> hidden)
    value_w1: Array2<f32>,
    /// Value network weights (hidden -> output)
    value_w2: Array2<f32>,
    /// Bias terms
    policy_b1: Array1<f32>,
    policy_b2: Array1<f32>,
    value_b1: Array1<f32>,
    value_b2: Array1<f32>,
}

impl PolicyValueNetwork {
    /// Create new network with random initialization
    pub fn new(input_size: usize, hidden_size: usize, output_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        
        // Xavier initialization
        let policy_w1 = Array2::from_shape_fn((hidden_size, input_size), |_| {
            rng.gen_range(-1.0..1.0) * (2.0 / input_size as f32).sqrt()
        });
        let policy_w2 = Array2::from_shape_fn((output_size, hidden_size), |_| {
            rng.gen_range(-1.0..1.0) * (2.0 / hidden_size as f32).sqrt()
        });
        let value_w1 = Array2::from_shape_fn((hidden_size, input_size), |_| {
            rng.gen_range(-1.0..1.0) * (2.0 / input_size as f32).sqrt()
        });
        let value_w2 = Array2::from_shape_fn((1, hidden_size), |_| {
            rng.gen_range(-1.0..1.0) * (2.0 / hidden_size as f32).sqrt()
        });
        
        Self {
            input_size,
            hidden_size,
            output_size,
            policy_w1,
            policy_w2,
            value_w1,
            value_w2,
            policy_b1: Array1::zeros(hidden_size),
            policy_b2: Array1::zeros(output_size),
            value_b1: Array1::zeros(hidden_size),
            value_b2: Array1::from_elem(1, 0.0),
        }
    }
    
    /// Forward pass through policy network
    pub fn forward_policy(&self, state: &[f32]) -> Vec<f32> {
        let state_arr = Array1::from_vec(state.to_vec());
        
        // Hidden layer: ReLU(W1 * x + b1)
        let hidden = (self.policy_w1.dot(&state_arr) + &self.policy_b1)
            .mapv(|x| x.max(0.0)); // ReLU
        
        // Output layer: softmax(W2 * h + b2)
        let logits = self.policy_w2.dot(&hidden) + &self.policy_b2;
        
        // Softmax
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exp_logits: Vec<f32> = logits.iter().map(|&x| (x - max_logit).exp()).collect();
        let sum_exp: f32 = exp_logits.iter().sum();
        exp_logits.iter().map(|&x| x / sum_exp).collect()
    }
    
    /// Forward pass through value network
    pub fn forward_value(&self, state: &[f32]) -> f32 {
        let state_arr = Array1::from_vec(state.to_vec());
        
        // Hidden layer: ReLU(W1 * x + b1)
        let hidden = (self.value_w1.dot(&state_arr) + &self.value_b1)
            .mapv(|x| x.max(0.0)); // ReLU
        
        // Output layer: W2 * h + b2
        let value = self.value_w2.dot(&hidden) + &self.value_b2;
        value[0]
    }
    
    /// Select action based on policy
    pub fn select_action(&self, state: &[f32]) -> (usize, f32) {
        let probs = self.forward_policy(state);
        
        // Sample from categorical distribution
        let mut rng = rand::thread_rng();
        let rand_val: f32 = rng.gen();
        let mut cumsum = 0.0;
        
        for (i, &prob) in probs.iter().enumerate() {
            cumsum += prob;
            if rand_val < cumsum {
                return (i, prob.ln());
            }
        }
        
        // Fallback (shouldn't happen with valid probabilities)
        (probs.len() - 1, probs[probs.len() - 1].ln())
    }
}

/// PPO agent for policy optimization
pub struct PpoAgent {
    /// Neural network for policy and value
    network: PolicyValueNetwork,
    /// Configuration
    config: PpoConfig,
    /// Experience replay buffer
    buffer: VecDeque<Experience>,
    /// Training step counter
    step: usize,
}

impl PpoAgent {
    /// Create new PPO agent
    pub fn new(state_dim: usize, action_dim: usize, config: PpoConfig) -> Self {
        let hidden_size = 128; // Default hidden layer size
        Self {
            network: PolicyValueNetwork::new(state_dim, hidden_size, action_dim),
            config,
            buffer: VecDeque::new(),
            step: 0,
        }
    }
    
    /// Select action for given state
    pub fn select_action(&mut self, state: &[f32]) -> (usize, f32, f32) {
        let (action, log_prob) = self.network.select_action(state);
        let value = self.network.forward_value(state);
        (action, log_prob, value)
    }
    
    /// Store experience in replay buffer
    pub fn store_experience(&mut self, exp: Experience) {
        self.buffer.push_back(exp);
        
        // Limit buffer size
        if self.buffer.len() > 10000 {
            self.buffer.pop_front();
        }
    }
    
    /// Compute advantages using GAE
    fn compute_advantages(&self, experiences: &[Experience]) -> Vec<f32> {
        let mut advantages = Vec::with_capacity(experiences.len());
        let mut gae = 0.0;
        
        for i in (0..experiences.len()).rev() {
            let exp = &experiences[i];
            
            let next_value = if exp.done {
                0.0
            } else if i + 1 < experiences.len() {
                experiences[i + 1].value
            } else {
                self.network.forward_value(&exp.next_state)
            };
            
            let delta = exp.reward + self.config.discount * next_value - exp.value;
            gae = delta + self.config.discount * self.config.gae_lambda * gae;
            advantages.push(gae);
        }
        
        advantages.reverse();
        
        // Normalize advantages
        let mean: f32 = advantages.iter().sum::<f32>() / advantages.len() as f32;
        let std: f32 = (advantages.iter().map(|x| (x - mean).powi(2)).sum::<f32>() 
            / advantages.len() as f32).sqrt() + 1e-8;
        
        advantages.iter().map(|x| (x - mean) / std).collect()
    }
    
    /// Update policy using PPO algorithm with real gradient descent
    ///
    /// Implements numerical gradient estimation via finite differences and
    /// applies actual weight updates using the PPO clipped objective.
    pub fn update(&mut self) -> Result<f32, String> {
        if self.buffer.len() < self.config.batch_size {
            return Err("Not enough experiences".to_string());
        }
        
        // Convert buffer to vector
        let experiences: Vec<Experience> = self.buffer.drain(..).collect();
        
        // Compute advantages
        let advantages = self.compute_advantages(&experiences);
        
        // Compute returns
        let returns: Vec<f32> = experiences.iter().zip(&advantages)
            .map(|(exp, adv)| exp.value + adv)
            .collect();
        
        let mut total_loss = 0.0;
        let num_updates = (self.config.epochs * (experiences.len() / self.config.batch_size)).max(1);
        let lr = self.config.learning_rate;
        
        // PPO training loop with REAL weight updates
        for _epoch in 0..self.config.epochs {
            for batch_start in (0..experiences.len()).step_by(self.config.batch_size) {
                let batch_end = (batch_start + self.config.batch_size).min(experiences.len());
                let batch = &experiences[batch_start..batch_end];
                let batch_advs = &advantages[batch_start..batch_end];
                let batch_rets = &returns[batch_start..batch_end];
                
                // ─── Compute batch loss for current parameters ───
                let mut batch_loss = 0.0f32;
                for (idx, exp) in batch.iter().enumerate() {
                    let probs = self.network.forward_policy(&exp.state);
                    let new_log_prob = probs[exp.action].max(1e-8).ln();
                    
                    let ratio = (new_log_prob - exp.log_prob).exp();
                    let clipped = ratio.clamp(
                        1.0 - self.config.clip_epsilon,
                        1.0 + self.config.clip_epsilon,
                    );
                    let policy_loss = -(ratio.min(clipped)) * batch_advs[idx];
                    
                    let value_pred = self.network.forward_value(&exp.state);
                    let value_loss = (value_pred - batch_rets[idx]).powi(2);
                    
                    let entropy: f32 = -probs.iter()
                        .map(|&p| if p > 1e-8 { p * p.ln() } else { 0.0 })
                        .sum::<f32>();
                    
                    batch_loss += policy_loss
                        + self.config.value_coef * value_loss
                        - self.config.entropy_coef * entropy;
                }
                batch_loss /= batch.len() as f32;
                total_loss += batch_loss;
                
                // ─── Numerical gradient descent on policy weights ───
                // We perturb each weight, measure loss change, and update.
                // This is O(params * batch) but our network is small (5→128→10).
                let eps = 1e-3f32;
                
                // Helper: compute batch loss with current network state
                let batch_loss_fn = |net: &PolicyValueNetwork| -> f32 {
                    let mut l = 0.0f32;
                    for (idx, exp) in batch.iter().enumerate() {
                        let probs = net.forward_policy(&exp.state);
                        let nlp = probs[exp.action].max(1e-8).ln();
                        let ratio = (nlp - exp.log_prob).exp();
                        let clipped = ratio.clamp(
                            1.0 - self.config.clip_epsilon,
                            1.0 + self.config.clip_epsilon,
                        );
                        let pl = -(ratio.min(clipped)) * batch_advs[idx];
                        let vp = net.forward_value(&exp.state);
                        let vl = (vp - batch_rets[idx]).powi(2);
                        let ent: f32 = -probs.iter()
                            .map(|&p| if p > 1e-8 { p * p.ln() } else { 0.0 })
                            .sum::<f32>();
                        l += pl + self.config.value_coef * vl - self.config.entropy_coef * ent;
                    }
                    l / batch.len() as f32
                };
                
                use super::gradient::{update_matrix_fd, update_bias_fd};
                
                // Update policy weights
                update_matrix_fd!(self.network.policy_w1, eps, lr, batch_loss_fn(&self.network));
                update_matrix_fd!(self.network.policy_w2, eps, lr, batch_loss_fn(&self.network));
                update_bias_fd!(self.network.policy_b1, eps, lr, batch_loss_fn(&self.network));
                update_bias_fd!(self.network.policy_b2, eps, lr, batch_loss_fn(&self.network));
                
                // Update value weights
                update_matrix_fd!(self.network.value_w1, eps, lr, batch_loss_fn(&self.network));
                update_matrix_fd!(self.network.value_w2, eps, lr, batch_loss_fn(&self.network));
                update_bias_fd!(self.network.value_b1, eps, lr, batch_loss_fn(&self.network));
                update_bias_fd!(self.network.value_b2, eps, lr, batch_loss_fn(&self.network));
            }
        }
        
        self.step += 1;
        Ok(total_loss / num_updates as f32)
    }
    
    /// Save model to bytes
    pub fn save(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(&self.network)
            .map_err(|e| format!("Failed to serialize network: {}", e))
    }
    
    /// Load model from bytes
    pub fn load(&mut self, data: &[u8]) -> Result<(), String> {
        self.network = bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize network: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_creation() {
        let network = PolicyValueNetwork::new(10, 64, 5);
        assert_eq!(network.input_size, 10);
        assert_eq!(network.hidden_size, 64);
        assert_eq!(network.output_size, 5);
    }
    
    #[test]
    fn test_forward_pass() {
        let network = PolicyValueNetwork::new(5, 32, 3);
        let state = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        
        let probs = network.forward_policy(&state);
        assert_eq!(probs.len(), 3);
        
        // Check probabilities sum to 1
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        
        let value = network.forward_value(&state);
        assert!(value.is_finite());
    }
    
    #[test]
    fn test_ppo_agent() {
        let config = PpoConfig::default();
        let mut agent = PpoAgent::new(5, 3, config);
        
        let state = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        let (action, log_prob, value) = agent.select_action(&state);
        
        assert!(action < 3);
        assert!(log_prob <= 0.0); // Log probability is negative
        assert!(value.is_finite());
    }
    
    #[test]
    fn test_experience_storage() {
        let config = PpoConfig::default();
        let mut agent = PpoAgent::new(5, 3, config);
        
        let exp = Experience {
            state: vec![0.1, 0.2, 0.3, 0.4, 0.5],
            action: 0,
            reward: 1.0,
            next_state: vec![0.2, 0.3, 0.4, 0.5, 0.6],
            done: false,
            log_prob: -1.0,
            value: 0.5,
        };
        
        agent.store_experience(exp);
        assert_eq!(agent.buffer.len(), 1);
    }
}
