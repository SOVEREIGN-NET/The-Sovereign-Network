//! Reinforcement Learning Router with PPO

use crate::error::Result;
use crate::ml::{PpoAgent, PpoConfig, Experience};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network state for RL decision making
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub latencies: HashMap<String, f32>,
    pub bandwidth: HashMap<String, f32>,
    pub packet_loss: HashMap<String, f32>,
    pub energy_scores: HashMap<String, f32>,
    pub congestion: f32,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            latencies: HashMap::new(),
            bandwidth: HashMap::new(),
            packet_loss: HashMap::new(),
            energy_scores: HashMap::new(),
            congestion: 0.0,
        }
    }

    /// Convert network state to feature vector for ML model
    /// Features: [congestion, avg_latency, avg_bandwidth, avg_packet_loss, avg_energy]
    pub fn to_feature_vector(&self) -> Vec<f32> {
        let avg_latency = if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies.values().sum::<f32>() / self.latencies.len() as f32
        };
        
        let avg_bandwidth = if self.bandwidth.is_empty() {
            0.0
        } else {
            self.bandwidth.values().sum::<f32>() / self.bandwidth.len() as f32
        };
        
        let avg_packet_loss = if self.packet_loss.is_empty() {
            0.0
        } else {
            self.packet_loss.values().sum::<f32>() / self.packet_loss.len() as f32
        };
        
        let avg_energy = if self.energy_scores.is_empty() {
            0.0
        } else {
            self.energy_scores.values().sum::<f32>() / self.energy_scores.len() as f32
        };
        
        vec![
            self.congestion,
            avg_latency,
            avg_bandwidth,
            avg_packet_loss,
            avg_energy,
        ]
    }
    
    /// Get sorted node list by latency (for fallback)
    pub fn get_node_ids(&self) -> Vec<String> {
        self.latencies.keys().cloned().collect()
    }
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

/// Routing decision with confidence score
#[derive(Debug, Clone)]
pub struct RoutingAction {
    pub nodes: Vec<String>,
    pub confidence: f32,
    pub action_id: usize,
}

/// RL-based router using PPO
pub struct RlRouter {
    enabled: bool,
    agent: Option<PpoAgent>,
    node_list: Vec<String>,
    last_state: Option<Vec<f32>>,
    last_action: Option<usize>,
    last_log_prob: Option<f32>,
    last_value: Option<f32>,
}

impl std::fmt::Debug for RlRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlRouter")
            .field("enabled", &self.enabled)
            .field("has_agent", &self.agent.is_some())
            .field("node_list", &self.node_list)
            .finish()
    }
}

impl RlRouter {
    /// Create new RL router
    pub fn new() -> Self {
        Self {
            enabled: false,
            agent: None,
            node_list: Vec::new(),
            last_state: None,
            last_action: None,
            last_log_prob: None,
            last_value: None,
        }
    }

    /// Enable RL routing with specified dimensions
    pub fn enable(&mut self, state_dim: usize, action_dim: usize) {
        let config = PpoConfig::default();
        self.agent = Some(PpoAgent::new(state_dim, action_dim, config));
        self.enabled = true;
    }
    
    /// Enable with custom config
    pub fn enable_with_config(&mut self, state_dim: usize, action_dim: usize, config: PpoConfig) {
        self.agent = Some(PpoAgent::new(state_dim, action_dim, config));
        self.enabled = true;
    }

    /// Select routing action using RL policy
    pub fn select_action(&mut self, state: &NetworkState) -> Result<RoutingAction> {
        if !self.enabled {
            return Err(crate::error::NeuralMeshError::InferenceFailed(
                "RL Router not enabled".to_string(),
            ));
        }

        let agent = self.agent.as_mut().ok_or_else(|| {
            crate::error::NeuralMeshError::InferenceFailed("No agent initialized".to_string())
        })?;

        // Update node list if changed
        let current_nodes = state.get_node_ids();
        if current_nodes != self.node_list {
            self.node_list = current_nodes;
        }

        // Get feature vector
        let features = state.to_feature_vector();
        
        // Select action using PPO
        let (action, log_prob, value) = agent.select_action(&features);
        
        // Store for reward feedback
        self.last_state = Some(features);
        self.last_action = Some(action);
        self.last_log_prob = Some(log_prob);
        self.last_value = Some(value);

        // Map action to routing nodes
        let selected_nodes = self.map_action_to_nodes(action, state);
        
        Ok(RoutingAction {
            nodes: selected_nodes,
            confidence: value.clamp(0.0, 1.0), // Clamp value to [0, 1] range
            action_id: action,
        })
    }

    /// Provide reward signal for learning
    pub fn provide_reward(&mut self, reward: f32, next_state: &NetworkState, done: bool) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let agent = self.agent.as_mut().ok_or_else(|| {
            crate::error::NeuralMeshError::InferenceFailed("No agent initialized".to_string())
        })?;

        // Get stored experience components
        let state = self.last_state.take().ok_or_else(|| {
            crate::error::NeuralMeshError::InferenceFailed("No previous state".to_string())
        })?;
        
        let action = self.last_action.take().ok_or_else(|| {
            crate::error::NeuralMeshError::InferenceFailed("No previous action".to_string())
        })?;
        
        let log_prob = self.last_log_prob.take().unwrap_or(0.0);
        let value = self.last_value.take().unwrap_or(0.0);

        // Create experience
        let exp = Experience {
            state,
            action,
            reward,
            next_state: next_state.to_feature_vector(),
            done,
            log_prob,
            value,
        };

        agent.store_experience(exp);
        
        Ok(())
    }

    /// Update policy using collected experiences
    pub fn update_policy(&mut self) -> Result<f32> {
        if !self.enabled {
            return Err(crate::error::NeuralMeshError::TrainingFailed(
                "RL Router not enabled".to_string(),
            ));
        }

        let agent = self.agent.as_mut().ok_or_else(|| {
            crate::error::NeuralMeshError::TrainingFailed("No agent initialized".to_string())
        })?;

        agent.update().map_err(|e| {
            crate::error::NeuralMeshError::TrainingFailed(e)
        })
    }

    /// Save model to bytes
    pub fn save_model(&self) -> Result<Vec<u8>> {
        let agent = self.agent.as_ref().ok_or_else(|| {
            crate::error::NeuralMeshError::InferenceFailed("No agent initialized".to_string())
        })?;

        agent.save().map_err(|e| {
            crate::error::NeuralMeshError::InferenceFailed(e)
        })
    }

    /// Load model from bytes
    pub fn load_model(&mut self, data: &[u8], state_dim: usize, action_dim: usize) -> Result<()> {
        let mut agent = PpoAgent::new(state_dim, action_dim, PpoConfig::default());
        agent.load(data).map_err(|e| {
            crate::error::NeuralMeshError::InferenceFailed(e)
        })?;

        self.agent = Some(agent);
        self.enabled = true;
        
        Ok(())
    }

    /// Map action ID to actual routing nodes
    fn map_action_to_nodes(&self, action: usize, state: &NetworkState) -> Vec<String> {
        if self.node_list.is_empty() {
            return Vec::new();
        }

        // Strategy: Use action to select routing strategy
        // Action 0-2: Select top 1-3 nodes by latency
        // Action 3-5: Select top 1-3 nodes by bandwidth
        // Action 6-8: Select nodes by energy score
        // Action 9+: Random or round-robin
        
        let strategy = action % 10;
        let num_nodes = (action / 10).min(2) + 1; // 1-3 nodes
        
        let mut selected = Vec::new();
        
        match strategy {
            0..=2 => {
                // Low latency strategy
                let mut nodes: Vec<_> = state.latencies.iter().collect();
                nodes.sort_by(|a, b| a.1.partial_cmp(b.1).unwrap());
                selected = nodes.iter().take(num_nodes).map(|(id, _)| (*id).clone()).collect();
            }
            3..=5 => {
                // High bandwidth strategy
                let mut nodes: Vec<_> = state.bandwidth.iter().collect();
                nodes.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
                selected = nodes.iter().take(num_nodes).map(|(id, _)| (*id).clone()).collect();
            }
            6..=8 => {
                // Energy-efficient strategy
                let mut nodes: Vec<_> = state.energy_scores.iter().collect();
                nodes.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
                selected = nodes.iter().take(num_nodes).map(|(id, _)| (*id).clone()).collect();
            }
            _ => {
                // Balanced strategy (combine metrics)
                let mut scored_nodes: Vec<_> = self.node_list.iter().map(|id| {
                    let lat = state.latencies.get(id).unwrap_or(&1000.0);
                    let bw = state.bandwidth.get(id).unwrap_or(&0.0);
                    let energy = state.energy_scores.get(id).unwrap_or(&0.5);
                    let score = (1.0 / (lat + 0.1)) + bw + energy;
                    (id.clone(), score)
                }).collect();
                scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
                selected = scored_nodes.iter().take(num_nodes).map(|(id, _)| id.clone()).collect();
            }
        }
        
        // Fallback if empty
        if selected.is_empty() && !self.node_list.is_empty() {
            selected.push(self.node_list[0].clone());
        }
        
        selected
    }
}

impl Default for RlRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = RlRouter::new();
        assert!(!router.enabled);
    }

    #[test]
    fn test_router_enable() {
        let mut router = RlRouter::new();
        router.enable(5, 10);
        assert!(router.enabled);
        assert!(router.agent.is_some());
    }

    #[test]
    fn test_network_state_features() {
        let mut state = NetworkState::new();
        state.congestion = 0.5;
        state.latencies.insert("node1".to_string(), 10.0);
        state.latencies.insert("node2".to_string(), 20.0);
        
        let features = state.to_feature_vector();
        assert_eq!(features.len(), 5);
        assert_eq!(features[0], 0.5); // congestion
        assert_eq!(features[1], 15.0); // avg latency
    }

    #[test]
    fn test_routing_action() {
        let mut router = RlRouter::new();
        router.enable(5, 10);
        
        let mut state = NetworkState::new();
        state.congestion = 0.3;
        state.latencies.insert("node1".to_string(), 10.0);
        state.latencies.insert("node2".to_string(), 20.0);
        state.latencies.insert("node3".to_string(), 5.0);
        state.bandwidth.insert("node1".to_string(), 100.0);
        state.bandwidth.insert("node2".to_string(), 50.0);
        state.bandwidth.insert("node3".to_string(), 150.0);
        
        let action = router.select_action(&state).unwrap();
        assert!(!action.nodes.is_empty());
        assert!(action.confidence >= 0.0 && action.confidence <= 1.0);
    }
}
