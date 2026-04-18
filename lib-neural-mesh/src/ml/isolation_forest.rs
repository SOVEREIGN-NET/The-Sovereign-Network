//! Isolation Forest implementation for anomaly detection
//!
//! This module implements the Isolation Forest algorithm for detecting anomalies.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Isolation Forest hyperparameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForestConfig {
    /// Number of trees in the forest
    pub n_trees: usize,
    /// Subsample size for each tree
    pub subsample_size: usize,
    /// Maximum tree depth
    pub max_depth: usize,
    /// Random seed
    pub random_seed: Option<u64>,
}

impl Default for IsolationForestConfig {
    fn default() -> Self {
        Self {
            n_trees: 100,
            subsample_size: 256,
            max_depth: 10,
            random_seed: None,
        }
    }
}

/// Node in an isolation tree
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IsolationNode {
    Internal {
        feature: usize,
        split_value: f32,
        left: Box<IsolationNode>,
        right: Box<IsolationNode>,
    },
    Leaf {
        size: usize,
    },
}

impl IsolationNode {
    /// Compute path length for a sample
    fn path_length(&self, sample: &[f32], current_depth: usize) -> f32 {
        match self {
            IsolationNode::Internal { feature, split_value, left, right } => {
                if sample[*feature] < *split_value {
                    left.path_length(sample, current_depth + 1)
                } else {
                    right.path_length(sample, current_depth + 1)
                }
            }
            IsolationNode::Leaf { size } => {
                // Add average path length of unsuccessful search in BST
                current_depth as f32 + Self::average_path_length(*size)
            }
        }
    }
    
    /// Average path length of unsuccessful search in BST
    fn average_path_length(n: usize) -> f32 {
        if n <= 1 {
            return 0.0;
        }
        
        // H(n-1) - (n-1)/n where H is harmonic number
        let n_f = n as f32;
        let h_n = 2.0 * (n_f - 1.0 + std::f32::consts::E.ln()).ln() - 2.0 * (n_f - 1.0) / n_f;
        h_n
    }
}

/// Single isolation tree
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationTree {
    root: IsolationNode,
    max_depth: usize,
}

impl IsolationTree {
    /// Build tree from samples
    fn build(samples: &[Vec<f32>], max_depth: usize, current_depth: usize) -> IsolationNode {
        if samples.is_empty() || current_depth >= max_depth || samples.len() == 1 {
            return IsolationNode::Leaf { size: samples.len() };
        }
        
        let mut rng = rand::thread_rng();
        let n_features = samples[0].len();
        
        // Randomly select feature
        let feature = rng.gen_range(0..n_features);
        
        // Find min and max values for this feature
        let mut min_val = f32::INFINITY;
        let mut max_val = f32::NEG_INFINITY;
        
        for sample in samples {
            let val = sample[feature];
            min_val = min_val.min(val);
            max_val = max_val.max(val);
        }
        
        if (max_val - min_val).abs() < 1e-10 {
            return IsolationNode::Leaf { size: samples.len() };
        }
        
        // Random split point
        let split_value = rng.gen_range(min_val..max_val);
        
        // Partition samples
        let mut left_samples = Vec::new();
        let mut right_samples = Vec::new();
        
        for sample in samples {
            if sample[feature] < split_value {
                left_samples.push(sample.clone());
            } else {
                right_samples.push(sample.clone());
            }
        }
        
        // Build subtrees
        let left = Box::new(Self::build(&left_samples, max_depth, current_depth + 1));
        let right = Box::new(Self::build(&right_samples, max_depth, current_depth + 1));
        
        IsolationNode::Internal {
            feature,
            split_value,
            left,
            right,
        }
    }
    
    /// Create new tree from samples
    fn new(samples: &[Vec<f32>], max_depth: usize) -> Self {
        let root = Self::build(samples, max_depth, 0);
        Self { root, max_depth }
    }
    
    /// Compute path length for sample
    fn path_length(&self, sample: &[f32]) -> f32 {
        self.root.path_length(sample, 0)
    }
}

/// Isolation Forest for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    config: IsolationForestConfig,
    n_samples_trained: usize,
}

impl IsolationForest {
    /// Create new Isolation Forest
    pub fn new(config: IsolationForestConfig) -> Self {
        Self {
            trees: Vec::new(),
            config,
            n_samples_trained: 0,
        }
    }
    
    /// Train forest on samples
    pub fn fit(&mut self, samples: &[Vec<f32>]) {
        if samples.is_empty() {
            return;
        }
        
        self.n_samples_trained = samples.len();
        self.trees.clear();
        
        let mut rng = rand::thread_rng();
        
        for _ in 0..self.config.n_trees {
            // Random subsample
            let subsample_size = self.config.subsample_size.min(samples.len());
            let mut subsample = Vec::with_capacity(subsample_size);
            
            for _ in 0..subsample_size {
                let idx = rng.gen_range(0..samples.len());
                subsample.push(samples[idx].clone());
            }
            
            // Build tree
            let tree = IsolationTree::new(&subsample, self.config.max_depth);
            self.trees.push(tree);
        }
    }
    
    /// Compute anomaly score for sample
    /// Returns score in [0, 1] where higher values indicate anomalies
    pub fn anomaly_score(&self, sample: &[f32]) -> f32 {
        if self.trees.is_empty() {
            return 0.0;
        }
        
        // Average path length across all trees
        let avg_path_length: f32 = self.trees.iter()
            .map(|tree| tree.path_length(sample))
            .sum::<f32>() / self.trees.len() as f32;
        
        // Expected average path length for normal data
        let c = IsolationNode::average_path_length(self.n_samples_trained);
        
        if c == 0.0 {
            return 0.0;
        }
        
        // Anomaly score: 2^(-E[h(x)]/c)
        // Score → 1 for anomalies (short paths)
        // Score → 0 for normal data (long paths)
        2.0_f32.powf(-avg_path_length / c)
    }
    
    /// Predict if sample is anomaly based on threshold
    pub fn predict(&self, sample: &[f32], threshold: f32) -> bool {
        self.anomaly_score(sample) > threshold
    }
    
    /// Batch prediction
    pub fn predict_batch(&self, samples: &[Vec<f32>], threshold: f32) -> Vec<bool> {
        samples.iter()
            .map(|sample| self.predict(sample, threshold))
            .collect()
    }
    
    /// Get anomaly scores for batch
    pub fn score_batch(&self, samples: &[Vec<f32>]) -> Vec<f32> {
        samples.iter()
            .map(|sample| self.anomaly_score(sample))
            .collect()
    }
    
    /// Save model
    pub fn save(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize forest: {}", e))
    }
    
    /// Load model
    pub fn load(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize forest: {}", e))
    }
}

/// Anomaly detector with automatic threshold tuning
pub struct AnomalyDetector {
    forest: IsolationForest,
    threshold: f32,
    contamination: f32,
}

impl AnomalyDetector {
    /// Create new detector
    pub fn new(config: IsolationForestConfig, contamination: f32) -> Self {
        Self {
            forest: IsolationForest::new(config),
            threshold: 0.6, // Default threshold
            contamination,
        }
    }
    
    /// Train detector and set threshold
    pub fn fit(&mut self, samples: &[Vec<f32>]) {
        self.forest.fit(samples);
        
        // Compute scores for training data
        let mut scores: Vec<f32> = samples.iter()
            .map(|sample| self.forest.anomaly_score(sample))
            .collect();
        
        // Sort scores
        scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(Ordering::Equal));
        
        // Set threshold at contamination percentile
        let threshold_idx = (scores.len() as f32 * self.contamination) as usize;
        self.threshold = scores.get(threshold_idx).copied().unwrap_or(0.6);
    }
    
    /// Detect anomaly
    pub fn predict(&self, sample: &[f32]) -> bool {
        self.forest.predict(sample, self.threshold)
    }
    
    /// Get anomaly score
    pub fn score(&self, sample: &[f32]) -> f32 {
        self.forest.anomaly_score(sample)
    }
    
    /// Get current threshold
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Save the internal forest to bytes for distributed sync
    pub fn save_forest(&self) -> Result<Vec<u8>, String> {
        self.forest.save()
    }

    /// Load a forest from bytes (replaces internal state)
    pub fn load_forest(&mut self, forest: IsolationForest) {
        self.forest = forest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_isolation_forest_creation() {
        let config = IsolationForestConfig::default();
        let forest = IsolationForest::new(config);
        assert_eq!(forest.trees.len(), 0);
    }
    
    #[test]
    fn test_training() {
        let config = IsolationForestConfig {
            n_trees: 10,
            subsample_size: 50,
            max_depth: 5,
            random_seed: Some(42),
        };
        let mut forest = IsolationForest::new(config);
        
        // Generate normal data
        let samples: Vec<Vec<f32>> = (0..100)
            .map(|i| vec![i as f32 / 100.0, (i as f32 / 100.0).sin()])
            .collect();
        
        forest.fit(&samples);
        assert_eq!(forest.trees.len(), 10);
    }
    
    #[test]
    fn test_anomaly_detection() {
        let config = IsolationForestConfig {
            n_trees: 50,
            subsample_size: 100,
            max_depth: 8,
            random_seed: Some(42),
        };
        let mut forest = IsolationForest::new(config);
        
        // Normal data clustered around origin
        let normal_data: Vec<Vec<f32>> = (0..100)
            .map(|i| {
                let x = (i as f32 / 50.0 - 1.0) * 0.1;
                let y = (i as f32 / 50.0 - 1.0) * 0.1;
                vec![x, y]
            })
            .collect();
        
        forest.fit(&normal_data);
        
        // Normal point should have low anomaly score
        let normal_point = vec![0.05, 0.05];
        let normal_score = forest.anomaly_score(&normal_point);
        assert!(normal_score < 0.6);
        
        // Outlier should have high anomaly score
        let outlier = vec![10.0, 10.0];
        let outlier_score = forest.anomaly_score(&outlier);
        assert!(outlier_score > 0.6);
        assert!(outlier_score > normal_score);
    }
    
    #[test]
    fn test_anomaly_detector() {
        let config = IsolationForestConfig {
            n_trees: 50,
            subsample_size: 100,
            max_depth: 8,
            random_seed: Some(42),
        };
        let mut detector = AnomalyDetector::new(config, 0.1);
        
        // Normal data
        let samples: Vec<Vec<f32>> = (0..100)
            .map(|i| {
                let x = (i as f32 / 50.0 - 1.0) * 0.1;
                let y = (i as f32 / 50.0 - 1.0) * 0.1;
                vec![x, y]
            })
            .collect();
        
        detector.fit(&samples);
        
        // Check predictions
        let normal = vec![0.05, 0.05];
        let outlier = vec![10.0, 10.0];
        
        assert!(!detector.predict(&normal));
        assert!(detector.predict(&outlier));
    }
}
