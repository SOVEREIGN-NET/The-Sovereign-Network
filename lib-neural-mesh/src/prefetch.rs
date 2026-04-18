//! Predictive prefetching using LSTM for negative latency

use crate::error::{NeuralMeshError, Result};
use crate::ml::{LstmNetwork, LstmConfig};
use std::collections::{VecDeque, HashMap};

/// Access history for prediction
#[derive(Debug, Clone)]
pub struct AccessPattern {
    /// Shard ID
    pub shard_id: String,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// User/context ID
    pub context: String,
}

impl AccessPattern {
    /// Convert to feature vector for LSTM
    /// Features: [shard_hash, time_delta, context_hash]
    pub fn to_feature_vector(&self, shard_to_id: &HashMap<String, usize>, prev_time: u64) -> Vec<f32> {
        let shard_id = *shard_to_id.get(&self.shard_id).unwrap_or(&0) as f32;
        let time_delta = (self.timestamp.saturating_sub(prev_time)) as f32 / 1000.0; // Convert to seconds
        let context_hash = self.context.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32)) as f32;
        
        vec![shard_id / 1000.0, time_delta / 100.0, context_hash / 10000.0]
    }
}

/// Predictive prefetcher using sequence modeling
pub struct PredictivePrefetcher {
    enabled: bool,
    history: VecDeque<AccessPattern>,
    max_history: usize,
    confidence_threshold: f32,
    lstm: Option<LstmNetwork>,
    sequence_length: usize,
    shard_to_id: HashMap<String, usize>,
    id_to_shard: HashMap<usize, String>,
    next_shard_id: usize,
}

impl std::fmt::Debug for PredictivePrefetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredictivePrefetcher")
            .field("enabled", &self.enabled)
            .field("history_len", &self.history.len())
            .field("confidence_threshold", &self.confidence_threshold)
            .field("has_lstm", &self.lstm.is_some())
            .finish()
    }
}

impl PredictivePrefetcher {
    /// Create new predictive prefetcher
    pub fn new() -> Self {
        Self {
            enabled: false,
            history: VecDeque::new(),
            max_history: 1000,
            confidence_threshold: 0.8, // 80% confidence threshold
            lstm: None,
            sequence_length: 10,
            shard_to_id: HashMap::new(),
            id_to_shard: HashMap::new(),
            next_shard_id: 0,
        }
    }

    /// Enable predictive prefetching with LSTM
    pub fn enable(&mut self, input_size: usize, hidden_size: usize, output_size: usize, sequence_length: usize) {
        let config = LstmConfig {
            learning_rate: 1e-3,
            input_size,
            hidden_size,
            output_size,
            sequence_length,
            batch_size: 32,
        };
        
        self.lstm = Some(LstmNetwork::new(config));
        self.sequence_length = sequence_length;
        self.enabled = true;
    }
    
    /// Enable with default configuration
    pub fn enable_default(&mut self) {
        self.enable(3, 64, 3, 10); // 3 input features, 64 hidden, 3 output, 10 step sequence
    }

    /// Set confidence threshold (0.0 - 1.0)
    pub fn set_threshold(&mut self, threshold: f32) {
        self.confidence_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Record access pattern
    pub fn record_access(&mut self, pattern: AccessPattern) {
        // Register shard ID if new
        if !self.shard_to_id.contains_key(&pattern.shard_id) {
            self.shard_to_id.insert(pattern.shard_id.clone(), self.next_shard_id);
            self.id_to_shard.insert(self.next_shard_id, pattern.shard_id.clone());
            self.next_shard_id += 1;
        }
        
        self.history.push_back(pattern);
        
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }

    /// Predict next likely accesses
    pub fn predict_next(&mut self, context: &str, num_predictions: usize) -> Result<Vec<PredictionResult>> {
        if !self.enabled {
            return Err(NeuralMeshError::InferenceFailed(
                "Predictive prefetcher not enabled".to_string(),
            ));
        }

        let lstm = self.lstm.as_mut().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("No LSTM network initialized".to_string())
        })?;

        // Get recent patterns for this context
        let recent_patterns: Vec<&AccessPattern> = self
            .history
            .iter()
            .rev()
            .filter(|p| p.context == context)
            .take(self.sequence_length)
            .collect();
        
        if recent_patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Convert patterns to feature vectors
        let mut prev_time = 0;
        let features: Vec<Vec<f32>> = recent_patterns
            .iter()
            .rev()
            .map(|p| {
                let feat = p.to_feature_vector(&self.shard_to_id, prev_time);
                prev_time = p.timestamp;
                feat
            })
            .collect();

        // Get LSTM predictions
        let predictions = lstm.predict_multi(&features, num_predictions);
        
        // Convert predictions back to shard IDs
        let mut results = Vec::new();
        for pred in predictions.iter().take(num_predictions) {
            // Use first element as shard ID prediction
            let shard_id_float = pred[0] * 1000.0;
            let shard_id_int = shard_id_float.round() as usize;
            
            if let Some(shard_name) = self.id_to_shard.get(&shard_id_int) {
                // Calculate confidence based on prediction consistency
                let confidence = self.calculate_confidence(&pred);
                
                if confidence >= self.confidence_threshold {
                    results.push(PredictionResult {
                        shard_id: shard_name.clone(),
                        confidence,
                    });
                }
            }
        }
        
        // Fallback to heuristic if LSTM predictions insufficient
        if results.is_empty() {
            results = self.fallback_prediction(context, num_predictions);
        }
        
        Ok(results)
    }

    /// Calculate confidence from prediction vector
    fn calculate_confidence(&self, prediction: &[f32]) -> f32 {
        // Use variance as inverse confidence (low variance = high confidence)
        let mean: f32 = prediction.iter().sum::<f32>() / prediction.len() as f32;
        let variance: f32 = prediction.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f32>() / prediction.len() as f32;
        
        // Convert to confidence score (0-1)
        (1.0 / (1.0 + variance)).clamp(0.0, 1.0)
    }

    /// Fallback prediction using pattern matching
    fn fallback_prediction(&self, context: &str, num_predictions: usize) -> Vec<PredictionResult> {
        let recent_patterns: Vec<&AccessPattern> = self
            .history
            .iter()
            .rev()
            .filter(|p| p.context == context)
            .take(5)
            .collect();
        
        if recent_patterns.is_empty() {
            return Vec::new();
        }

        recent_patterns
            .into_iter()
            .take(num_predictions)
            .map(|p| PredictionResult {
                shard_id: p.shard_id.clone(),
                confidence: 0.6, // Lower confidence for fallback
            })
            .collect()
    }

    /// Check if predictions meet confidence threshold
    pub fn should_prefetch(&self, prediction: &PredictionResult) -> bool {
        prediction.confidence >= self.confidence_threshold
    }
}

impl Default for PredictivePrefetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Prediction result with confidence
#[derive(Debug, Clone)]
pub struct PredictionResult {
    /// Predicted shard ID
    pub shard_id: String,
    
    /// Confidence score (0-1)
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetcher_creation() {
        let prefetcher = PredictivePrefetcher::new();
        assert!(!prefetcher.enabled);
        assert_eq!(prefetcher.confidence_threshold, 0.8);
    }

    #[test]
    fn test_access_recording() {
        let mut prefetcher = PredictivePrefetcher::new();
        
        prefetcher.record_access(AccessPattern {
            shard_id: "shard1".to_string(),
            timestamp: 1000,
            context: "user1".to_string(),
        });
        
        assert_eq!(prefetcher.history.len(), 1);
    }

    #[test]
    fn test_prediction() {
        let mut prefetcher = PredictivePrefetcher::new();
        prefetcher.enable_default();
        
        // Record some access patterns
        for i in 0..15 {
            prefetcher.record_access(AccessPattern {
                shard_id: format!("shard{}", i % 3),
                timestamp: 1000 + i as u64 * 100,
                context: "user1".to_string(),
            });
        }
        
        let predictions = prefetcher.predict_next("user1", 3).unwrap();
        assert!(!predictions.is_empty());
    }
}
