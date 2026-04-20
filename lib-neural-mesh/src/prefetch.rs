//! Predictive prefetching using LSTM for negative latency
//!
//! Includes the base `PredictivePrefetcher` (shard-level prediction) and
//! the higher-level `SemanticPrefetcher` that extends it with tag-chain
//! prediction for the Semantic Channeling layer.

use crate::error::{NeuralMeshError, Result};
use crate::ml::{LstmNetwork, LstmConfig};
use crate::semantic_channeling::TagId;
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

    /// Train the LSTM on accumulated access history.
    ///
    /// Converts the recorded access patterns into input→target sequence pairs
    /// and calls the underlying LSTM `train()` method. Without this, the LSTM
    /// runs inference on random Xavier-initialized weights forever.
    ///
    /// Returns `(loss, num_sequences)` — the MSE loss and how many training
    /// sequences were generated from history.
    pub fn train_from_history(&mut self) -> Result<(f32, usize)> {
        if !self.enabled {
            return Err(NeuralMeshError::TrainingFailed(
                "Predictive prefetcher not enabled".to_string(),
            ));
        }

        let lstm = self.lstm.as_mut().ok_or_else(|| {
            NeuralMeshError::TrainingFailed("No LSTM network initialized".to_string())
        })?;

        // Need at least sequence_length + 1 patterns to form one training pair
        let min_len = self.sequence_length + 1;
        if self.history.len() < min_len {
            return Err(NeuralMeshError::TrainingFailed(
                format!(
                    "Not enough history to train: have {}, need at least {}",
                    self.history.len(),
                    min_len
                ),
            ));
        }

        // Convert history into feature vectors
        let mut feature_vecs: Vec<Vec<f32>> = Vec::with_capacity(self.history.len());
        let mut prev_time = 0u64;
        for pattern in self.history.iter() {
            let feat = pattern.to_feature_vector(&self.shard_to_id, prev_time);
            prev_time = pattern.timestamp;
            feature_vecs.push(feat);
        }

        // Create overlapping sequence→target pairs using a sliding window
        // Input: feature_vecs[i..i+seq_len], Target: feature_vecs[i+1..i+seq_len+1]
        let mut sequences: Vec<Vec<Vec<f32>>> = Vec::new();
        let mut targets: Vec<Vec<Vec<f32>>> = Vec::new();

        let max_pairs = 32usize; // Cap training pairs per call to keep latency bounded
        let total = feature_vecs.len();
        let stride = if total - self.sequence_length > max_pairs {
            (total - self.sequence_length) / max_pairs
        } else {
            1
        };

        let mut i = 0;
        while i + self.sequence_length < total && sequences.len() < max_pairs {
            let seq: Vec<Vec<f32>> = feature_vecs[i..i + self.sequence_length].to_vec();
            let tgt: Vec<Vec<f32>> = feature_vecs[i + 1..i + self.sequence_length + 1].to_vec();
            sequences.push(seq);
            targets.push(tgt);
            i += stride;
        }

        let num_sequences = sequences.len();
        if num_sequences == 0 {
            return Ok((0.0, 0));
        }

        let loss = lstm.train(&sequences, &targets);
        Ok((loss, num_sequences))
    }

    /// Save LSTM model weights to bytes (compressed-ready for distributed sync)
    pub fn save_model(&self) -> Result<Vec<u8>> {
        let lstm = self.lstm.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("No LSTM initialized".to_string())
        })?;
        lstm.save().map_err(|e| NeuralMeshError::InferenceFailed(e))
    }

    /// Load LSTM model weights from bytes (from compressed distributed sync)
    pub fn load_model(&mut self, data: &[u8]) -> Result<()> {
        let lstm = LstmNetwork::load(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(e))?;
        self.lstm = Some(lstm);
        self.enabled = true;
        Ok(())
    }

    /// Get the byte size of the current model weights
    pub fn model_size_bytes(&self) -> usize {
        self.save_model().map(|v| v.len()).unwrap_or(0)
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

// ═══════════════════════════════════════════════════════════════════════
// SemanticPrefetcher — tag-chain prediction for Semantic Channeling
// ═══════════════════════════════════════════════════════════════════════

/// A tag-chain access event recorded for training the semantic prefetcher.
#[derive(Debug, Clone)]
pub struct TagAccessEvent {
    /// The tags that were accessed (in order of the channel traversal)
    pub tag_chain: Vec<TagId>,

    /// Timestamp in milliseconds
    pub timestamp: u64,

    /// Channel strategy that produced this traversal (as a u8 tag:
    /// 0=DepthFirst, 1=BreadthFirst, 2=Similarity, 3=RandomWalk, etc.)
    pub strategy_id: u8,
}

/// Prediction of the next tag chain the network is likely to request.
#[derive(Debug, Clone)]
pub struct TagChainPrediction {
    /// Predicted next tags (in order of traversal likelihood)
    pub predicted_tags: Vec<TagId>,

    /// Confidence score (0.0–1.0)
    pub confidence: f32,

    /// How many steps ahead this prediction covers
    pub lookahead: usize,
}

/// Extends the base `PredictivePrefetcher` with tag-chain prediction.
///
/// Where the base prefetcher predicts "which shard will be accessed next?",
/// the SemanticPrefetcher predicts "which tag chain will the channeling
/// layer traverse next?" — enabling pre-fetching entire semantic
/// neighborhoods before they're requested.
///
/// Architecture:
/// - Wraps the base shard-level prefetcher for backward compatibility
/// - Adds a second LSTM that operates on tag ID sequences
/// - Tag IDs are hashed to a fixed vocabulary index (modular ring)
/// - Output is a probability distribution over the tag vocabulary
pub struct SemanticPrefetcher {
    /// Base shard-level prefetcher
    pub base: PredictivePrefetcher,

    /// Tag-chain LSTM (separate from the shard LSTM)
    tag_lstm: Option<LstmNetwork>,

    /// Tag history for training
    tag_history: VecDeque<TagAccessEvent>,

    /// Tag vocabulary: TagId → index
    tag_to_idx: HashMap<TagId, usize>,

    /// Reverse: index → TagId
    idx_to_tag: HashMap<usize, TagId>,

    /// Next index in the vocabulary
    next_tag_idx: usize,

    /// Vocabulary capacity (mod ring size)
    vocab_capacity: usize,

    /// Maximum tag history length
    max_tag_history: usize,

    /// Sequence length for the tag LSTM
    tag_sequence_length: usize,

    /// Confidence threshold for tag predictions
    tag_confidence_threshold: f32,

    /// Whether tag-chain prediction is enabled
    tag_prediction_enabled: bool,
}

impl std::fmt::Debug for SemanticPrefetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticPrefetcher")
            .field("base", &self.base)
            .field("tag_prediction_enabled", &self.tag_prediction_enabled)
            .field("tag_vocab_size", &self.tag_to_idx.len())
            .field("tag_history_len", &self.tag_history.len())
            .field("has_tag_lstm", &self.tag_lstm.is_some())
            .finish()
    }
}

impl SemanticPrefetcher {
    /// Create a new semantic prefetcher (tag prediction disabled by default).
    pub fn new() -> Self {
        Self {
            base: PredictivePrefetcher::new(),
            tag_lstm: None,
            tag_history: VecDeque::new(),
            tag_to_idx: HashMap::new(),
            idx_to_tag: HashMap::new(),
            next_tag_idx: 0,
            vocab_capacity: 4096,
            max_tag_history: 2000,
            tag_sequence_length: 8,
            tag_confidence_threshold: 0.5,
            tag_prediction_enabled: false,
        }
    }

    /// Enable tag-chain prediction with an LSTM.
    ///
    /// * `hidden_size` — LSTM hidden state dimension (e.g. 64)
    /// * `sequence_length` — how many past tag events to consider
    pub fn enable_tag_prediction(&mut self, hidden_size: usize, sequence_length: usize) {
        // Input features per tag event: [tag_idx_normalized, time_delta, strategy_id, chain_len]
        let input_size = 4;
        // Output: predicted next tag features
        let output_size = 4;

        let config = LstmConfig {
            learning_rate: 5e-4,
            input_size,
            hidden_size,
            output_size,
            sequence_length,
            batch_size: 16,
        };

        self.tag_lstm = Some(LstmNetwork::new(config));
        self.tag_sequence_length = sequence_length;
        self.tag_prediction_enabled = true;
    }

    /// Enable with default configuration.
    pub fn enable_default(&mut self) {
        self.base.enable_default();
        self.enable_tag_prediction(64, 8);
    }

    /// Set the tag prediction confidence threshold.
    pub fn set_tag_threshold(&mut self, threshold: f32) {
        self.tag_confidence_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Register a tag in the vocabulary.
    fn register_tag(&mut self, tag_id: TagId) -> usize {
        if let Some(&idx) = self.tag_to_idx.get(&tag_id) {
            return idx;
        }

        let idx = self.next_tag_idx % self.vocab_capacity;
        self.tag_to_idx.insert(tag_id, idx);
        self.idx_to_tag.insert(idx, tag_id);
        self.next_tag_idx += 1;
        idx
    }

    /// Record a tag-chain access event (for training).
    pub fn record_tag_access(&mut self, event: TagAccessEvent) {
        // Register all tags in the chain
        for tag_id in &event.tag_chain {
            self.register_tag(*tag_id);
        }

        self.tag_history.push_back(event);

        if self.tag_history.len() > self.max_tag_history {
            self.tag_history.pop_front();
        }
    }

    /// Convert a tag access event to a feature vector.
    ///
    /// Features: `[primary_tag_idx_norm, time_delta_norm, strategy_id_norm, chain_len_norm]`
    fn tag_event_to_features(&self, event: &TagAccessEvent, prev_time: u64) -> Vec<f32> {
        let primary_idx = event
            .tag_chain
            .first()
            .and_then(|t| self.tag_to_idx.get(t))
            .copied()
            .unwrap_or(0);

        let tag_norm = primary_idx as f32 / self.vocab_capacity as f32;
        let time_delta = (event.timestamp.saturating_sub(prev_time)) as f32 / 10_000.0;
        let strategy_norm = event.strategy_id as f32 / 8.0;
        let chain_len_norm = event.tag_chain.len() as f32 / 16.0;

        vec![tag_norm, time_delta, strategy_norm, chain_len_norm]
    }

    /// Predict the next tag chain the channeling layer will request.
    ///
    /// Returns up to `num_predictions` tag chain predictions, sorted by
    /// descending confidence.
    pub fn predict_next_tags(
        &mut self,
        num_predictions: usize,
    ) -> Result<Vec<TagChainPrediction>> {
        if !self.tag_prediction_enabled {
            return Err(NeuralMeshError::InferenceFailed(
                "Tag-chain prediction not enabled".to_string(),
            ));
        }

        if self.tag_lstm.is_none() {
            return Err(NeuralMeshError::InferenceFailed(
                "No tag LSTM initialized".to_string(),
            ));
        }

        if self.tag_history.is_empty() {
            return Ok(Vec::new());
        }

        // Build feature vectors FIRST (borrows self immutably)
        let recent: Vec<&TagAccessEvent> = self.tag_history.iter().rev()
            .take(self.tag_sequence_length)
            .collect();

        let mut prev_time = 0u64;
        let features: Vec<Vec<f32>> = recent
            .iter()
            .rev()
            .map(|e| {
                let feat = self.tag_event_to_features(e, prev_time);
                prev_time = e.timestamp;
                feat
            })
            .collect();

        // NOW get LSTM mutably (features already built)
        let lstm = self.tag_lstm.as_mut().unwrap();
        let predictions = lstm.predict_multi(&features, num_predictions);

        let mut results = Vec::new();
        for pred in predictions.iter().take(num_predictions) {
            // Decode predicted tag index from first feature
            let predicted_idx = (pred[0] * self.vocab_capacity as f32).round() as usize;

            if let Some(&tag_id) = self.idx_to_tag.get(&predicted_idx) {
                let confidence = self.calculate_tag_confidence(pred);
                let chain_len = (pred[3] * 16.0).round().max(1.0) as usize;

                if confidence >= self.tag_confidence_threshold {
                    results.push(TagChainPrediction {
                        predicted_tags: vec![tag_id], // primary prediction
                        confidence,
                        lookahead: chain_len,
                    });
                }
            }
        }

        // Fallback: return the most recently accessed tags
        if results.is_empty() {
            results = self.fallback_tag_prediction(num_predictions);
        }

        // Sort by confidence descending
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        Ok(results)
    }

    /// Calculate confidence from a tag prediction vector.
    fn calculate_tag_confidence(&self, prediction: &[f32]) -> f32 {
        let mean: f32 = prediction.iter().sum::<f32>() / prediction.len() as f32;
        let variance: f32 = prediction.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f32>() / prediction.len() as f32;
        (1.0 / (1.0 + variance)).clamp(0.0, 1.0)
    }

    /// Fallback: return the most frequently accessed tags.
    fn fallback_tag_prediction(&self, num: usize) -> Vec<TagChainPrediction> {
        // Count tag frequency in recent history
        let mut freq: HashMap<TagId, usize> = HashMap::new();
        for event in self.tag_history.iter().rev().take(50) {
            for tag in &event.tag_chain {
                *freq.entry(*tag).or_insert(0) += 1;
            }
        }

        let mut pairs: Vec<_> = freq.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));

        pairs.into_iter()
            .take(num)
            .map(|(tag_id, count)| TagChainPrediction {
                predicted_tags: vec![tag_id],
                confidence: (count as f32 / 50.0).min(0.8), // Capped below normal threshold
                lookahead: 1,
            })
            .collect()
    }

    /// Train the tag-chain LSTM on accumulated tag history.
    ///
    /// Returns `(loss, num_sequences)`.
    pub fn train_from_tag_history(&mut self) -> Result<(f32, usize)> {
        if !self.tag_prediction_enabled {
            return Err(NeuralMeshError::TrainingFailed(
                "Tag-chain prediction not enabled".to_string(),
            ));
        }

        let min_len = self.tag_sequence_length + 1;
        if self.tag_history.len() < min_len {
            return Err(NeuralMeshError::TrainingFailed(
                format!(
                    "Not enough tag history: have {}, need {}",
                    self.tag_history.len(),
                    min_len
                ),
            ));
        }

        // Convert history to feature vectors
        let mut feature_vecs: Vec<Vec<f32>> = Vec::with_capacity(self.tag_history.len());
        let mut prev_time = 0u64;
        for event in self.tag_history.iter() {
            let feat = self.tag_event_to_features(event, prev_time);
            prev_time = event.timestamp;
            feature_vecs.push(feat);
        }

        // Sliding window: sequences and targets
        let max_pairs = 32usize;
        let total = feature_vecs.len();
        let stride = if total - self.tag_sequence_length > max_pairs {
            (total - self.tag_sequence_length) / max_pairs
        } else {
            1
        };

        let mut sequences = Vec::new();
        let mut targets = Vec::new();
        let mut i = 0;
        while i + self.tag_sequence_length < total && sequences.len() < max_pairs {
            sequences.push(feature_vecs[i..i + self.tag_sequence_length].to_vec());
            targets.push(feature_vecs[i + 1..i + self.tag_sequence_length + 1].to_vec());
            i += stride;
        }

        let num_sequences = sequences.len();
        if num_sequences == 0 {
            return Ok((0.0, 0));
        }

        let lstm = self.tag_lstm.as_mut().ok_or_else(|| {
            NeuralMeshError::TrainingFailed("No tag LSTM initialized".to_string())
        })?;

        let loss = lstm.train(&sequences, &targets);
        Ok((loss, num_sequences))
    }

    /// Save the tag LSTM model weights (for distributed sync).
    pub fn save_tag_model(&self) -> Result<Vec<u8>> {
        let lstm = self.tag_lstm.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("No tag LSTM initialized".to_string())
        })?;
        lstm.save().map_err(|e| NeuralMeshError::InferenceFailed(e))
    }

    /// Load tag LSTM model weights (from distributed sync).
    pub fn load_tag_model(&mut self, data: &[u8]) -> Result<()> {
        let lstm = LstmNetwork::load(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(e))?;
        self.tag_lstm = Some(lstm);
        self.tag_prediction_enabled = true;
        Ok(())
    }

    /// Total model size (shard LSTM + tag LSTM) in bytes.
    pub fn total_model_size_bytes(&self) -> usize {
        self.base.model_size_bytes()
            + self.save_tag_model().map(|v| v.len()).unwrap_or(0)
    }

    /// Tag vocabulary size
    pub fn tag_vocab_size(&self) -> usize {
        self.tag_to_idx.len()
    }
}

impl Default for SemanticPrefetcher {
    fn default() -> Self {
        Self::new()
    }
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

    // ── SemanticPrefetcher tests ─────────────────────────────────────

    fn make_tag(seed: u8) -> TagId {
        TagId([seed; 32])
    }

    #[test]
    fn test_semantic_prefetcher_creation() {
        let sp = SemanticPrefetcher::new();
        assert!(!sp.tag_prediction_enabled);
        assert_eq!(sp.tag_vocab_size(), 0);
    }

    #[test]
    fn test_semantic_prefetcher_enable_default() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_default();
        assert!(sp.tag_prediction_enabled);
        assert!(sp.base.enabled);
    }

    #[test]
    fn test_tag_access_recording() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_tag_prediction(32, 4);

        sp.record_tag_access(TagAccessEvent {
            tag_chain: vec![make_tag(1), make_tag(2)],
            timestamp: 1000,
            strategy_id: 0,
        });

        assert_eq!(sp.tag_history.len(), 1);
        assert_eq!(sp.tag_vocab_size(), 2);
    }

    #[test]
    fn test_tag_prediction_not_enabled_error() {
        let mut sp = SemanticPrefetcher::new();
        let result = sp.predict_next_tags(3);
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_prediction_with_history() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_tag_prediction(32, 4);

        // Record enough events for the LSTM
        for i in 0..20u64 {
            sp.record_tag_access(TagAccessEvent {
                tag_chain: vec![make_tag((i % 5) as u8)],
                timestamp: 1000 + i * 100,
                strategy_id: 0,
            });
        }

        let predictions = sp.predict_next_tags(3).unwrap();
        // Should have at least fallback predictions
        assert!(!predictions.is_empty());
    }

    #[test]
    fn test_tag_train_from_history() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_tag_prediction(32, 4);

        // Need at least seq_length + 1 = 5 events
        for i in 0..10u64 {
            sp.record_tag_access(TagAccessEvent {
                tag_chain: vec![make_tag((i % 3) as u8)],
                timestamp: 1000 + i * 50,
                strategy_id: (i % 2) as u8,
            });
        }

        let (loss, num_seq) = sp.train_from_tag_history().unwrap();
        assert!(loss >= 0.0);
        assert!(num_seq > 0);
    }

    #[test]
    fn test_tag_train_insufficient_history() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_tag_prediction(32, 8);

        // Only 3 events, need 9 (seq_length=8 + 1)
        for i in 0..3u64 {
            sp.record_tag_access(TagAccessEvent {
                tag_chain: vec![make_tag(i as u8)],
                timestamp: 1000 + i * 100,
                strategy_id: 0,
            });
        }

        let result = sp.train_from_tag_history();
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_model_save_load() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_tag_prediction(32, 4);

        let bytes = sp.save_tag_model().unwrap();
        assert!(!bytes.is_empty());

        let mut sp2 = SemanticPrefetcher::new();
        sp2.load_tag_model(&bytes).unwrap();
        assert!(sp2.tag_prediction_enabled);
    }

    #[test]
    fn test_total_model_size() {
        let mut sp = SemanticPrefetcher::new();
        sp.enable_default();
        let size = sp.total_model_size_bytes();
        assert!(size > 0);
    }
}
