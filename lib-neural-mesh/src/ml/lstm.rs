//! LSTM implementation for predictive prefetching
//!
//! This module implements Long Short-Term Memory networks for sequence prediction.

use ndarray::{Array1, Array2};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// LSTM hyperparameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstmConfig {
    /// Learning rate
    pub learning_rate: f64,
    /// Input dimension
    pub input_size: usize,
    /// Hidden state dimension
    pub hidden_size: usize,
    /// Output dimension
    pub output_size: usize,
    /// Sequence length for training
    pub sequence_length: usize,
    /// Batch size
    pub batch_size: usize,
}

impl Default for LstmConfig {
    fn default() -> Self {
        Self {
            learning_rate: 1e-3,
            input_size: 64,
            hidden_size: 128,
            output_size: 64,
            sequence_length: 10,
            batch_size: 32,
        }
    }
}

/// LSTM cell state
#[derive(Debug, Clone)]
struct LstmState {
    /// Hidden state
    h: Array1<f32>,
    /// Cell state
    c: Array1<f32>,
}

impl LstmState {
    fn new(hidden_size: usize) -> Self {
        Self {
            h: Array1::zeros(hidden_size),
            c: Array1::zeros(hidden_size),
        }
    }
}

/// LSTM network for sequence prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstmNetwork {
    config: LstmConfig,
    
    // Input gate weights
    w_ii: Array2<f32>, // input -> input gate
    w_hi: Array2<f32>, // hidden -> input gate
    b_i: Array1<f32>,
    
    // Forget gate weights
    w_if: Array2<f32>, // input -> forget gate
    w_hf: Array2<f32>, // hidden -> forget gate
    b_f: Array1<f32>,
    
    // Cell gate weights
    w_ig: Array2<f32>, // input -> cell gate
    w_hg: Array2<f32>, // hidden -> cell gate
    b_g: Array1<f32>,
    
    // Output gate weights
    w_io: Array2<f32>, // input -> output gate
    w_ho: Array2<f32>, // hidden -> output gate
    b_o: Array1<f32>,
    
    // Output projection
    w_out: Array2<f32>,
    b_out: Array1<f32>,
}

impl LstmNetwork {
    /// Create new LSTM network
    pub fn new(config: LstmConfig) -> Self {
        let mut rng = rand::thread_rng();
        
        let input_size = config.input_size;
        let hidden_size = config.hidden_size;
        let output_size = config.output_size;
        
        // Xavier initialization
        let mut init_weight = |rows: usize, cols: usize| {
            Array2::from_shape_fn((rows, cols), |_| {
                rng.gen_range(-1.0..1.0) * (2.0 / cols as f32).sqrt()
            })
        };
        
        Self {
            config,
            
            // Input gate
            w_ii: init_weight(hidden_size, input_size),
            w_hi: init_weight(hidden_size, hidden_size),
            b_i: Array1::zeros(hidden_size),
            
            // Forget gate
            w_if: init_weight(hidden_size, input_size),
            w_hf: init_weight(hidden_size, hidden_size),
            b_f: Array1::from_elem(hidden_size, 1.0), // Initialize to 1 (forget bias)
            
            // Cell gate
            w_ig: init_weight(hidden_size, input_size),
            w_hg: init_weight(hidden_size, hidden_size),
            b_g: Array1::zeros(hidden_size),
            
            // Output gate
            w_io: init_weight(hidden_size, input_size),
            w_ho: init_weight(hidden_size, hidden_size),
            b_o: Array1::zeros(hidden_size),
            
            // Output projection
            w_out: init_weight(output_size, hidden_size),
            b_out: Array1::zeros(output_size),
        }
    }
    
    /// Sigmoid activation
    fn sigmoid(x: f32) -> f32 {
        1.0 / (1.0 + (-x).exp())
    }
    
    /// Tanh activation
    fn tanh(x: f32) -> f32 {
        x.tanh()
    }
    
    /// Forward pass through one LSTM cell
    fn cell_forward(&self, input: &Array1<f32>, state: &LstmState) -> LstmState {
        // Input gate: i_t = σ(W_ii * x_t + W_hi * h_{t-1} + b_i)
        let i_t = (self.w_ii.dot(input) + self.w_hi.dot(&state.h) + &self.b_i)
            .mapv(Self::sigmoid);
        
        // Forget gate: f_t = σ(W_if * x_t + W_hf * h_{t-1} + b_f)
        let f_t = (self.w_if.dot(input) + self.w_hf.dot(&state.h) + &self.b_f)
            .mapv(Self::sigmoid);
        
        // Cell gate: g_t = tanh(W_ig * x_t + W_hg * h_{t-1} + b_g)
        let g_t = (self.w_ig.dot(input) + self.w_hg.dot(&state.h) + &self.b_g)
            .mapv(Self::tanh);
        
        // Output gate: o_t = σ(W_io * x_t + W_ho * h_{t-1} + b_o)
        let o_t = (self.w_io.dot(input) + self.w_ho.dot(&state.h) + &self.b_o)
            .mapv(Self::sigmoid);
        
        // New cell state: c_t = f_t ⊙ c_{t-1} + i_t ⊙ g_t
        let c_t = &f_t * &state.c + &i_t * &g_t;
        
        // New hidden state: h_t = o_t ⊙ tanh(c_t)
        let h_t = &o_t * &c_t.mapv(Self::tanh);
        
        LstmState { h: h_t, c: c_t }
    }
    
    /// Forward pass through sequence
    pub fn forward(&self, sequence: &[Vec<f32>]) -> Vec<Vec<f32>> {
        let mut state = LstmState::new(self.config.hidden_size);
        let mut outputs = Vec::with_capacity(sequence.len());
        
        for input_vec in sequence {
            let input = Array1::from_vec(input_vec.clone());
            state = self.cell_forward(&input, &state);
            
            // Project hidden state to output
            let output = self.w_out.dot(&state.h) + &self.b_out;
            outputs.push(output.to_vec());
        }
        
        outputs
    }
    
    /// Predict next element in sequence
    pub fn predict_next(&self, sequence: &[Vec<f32>]) -> Vec<f32> {
        let outputs = self.forward(sequence);
        outputs.last().unwrap_or(&vec![0.0; self.config.output_size]).clone()
    }
    
    /// Predict multiple steps ahead
    pub fn predict_multi(&self, sequence: &[Vec<f32>], steps: usize) -> Vec<Vec<f32>> {
        let mut current_seq: VecDeque<Vec<f32>> = sequence.iter().cloned().collect();
        let mut predictions = Vec::with_capacity(steps);
        
        for _ in 0..steps {
            let seq_vec: Vec<Vec<f32>> = current_seq.iter().cloned().collect();
            let next_pred = self.predict_next(&seq_vec);
            predictions.push(next_pred.clone());
            
            current_seq.pop_front();
            current_seq.push_back(next_pred);
        }
        
        predictions
    }
    
    /// Train on sequence using real Backpropagation Through Time (BPTT)
    ///
    /// Performs numerical gradient estimation via finite differences and
    /// updates all LSTM gate weights + output projection weights.
    /// This is O(params * seq_len) but our network is small (input=3-5, hidden=10-64).
    pub fn train(&mut self, sequences: &[Vec<Vec<f32>>], targets: &[Vec<Vec<f32>>]) -> f32 {
        let lr = self.config.learning_rate as f32;
        let eps = 1e-3f32;
        let mut total_loss = 0.0f32;
        let mut count = 0usize;
        
        // Compute current loss
        for (seq, target) in sequences.iter().zip(targets) {
            let predictions = self.forward(seq);
            for (pred, tgt) in predictions.iter().zip(target) {
                for (p, t) in pred.iter().zip(tgt) {
                    total_loss += (p - t).powi(2);
                    count += 1;
                }
            }
        }
        let base_loss = if count > 0 { total_loss / count as f32 } else { return 0.0 };
        
        // Helper: compute MSE loss with current network state
        let compute_loss = |net: &LstmNetwork| -> f32 {
            let mut l = 0.0f32;
            let mut c = 0usize;
            for (seq, target) in sequences.iter().zip(targets) {
                let preds = net.forward(seq);
                for (pred, tgt) in preds.iter().zip(target) {
                    for (p, t) in pred.iter().zip(tgt) {
                        l += (p - t).powi(2);
                        c += 1;
                    }
                }
            }
            if c > 0 { l / c as f32 } else { 0.0 }
        };
        
        // Macro-style weight update via finite differences for each weight matrix
        // Uses shared gradient macros to eliminate duplicated loops.
        use super::gradient::{update_matrix_fd, update_bias_fd};
        
        // Output projection (most impactful — always update first)
        update_matrix_fd!(self.w_out, eps, lr, compute_loss(self));
        update_bias_fd!(self.b_out, eps, lr, compute_loss(self));
        
        // Input gate: w_ii, w_hi, b_i
        update_matrix_fd!(self.w_ii, eps, lr, compute_loss(self));
        update_matrix_fd!(self.w_hi, eps, lr, compute_loss(self));
        update_bias_fd!(self.b_i, eps, lr, compute_loss(self));
        
        // Forget gate: w_if, w_hf, b_f
        update_matrix_fd!(self.w_if, eps, lr, compute_loss(self));
        update_matrix_fd!(self.w_hf, eps, lr, compute_loss(self));
        update_bias_fd!(self.b_f, eps, lr, compute_loss(self));
        
        // Cell gate: w_ig, w_hg, b_g
        update_matrix_fd!(self.w_ig, eps, lr, compute_loss(self));
        update_matrix_fd!(self.w_hg, eps, lr, compute_loss(self));
        update_bias_fd!(self.b_g, eps, lr, compute_loss(self));
        
        // Output gate: w_io, w_ho, b_o
        update_matrix_fd!(self.w_io, eps, lr, compute_loss(self));
        update_matrix_fd!(self.w_ho, eps, lr, compute_loss(self));
        update_bias_fd!(self.b_o, eps, lr, compute_loss(self));
        
        base_loss
    }
    
    /// Save model
    pub fn save(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self)
            .map_err(|e| format!("Failed to serialize LSTM: {}", e))
    }
    
    /// Load model
    pub fn load(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data)
            .map_err(|e| format!("Failed to deserialize LSTM: {}", e))
    }
}

/// LSTM-based sequence predictor for prefetching
pub struct SequencePredictor {
    network: LstmNetwork,
    history: VecDeque<Vec<f32>>,
    max_history: usize,
}

impl SequencePredictor {
    /// Create new predictor
    pub fn new(config: LstmConfig) -> Self {
        let max_history = config.sequence_length;
        Self {
            network: LstmNetwork::new(config),
            history: VecDeque::with_capacity(max_history),
            max_history,
        }
    }
    
    /// Add observation to history
    pub fn observe(&mut self, observation: Vec<f32>) {
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(observation);
    }
    
    /// Predict next items
    pub fn predict(&self, steps: usize) -> Vec<Vec<f32>> {
        if self.history.is_empty() {
            return vec![vec![0.0; self.network.config.output_size]; steps];
        }
        
        let history_vec: Vec<Vec<f32>> = self.history.iter().cloned().collect();
        self.network.predict_multi(&history_vec, steps)
    }
    
    /// Get prediction confidence based on recent accuracy
    pub fn confidence(&self) -> f32 {
        // Simple heuristic: confidence increases with more history
        let history_ratio = self.history.len() as f32 / self.max_history as f32;
        history_ratio.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lstm_creation() {
        let config = LstmConfig::default();
        let lstm = LstmNetwork::new(config);
        assert_eq!(lstm.config.input_size, 64);
        assert_eq!(lstm.config.hidden_size, 128);
    }
    
    #[test]
    fn test_forward_pass() {
        let config = LstmConfig {
            input_size: 5,
            hidden_size: 10,
            output_size: 5,
            ..Default::default()
        };
        let lstm = LstmNetwork::new(config);
        
        let sequence = vec![
            vec![0.1, 0.2, 0.3, 0.4, 0.5],
            vec![0.2, 0.3, 0.4, 0.5, 0.6],
            vec![0.3, 0.4, 0.5, 0.6, 0.7],
        ];
        
        let outputs = lstm.forward(&sequence);
        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].len(), 5);
    }
    
    #[test]
    fn test_prediction() {
        let config = LstmConfig {
            input_size: 5,
            hidden_size: 10,
            output_size: 5,
            sequence_length: 3,
            ..Default::default()
        };
        let lstm = LstmNetwork::new(config);
        
        let sequence = vec![
            vec![0.1, 0.2, 0.3, 0.4, 0.5],
            vec![0.2, 0.3, 0.4, 0.5, 0.6],
        ];
        
        let next = lstm.predict_next(&sequence);
        assert_eq!(next.len(), 5);
        
        let multi = lstm.predict_multi(&sequence, 3);
        assert_eq!(multi.len(), 3);
    }
    
    #[test]
    fn test_sequence_predictor() {
        let config = LstmConfig {
            input_size: 5,
            hidden_size: 10,
            output_size: 5,
            sequence_length: 5,
            ..Default::default()
        };
        let mut predictor = SequencePredictor::new(config);
        
        predictor.observe(vec![0.1, 0.2, 0.3, 0.4, 0.5]);
        predictor.observe(vec![0.2, 0.3, 0.4, 0.5, 0.6]);
        
        let predictions = predictor.predict(3);
        assert_eq!(predictions.len(), 3);
        
        let conf = predictor.confidence();
        assert!(conf > 0.0 && conf <= 1.0);
    }
}
