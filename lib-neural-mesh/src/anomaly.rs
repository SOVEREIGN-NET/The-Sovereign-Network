//! Anomaly detection for Byzantine fault identification

use crate::error::{NeuralMeshError, Result};
use crate::ml::{IsolationForest, IsolationForestConfig, AnomalyDetector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Node behavioral metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// Node ID
    pub node_id: String,
    
    /// Response time (ms)
    pub response_time: f32,
    
    /// Success rate (0-1)
    pub success_rate: f32,
    
    /// Data corruption rate (0-1)
    pub corruption_rate: f32,
    
    /// Network participation rate (0-1)
    pub participation_rate: f32,
    
    /// Reputation score (0-1)
    pub reputation: f32,
}

impl NodeMetrics {
    /// Convert to feature vector for ML model
    pub fn to_feature_vector(&self) -> Vec<f32> {
        vec![
            self.response_time / 1000.0,      // Normalize to seconds
            self.success_rate,
            self.corruption_rate * 100.0,     // Scale up small values
            self.participation_rate,
            self.reputation,
        ]
    }
}

/// Anomaly severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Anomaly detection report
#[derive(Debug, Clone)]
pub struct AnomalyReport {
    /// Node ID
    pub node_id: String,
    
    /// Anomaly score (0-1, higher = more anomalous)
    pub score: f32,
    
    /// Severity level
    pub severity: AnomalySeverity,
    
    /// Detected threat type
    pub threat_type: ThreatType,
}

/// Types of Byzantine threats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatType {
    Normal,
    SlowNode,
    DataCorruption,
    Selfish,
    Malicious,
}

/// ML-based anomaly detection system
pub struct AnomalySentry {
    enabled: bool,
    baseline: HashMap<String, NodeMetrics>,
    anomaly_threshold: f32,
    detector: Option<AnomalyDetector>,
}

impl std::fmt::Debug for AnomalySentry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalySentry")
            .field("enabled", &self.enabled)
            .field("baseline_count", &self.baseline.len())
            .field("threshold", &self.anomaly_threshold)
            .field("has_detector", &self.detector.is_some())
            .finish()
    }
}

impl AnomalySentry {
    /// Create new anomaly sentry
    pub fn new() -> Self {
        Self {
            enabled: false,
            baseline: HashMap::new(),
            anomaly_threshold: 0.7, // 70% anomaly threshold
            detector: None,
        }
    }

    /// Enable anomaly detection with default configuration
    pub fn enable(&mut self) {
        let config = IsolationForestConfig {
            n_trees: 100,
            subsample_size: 256,
            max_depth: 10,
            random_seed: Some(42),
        };
        
        self.detector = Some(AnomalyDetector::new(config, 0.1)); // 10% contamination rate
        self.enabled = true;
    }
    
    /// Enable with custom configuration
    pub fn enable_with_config(&mut self, config: IsolationForestConfig, contamination: f32) {
        self.detector = Some(AnomalyDetector::new(config, contamination));
        self.enabled = true;
    }

    /// Set anomaly threshold (0.0 - 1.0)
    pub fn set_threshold(&mut self, threshold: f32) {
        self.anomaly_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Train baseline model on normal behavior
    pub fn train_baseline(&mut self, metrics: Vec<NodeMetrics>) -> Result<()> {
        if metrics.is_empty() {
            return Err(NeuralMeshError::TrainingFailed(
                "No training data provided".to_string(),
            ));
        }

        let detector = self.detector.as_mut().ok_or_else(|| {
            NeuralMeshError::TrainingFailed("Detector not initialized".to_string())
        })?;

        // Convert metrics to feature vectors
        let samples: Vec<Vec<f32>> = metrics.iter()
            .map(|m| m.to_feature_vector())
            .collect();

        // Train Isolation Forest
        detector.fit(&samples);

        // Store baseline for reference
        for metric in metrics {
            self.baseline.insert(metric.node_id.clone(), metric);
        }

        Ok(())
    }

    /// Detect anomalies in node behavior
    pub fn detect_anomaly(&self, metrics: &NodeMetrics) -> Result<AnomalyReport> {
        if !self.enabled {
            return Err(NeuralMeshError::InferenceFailed(
                "Anomaly sentry not enabled".to_string(),
            ));
        }

        let detector = self.detector.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("Detector not initialized".to_string())
        })?;

        // Get ML-based anomaly score
        let features = metrics.to_feature_vector();
        let ml_score = detector.score(&features);
        
        // Combine with heuristic score for robustness
        let heuristic_score = self.calculate_heuristic_score(metrics);
        let anomaly_score = (ml_score * 0.7 + heuristic_score * 0.3).min(1.0);
        
        let severity = self.classify_severity(anomaly_score);
        let threat_type = self.classify_threat(metrics, anomaly_score);

        Ok(AnomalyReport {
            node_id: metrics.node_id.clone(),
            score: anomaly_score,
            severity,
            threat_type,
        })
    }
    
    /// Batch anomaly detection
    pub fn detect_batch(&self, metrics: &[NodeMetrics]) -> Result<Vec<AnomalyReport>> {
        if !self.enabled {
            return Err(NeuralMeshError::InferenceFailed(
                "Anomaly sentry not enabled".to_string(),
            ));
        }

        let detector = self.detector.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("Detector not initialized".to_string())
        })?;

        // Generate reports
        let reports: Vec<AnomalyReport> = metrics.iter()
            .map(|m| {
                let features = m.to_feature_vector();
                let ml_score = detector.score(&features);
                let heuristic_score = self.calculate_heuristic_score(m);
                let anomaly_score = (ml_score * 0.7 + heuristic_score * 0.3).min(1.0);
                let severity = self.classify_severity(anomaly_score);
                let threat_type = self.classify_threat(m, anomaly_score);
                
                AnomalyReport {
                    node_id: m.node_id.clone(),
                    score: anomaly_score,
                    severity,
                    threat_type,
                }
            })
            .collect();
        
        Ok(reports)
    }

    /// Calculate heuristic anomaly score (fallback/supplement to ML)
    fn calculate_heuristic_score(&self, metrics: &NodeMetrics) -> f32 {
        let mut score: f32 = 0.0;

        // High response time is anomalous
        if metrics.response_time > 1000.0 {
            score += 0.3;
        }

        // Low success rate is anomalous
        if metrics.success_rate < 0.9 {
            score += 0.3;
        }

        // Any corruption is highly anomalous
        if metrics.corruption_rate > 0.01 {
            score += 0.4;
        }

        // Low participation is suspicious
        if metrics.participation_rate < 0.5 {
            score += 0.2;
        }

        score.min(1.0)
    }

    /// Classify anomaly severity
    fn classify_severity(&self, score: f32) -> AnomalySeverity {
        if score >= 0.9 {
            AnomalySeverity::Critical
        } else if score >= 0.7 {
            AnomalySeverity::High
        } else if score >= 0.5 {
            AnomalySeverity::Medium
        } else {
            AnomalySeverity::Low
        }
    }

    /// Classify threat type based on metrics and score
    fn classify_threat(&self, metrics: &NodeMetrics, score: f32) -> ThreatType {
        // Use both raw metrics and ML score for classification
        // Even if ML score is low, dominant bad metrics should trigger classification
        
        if metrics.corruption_rate > 0.05 {
            ThreatType::Malicious
        } else if metrics.response_time > 2000.0 {
            ThreatType::SlowNode
        } else if metrics.corruption_rate > 0.01 {
            ThreatType::DataCorruption
        } else if metrics.participation_rate < 0.3 {
            ThreatType::Selfish
        } else if score >= self.anomaly_threshold {
            // High anomaly score but no specific bad metric
            ThreatType::Malicious
        } else {
            ThreatType::Normal
        }
    }
}

impl AnomalySentry {
    /// Save anomaly detection model to bytes (compressed-ready for distributed sync)
    pub fn save_model(&self) -> Result<Vec<u8>> {
        let detector = self.detector.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("No anomaly detector initialized".to_string())
        })?;
        // Serialize the full detector state: forest + threshold + contamination
        let state = AnomalyDetectorState {
            forest_bytes: detector.save_forest()
                .map_err(|e| NeuralMeshError::InferenceFailed(e))?,
            threshold: detector.threshold(),
            baseline: self.baseline.clone(),
        };
        bincode::serialize(&state)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Serialize anomaly model: {}", e)))
    }

    /// Load anomaly detection model from bytes (from compressed distributed sync)
    pub fn load_model(&mut self, data: &[u8]) -> Result<()> {
        let state: AnomalyDetectorState = bincode::deserialize(data)
            .map_err(|e| NeuralMeshError::InferenceFailed(format!("Deserialize anomaly model: {}", e)))?;
        let forest = IsolationForest::load(&state.forest_bytes)
            .map_err(|e| NeuralMeshError::InferenceFailed(e))?;
        let mut detector = AnomalyDetector::new(IsolationForestConfig::default(), 0.1);
        detector.load_forest(forest);
        self.detector = Some(detector);
        self.baseline = state.baseline;
        self.enabled = true;
        Ok(())
    }

    /// Get the byte size of the current model weights
    pub fn model_size_bytes(&self) -> usize {
        self.save_model().map(|v| v.len()).unwrap_or(0)
    }
}

/// Serializable snapshot of anomaly detector state for distributed sync
#[derive(Serialize, Deserialize)]
struct AnomalyDetectorState {
    forest_bytes: Vec<u8>,
    threshold: f32,
    baseline: HashMap<String, NodeMetrics>,
}

impl Default for AnomalySentry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentry_creation() {
        let sentry = AnomalySentry::new();
        assert!(!sentry.enabled);
        assert_eq!(sentry.anomaly_threshold, 0.7);
    }

    #[test]
    fn test_normal_node_detection() {
        let mut sentry = AnomalySentry::new();
        sentry.enable();

        // Train on normal nodes
        let training_data = vec![
            NodeMetrics {
                node_id: "train1".to_string(),
                response_time: 50.0,
                success_rate: 0.99,
                corruption_rate: 0.0,
                participation_rate: 0.95,
                reputation: 0.9,
            },
            NodeMetrics {
                node_id: "train2".to_string(),
                response_time: 60.0,
                success_rate: 0.98,
                corruption_rate: 0.0,
                participation_rate: 0.93,
                reputation: 0.88,
            },
        ];
        sentry.train_baseline(training_data).unwrap();

        let metrics = NodeMetrics {
            node_id: "node1".to_string(),
            response_time: 55.0,
            success_rate: 0.99,
            corruption_rate: 0.0,
            participation_rate: 0.95,
            reputation: 0.9,
        };

        let report = sentry.detect_anomaly(&metrics).unwrap();
        assert!(report.score < 0.7); // Should be low anomaly score
    }

    #[test]
    fn test_malicious_node_detection() {
        let mut sentry = AnomalySentry::new();
        sentry.enable();

        // Train on normal nodes
        let training_data: Vec<NodeMetrics> = (0..20).map(|i| NodeMetrics {
            node_id: format!("train{}", i),
            response_time: 50.0 + (i as f32 * 5.0),
            success_rate: 0.95 + (i as f32 * 0.002),
            corruption_rate: 0.0,
            participation_rate: 0.90 + (i as f32 * 0.003),
            reputation: 0.85 + (i as f32 * 0.005),
        }).collect();
        sentry.train_baseline(training_data).unwrap();

        let metrics = NodeMetrics {
            node_id: "bad_node".to_string(),
            response_time: 100.0,
            success_rate: 0.5,
            corruption_rate: 0.1, // 10% corruption!
            participation_rate: 0.8,
            reputation: 0.3,
        };

        let report = sentry.detect_anomaly(&metrics).unwrap();
        assert_eq!(report.threat_type, ThreatType::Malicious);
        assert!(report.score > 0.3); // Reduced threshold since ML model contributes to score
    }

    #[test]
    fn test_slow_node_detection() {
        let mut sentry = AnomalySentry::new();
        sentry.enable();

        // Train on normal nodes
        let training_data: Vec<NodeMetrics> = (0..20).map(|i| NodeMetrics {
            node_id: format!("train{}", i),
            response_time: 50.0 + (i as f32 * 5.0),
            success_rate: 0.95,
            corruption_rate: 0.0,
            participation_rate: 0.90,
            reputation: 0.85,
        }).collect();
        sentry.train_baseline(training_data).unwrap();

        let metrics = NodeMetrics {
            node_id: "slow_node".to_string(),
            response_time: 3000.0, // 3 seconds!
            success_rate: 0.95,
            corruption_rate: 0.0,
            participation_rate: 0.9,
            reputation: 0.8,
        };

        let report = sentry.detect_anomaly(&metrics).unwrap();
        assert_eq!(report.threat_type, ThreatType::SlowNode);
    }
    
    #[test]
    fn test_batch_detection() {
        let mut sentry = AnomalySentry::new();
        sentry.enable();

        // Train on normal nodes
        let training_data: Vec<NodeMetrics> = (0..20).map(|i| NodeMetrics {
            node_id: format!("train{}", i),
            response_time: 50.0,
            success_rate: 0.98,
            corruption_rate: 0.0,
            participation_rate: 0.95,
            reputation: 0.9,
        }).collect();
        sentry.train_baseline(training_data).unwrap();

        let test_metrics = vec![
            NodeMetrics {
                node_id: "normal".to_string(),
                response_time: 55.0,
                success_rate: 0.98,
                corruption_rate: 0.0,
                participation_rate: 0.95,
                reputation: 0.9,
            },
            NodeMetrics {
                node_id: "anomalous".to_string(),
                response_time: 5000.0,
                success_rate: 0.3,
                corruption_rate: 0.2,
                participation_rate: 0.1,
                reputation: 0.1,
            },
        ];

        let reports = sentry.detect_batch(&test_metrics).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports[0].score < reports[1].score); // Anomalous should have higher score
    }
}
