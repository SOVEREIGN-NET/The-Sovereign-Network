//! Reputation and Trust System
//! 
//! Implements a comprehensive reputation system for storage providers including:
//! - Multi-dimensional reputation scoring
//! - Historical performance tracking
//! - Peer-to-peer reputation consensus
//! - Reputation-based incentives and penalties
//! - Trust metrics and verification

use crate::types::QualityViolation;
// Note: No contracts imports needed - reputation is independent
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::Utc;

/// Reputation manager for tracking provider trustworthiness
#[derive(Debug)]
pub struct ReputationManager {
    /// Provider reputation scores
    provider_scores: HashMap<String, ReputationScore>,
    /// Historical performance data
    performance_history: HashMap<String, Vec<PerformanceRecord>>,
    /// Peer attestations
    peer_attestations: HashMap<String, Vec<PeerAttestation>>,
    /// Reputation configuration
    config: ReputationConfig,
}

/// Reputation system (alias for ReputationManager)
pub type ReputationSystem = ReputationManager;

/// Comprehensive reputation score for a provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Provider identifier
    pub provider_id: String,
    /// Overall reputation score (0.0-1.0)
    pub overall_score: f64,
    /// Individual metric scores
    pub metric_scores: ReputationMetrics,
    /// Confidence level in the score (0.0-1.0)
    pub confidence: f64,
    /// Number of completed contracts
    pub contracts_completed: u32,
    /// Total value of contracts handled
    pub total_value_handled: u64,
    /// Last update timestamp
    pub last_updated: u64,
    /// Reputation trend (improving/declining)
    pub trend: ReputationTrend,
}

/// Individual reputation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationMetrics {
    /// Reliability score (uptime, availability)
    pub reliability: f64,
    /// Performance score (latency, throughput)
    pub performance: f64,
    /// Security score (data protection, encryption)
    pub security: f64,
    /// Honesty score (accurate reporting, transparency)
    pub honesty: f64,
    /// Responsiveness score (communication, support)
    pub responsiveness: f64,
    /// Longevity score (time in network)
    pub longevity: f64,
}

/// Reputation trend indicator
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReputationTrend {
    Improving,
    Stable,
    Declining,
    NewProvider,
}

/// Historical performance record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRecord {
    /// Record timestamp
    pub timestamp: u64,
    /// Contract ID this record relates to
    pub contract_id: String,
    /// Performance metrics
    pub metrics: PerformanceSnapshot,
    /// SLA compliance
    pub sla_compliance: SlaCompliance,
    /// Client satisfaction rating
    pub client_rating: Option<f64>,
    /// Any incidents or issues
    pub incidents: Vec<IncidentRecord>,
}

/// Performance snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    /// Uptime percentage
    pub uptime: f64,
    /// Average response time (ms)
    pub avg_response_time: u64,
    /// Data integrity success rate
    pub data_integrity: f64,
    /// Throughput (bytes/second)
    pub throughput: u64,
    /// Error rate
    pub error_rate: f64,
}

/// SLA compliance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaCompliance {
    /// Overall compliance percentage
    pub overall_compliance: f64,
    /// Specific SLA metric compliance
    pub metric_compliance: HashMap<String, f64>,
    /// Violations count
    pub violations_count: u32,
    /// Penalty amount incurred
    pub penalty_amount: u64,
}

/// Incident record for reputation impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    /// Incident timestamp
    pub timestamp: u64,
    /// Incident type
    pub incident_type: IncidentType,
    /// Severity level
    pub severity: IncidentSeverity,
    /// Description
    pub description: String,
    /// Resolution time (seconds)
    pub resolution_time: Option<u64>,
    /// Impact on reputation
    pub reputation_impact: f64,
}

/// Types of incidents that affect reputation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IncidentType {
    DataLoss,
    ServiceOutage,
    SecurityBreach,
    PerformanceDegradation,
    CommunicationFailure,
    ContractViolation,
    TechnicalIssue,
}

/// Incident severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Peer attestation for reputation validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAttestation {
    /// Attesting peer ID
    pub attester_id: String,
    /// Subject provider ID
    pub subject_id: String,
    /// Attestation type
    pub attestation_type: AttestationType,
    /// Attestation value/rating
    pub value: f64,
    /// Supporting evidence
    pub evidence: Option<String>,
    /// Attestation timestamp
    pub timestamp: u64,
    /// Attester's reputation weight
    pub attester_weight: f64,
}

/// Types of peer attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationType {
    ReliabilityWitness,
    PerformanceWitness,
    SecurityAssessment,
    CommunicationRating,
    TechnicalCompetence,
    GeneralTrust,
}

/// Reputation configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Weight for different metrics in overall score
    pub metric_weights: ReputationWeights,
    /// Decay rate for old performance data
    pub decay_rate: f64,
    /// Minimum data points for confident score
    pub min_data_points: u32,
    /// Time window for trend calculation (seconds)
    pub trend_window: u64,
    /// Penalty multipliers for incidents
    pub incident_penalties: HashMap<IncidentType, f64>,
}

/// Weights for different reputation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationWeights {
    pub reliability: f64,
    pub performance: f64,
    pub security: f64,
    pub honesty: f64,
    pub responsiveness: f64,
    pub longevity: f64,
}

/// Trust level categories based on reputation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted,    // 0.0-0.3
    LowTrust,     // 0.3-0.5
    ModerateTrust, // 0.5-0.7
    HighTrust,    // 0.7-0.9
    ExpertTrust,  // 0.9-1.0
}

/// Reputation-based provider ranking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRanking {
    /// Provider ID
    pub provider_id: String,
    /// Current rank
    pub rank: u32,
    /// Reputation score
    pub score: f64,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Recommended contract limits
    pub contract_limits: ContractLimits,
}

/// Recommended limits based on reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractLimits {
    /// Maximum contract value
    pub max_contract_value: u64,
    /// Maximum storage capacity
    pub max_storage_capacity: u64,
    /// Maximum contract duration
    pub max_contract_duration: u64,
    /// Required escrow percentage
    pub required_escrow_percentage: f64,
}

impl ReputationManager {
    /// Create a new reputation manager
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            provider_scores: HashMap::new(),
            performance_history: HashMap::new(),
            peer_attestations: HashMap::new(),
            config,
        }
    }

    /// Initialize reputation for a new provider
    pub fn initialize_provider(&mut self, provider_id: String) -> Result<()> {
        let initial_score = ReputationScore {
            provider_id: provider_id.clone(),
            overall_score: 0.5, // Neutral starting score
            metric_scores: ReputationMetrics {
                reliability: 0.5,
                performance: 0.5,
                security: 0.5,
                honesty: 0.5,
                responsiveness: 0.5,
                longevity: 0.0, // New provider
            },
            confidence: 0.1, // Low confidence initially
            contracts_completed: 0,
            total_value_handled: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            trend: ReputationTrend::NewProvider,
        };

        self.provider_scores.insert(provider_id.clone(), initial_score);
        self.performance_history.insert(provider_id, Vec::new());
        Ok(())
    }

    /// Update reputation based on contract performance
    pub fn update_performance(
        &mut self,
        provider_id: &str,
        contract_id: String,
        performance: PerformanceSnapshot,
        sla_compliance: SlaCompliance,
        client_rating: Option<f64>,
    ) -> Result<()> {
        let record = PerformanceRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            contract_id,
            metrics: performance.clone(),
            sla_compliance: sla_compliance.clone(),
            client_rating,
            incidents: Vec::new(),
        };

        // Add to performance history
        self.performance_history
            .entry(provider_id.to_string())
            .or_insert_with(Vec::new)
            .push(record);

        // Recalculate reputation score
        self.recalculate_score(provider_id)?;

        Ok(())
    }

    /// Record an incident affecting reputation
    pub fn record_incident(
        &mut self,
        provider_id: &str,
        incident: IncidentRecord,
    ) -> Result<()> {
        // Add incident to latest performance record
        if let Some(history) = self.performance_history.get_mut(provider_id) {
            if let Some(latest_record) = history.last_mut() {
                latest_record.incidents.push(incident.clone());
            }
        }

        // Apply immediate reputation impact
        if let Some(score) = self.provider_scores.get_mut(provider_id) {
            let penalty = self.config.incident_penalties
                .get(&incident.incident_type)
                .copied()
                .unwrap_or(0.1);
            
            // Apply penalty based on severity
            let severity_multiplier = match incident.severity {
                IncidentSeverity::Low => 1.0,
                IncidentSeverity::Medium => 2.0,
                IncidentSeverity::High => 4.0,
                IncidentSeverity::Critical => 8.0,
            };

            let total_penalty = penalty * severity_multiplier * incident.reputation_impact;
            score.overall_score = (score.overall_score - total_penalty).max(0.0);
            score.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }

        Ok(())
    }

    /// Add peer attestation
    pub fn add_peer_attestation(&mut self, attestation: PeerAttestation) -> Result<()> {
        self.peer_attestations
            .entry(attestation.subject_id.clone())
            .or_insert_with(Vec::new)
            .push(attestation.clone());

        // Recalculate score considering new attestation
        self.recalculate_score(&attestation.subject_id)?;

        Ok(())
    }

    /// Recalculate reputation score for a provider
    fn recalculate_score(&mut self, provider_id: &str) -> Result<()> {
        let history = self.performance_history.get(provider_id)
            .ok_or_else(|| anyhow!("No performance history found"))?;

        if history.is_empty() {
            return Ok(()); // Nothing to calculate
        }

        // Calculate metric scores based on recent performance
        let recent_records: Vec<_> = history.iter()
            .rev()
            .take(10) // Last 10 records
            .collect();

        let reliability = self.calculate_reliability_score(&recent_records);
        let performance = self.calculate_performance_score(&recent_records);
        let security = self.calculate_security_score(&recent_records);
        let honesty = self.calculate_honesty_score(&recent_records);
        let responsiveness = self.calculate_responsiveness_score(&recent_records);
        let longevity = self.calculate_longevity_score(provider_id);
        
        // Calculate confidence based on data points
        let confidence = self.calculate_confidence(history.len() as u32);

        // Create temporary score for calculation
        let temp_score = ReputationScore {
            provider_id: provider_id.to_string(),
            metric_scores: ReputationMetrics {
                reliability,
                performance,
                security,
                honesty,
                responsiveness,
                longevity,
            },
            confidence,
            overall_score: 0.0, // Will be calculated
            trend: ReputationTrend::Stable,
            last_updated: Utc::now().timestamp() as u64,
            contracts_completed: 0, // Temp value
            total_value_handled: 0, // Temp value
        };
        
        // Calculate weighted overall score using the method
        let overall_score = self.calculate_overall_score(&temp_score) + (longevity * self.config.metric_weights.longevity);

        // Apply peer attestation influence
        let peer_influence = self.calculate_peer_influence(provider_id);
        let adjusted_score = (overall_score + peer_influence) / 2.0;

        // Determine trend
        let trend = self.calculate_trend(provider_id);

        // Update the score
        if let Some(score) = self.provider_scores.get_mut(provider_id) {
            score.overall_score = adjusted_score.min(1.0).max(0.0);
            score.metric_scores = ReputationMetrics {
                reliability,
                performance,
                security,
                honesty,
                responsiveness,
                longevity,
            };
            score.confidence = confidence;
            score.contracts_completed = history.len() as u32;
            score.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            score.trend = trend;
        }

        Ok(())
    }

    /// Calculate reliability score from performance records
    fn calculate_reliability_score(&self, records: &[&PerformanceRecord]) -> f64 {
        if records.is_empty() {
            return 0.5;
        }

        let avg_uptime: f64 = records.iter()
            .map(|r| r.metrics.uptime)
            .sum::<f64>() / records.len() as f64;

        let avg_integrity: f64 = records.iter()
            .map(|r| r.metrics.data_integrity)
            .sum::<f64>() / records.len() as f64;

        (avg_uptime + avg_integrity) / 2.0
    }

    /// Calculate performance score from performance records
    fn calculate_performance_score(&self, records: &[&PerformanceRecord]) -> f64 {
        if records.is_empty() {
            return 0.5;
        }

        // Lower response time is better
        let avg_response_time: f64 = records.iter()
            .map(|r| r.metrics.avg_response_time as f64)
            .sum::<f64>() / records.len() as f64;

        let response_score = (1000.0 - avg_response_time.min(1000.0)) / 1000.0;

        // Lower error rate is better
        let avg_error_rate: f64 = records.iter()
            .map(|r| r.metrics.error_rate)
            .sum::<f64>() / records.len() as f64;

        let error_score = 1.0 - avg_error_rate.min(1.0);

        (response_score + error_score) / 2.0
    }

    /// Calculate security score (simplified)
    fn calculate_security_score(&self, records: &[&PerformanceRecord]) -> f64 {
        // For now, base on incident history
        let security_incidents: usize = records.iter()
            .map(|r| r.incidents.iter()
                .filter(|i| matches!(i.incident_type, IncidentType::SecurityBreach))
                .count())
            .sum();

        if security_incidents == 0 {
            0.9 // High security score with no incidents
        } else {
            (0.9 - (security_incidents as f64 * 0.2)).max(0.1)
        }
    }

    /// Calculate honesty score based on SLA compliance
    fn calculate_honesty_score(&self, records: &[&PerformanceRecord]) -> f64 {
        if records.is_empty() {
            return 0.5;
        }

        let avg_compliance: f64 = records.iter()
            .map(|r| r.sla_compliance.overall_compliance)
            .sum::<f64>() / records.len() as f64;

        avg_compliance
    }

    /// Calculate responsiveness score
    fn calculate_responsiveness_score(&self, records: &[&PerformanceRecord]) -> f64 {
        if records.is_empty() {
            return 0.5;
        }

        // Base on client ratings if available
        let ratings: Vec<f64> = records.iter()
            .filter_map(|r| r.client_rating)
            .collect();

        if ratings.is_empty() {
            0.5 // Neutral if no ratings
        } else {
            ratings.iter().sum::<f64>() / ratings.len() as f64
        }
    }

    /// Calculate longevity score
    fn calculate_longevity_score(&self, provider_id: &str) -> f64 {
        if let Some(score) = self.provider_scores.get(provider_id) {
            let age_days = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - score.last_updated) / 86400;
            
            // Score increases with time, capped at 1.0
            (age_days as f64 / 365.0).min(1.0)
        } else {
            0.0
        }
    }

    /// Calculate peer influence on reputation
    fn calculate_peer_influence(&self, provider_id: &str) -> f64 {
        if let Some(attestations) = self.peer_attestations.get(provider_id) {
            if attestations.is_empty() {
                return 0.5; // Neutral influence
            }

            let weighted_sum: f64 = attestations.iter()
                .map(|a| a.value * a.attester_weight)
                .sum();
            
            let weight_sum: f64 = attestations.iter()
                .map(|a| a.attester_weight)
                .sum();

            if weight_sum > 0.0 {
                weighted_sum / weight_sum
            } else {
                0.5
            }
        } else {
            0.5
        }
    }

    /// Calculate confidence level
    fn calculate_confidence(&self, data_points: u32) -> f64 {
        if data_points >= self.config.min_data_points {
            1.0
        } else {
            (data_points as f64) / (self.config.min_data_points as f64)
        }
    }

    /// Calculate reputation trend
    fn calculate_trend(&self, provider_id: &str) -> ReputationTrend {
        if let Some(history) = self.performance_history.get(provider_id) {
            if history.len() < 3 {
                return ReputationTrend::NewProvider;
            }

            let recent_avg = history.iter().rev().take(3)
                .map(|r| r.sla_compliance.overall_compliance)
                .sum::<f64>() / 3.0;

            let older_avg = history.iter().rev().skip(3).take(3)
                .map(|r| r.sla_compliance.overall_compliance)
                .sum::<f64>() / 3.0;

            if recent_avg > older_avg + 0.05 {
                ReputationTrend::Improving
            } else if recent_avg < older_avg - 0.05 {
                ReputationTrend::Declining
            } else {
                ReputationTrend::Stable
            }
        } else {
            ReputationTrend::NewProvider
        }
    }

    /// Get reputation score for a provider
    pub fn get_reputation(&self, provider_id: &str) -> Option<&ReputationScore> {
        self.provider_scores.get(provider_id)
    }

    /// Get trust level for a provider
    pub fn get_trust_level(&self, provider_id: &str) -> TrustLevel {
        if let Some(score) = self.provider_scores.get(provider_id) {
            match score.overall_score {
                s if s >= 0.9 => TrustLevel::ExpertTrust,
                s if s >= 0.7 => TrustLevel::HighTrust,
                s if s >= 0.5 => TrustLevel::ModerateTrust,
                s if s >= 0.3 => TrustLevel::LowTrust,
                _ => TrustLevel::Untrusted,
            }
        } else {
            TrustLevel::Untrusted
        }
    }

    /// Get provider rankings
    pub fn get_provider_rankings(&self) -> Vec<ProviderRanking> {
        let mut rankings: Vec<_> = self.provider_scores.iter()
            .map(|(id, score)| {
                let trust_level = self.get_trust_level(id);
                let contract_limits = self.calculate_contract_limits(score);
                
                ProviderRanking {
                    provider_id: id.clone(),
                    rank: 0, // Will be set after sorting
                    score: score.overall_score,
                    trust_level,
                    contract_limits,
                }
            })
            .collect();

        // Sort by score descending
        rankings.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Set ranks
        for (index, ranking) in rankings.iter_mut().enumerate() {
            ranking.rank = (index + 1) as u32;
        }

        rankings
    }

    /// Calculate recommended contract limits
    fn calculate_contract_limits(&self, score: &ReputationScore) -> ContractLimits {
        let base_value = match score.overall_score {
            s if s >= 0.9 => 10_000_000, // 10M tokens for expert providers
            s if s >= 0.7 => 5_000_000,  // 5M tokens for high trust
            s if s >= 0.5 => 1_000_000,  // 1M tokens for moderate trust
            s if s >= 0.3 => 100_000,    // 100K tokens for low trust
            _ => 10_000,                 // 10K tokens for untrusted
        };

        ContractLimits {
            max_contract_value: base_value,
            max_storage_capacity: base_value * 1024, // GB
            max_contract_duration: if score.overall_score >= 0.7 { 31536000 } else { 2592000 }, // 1 year vs 1 month
            required_escrow_percentage: if score.overall_score >= 0.8 { 0.1 } else { 0.3 }, // 10% vs 30%
        }
    }

    /// Record a violation for a provider
    pub async fn record_violation(&mut self, node_id: lib_crypto::Hash, violation: QualityViolation) -> anyhow::Result<()> {
        let node_id_str = hex::encode(node_id.as_bytes());
        
        // Initialize provider if not exists
        if !self.provider_scores.contains_key(&node_id_str) {
            self.initialize_provider(node_id_str.clone())?;
        }
        
        // Calculate trend before mutable borrow
        let trend = self.calculate_trend(&node_id_str);
        
        if let Some(score) = self.provider_scores.get_mut(&node_id_str) {
            // Apply violation penalty based on severity
            let penalty = match violation.severity {
                s if s <= 0.25 => 0.05,    // Low severity
                s if s <= 0.50 => 0.15,    // Medium severity
                s if s <= 0.75 => 0.30,    // High severity
                _ => 0.50,                 // Critical severity
            };
            
            // Reduce reputation based on violation type
            match violation.violation_type.as_str() {
                "data_loss" => score.metric_scores.reliability = (score.metric_scores.reliability - penalty).max(0.0),
                "downtime" => score.metric_scores.reliability = (score.metric_scores.reliability - penalty).max(0.0),
                "slow_response" => score.metric_scores.performance = (score.metric_scores.performance - penalty).max(0.0),
                "breach" => score.metric_scores.security = (score.metric_scores.security - penalty).max(0.0),
                _ => score.overall_score = (score.overall_score - penalty * 0.5).max(0.0),
            }
            
            // Recalculate overall score using the method (calculate directly to avoid borrowing issues)
            let metrics = &score.metric_scores;
            let weighted_score = (metrics.reliability * 0.3) +
                               (metrics.performance * 0.25) +
                               (metrics.security * 0.2) +
                               (metrics.honesty * 0.15) +
                               (metrics.responsiveness * 0.1);
            let overall_score = weighted_score * score.confidence;
            score.overall_score = overall_score;
            
            // Update trend
            score.trend = trend;
            score.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
        
        Ok(())
    }
    
    /// Calculate overall score from individual metrics
    fn calculate_overall_score(&self, score: &ReputationScore) -> f64 {
        let metrics = &score.metric_scores;
        // Weighted average of different metrics
        let weighted_score = (metrics.reliability * 0.3) +
                           (metrics.performance * 0.25) +
                           (metrics.security * 0.2) +
                           (metrics.honesty * 0.15) +
                           (metrics.responsiveness * 0.1);
        
        // Apply confidence factor
        weighted_score * score.confidence
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        let mut incident_penalties = HashMap::new();
        incident_penalties.insert(IncidentType::DataLoss, 0.3);
        incident_penalties.insert(IncidentType::SecurityBreach, 0.4);
        incident_penalties.insert(IncidentType::ServiceOutage, 0.2);
        incident_penalties.insert(IncidentType::PerformanceDegradation, 0.1);
        incident_penalties.insert(IncidentType::CommunicationFailure, 0.05);
        incident_penalties.insert(IncidentType::ContractViolation, 0.25);
        incident_penalties.insert(IncidentType::TechnicalIssue, 0.1);

        Self {
            metric_weights: ReputationWeights {
                reliability: 0.3,
                performance: 0.25,
                security: 0.2,
                honesty: 0.15,
                responsiveness: 0.05,
                longevity: 0.05,
            },
            decay_rate: 0.01,
            min_data_points: 5,
            trend_window: 86400 * 30, // 30 days
            incident_penalties,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reputation_manager_creation() {
        let config = ReputationConfig::default();
        let manager = ReputationManager::new(config);
        assert!(manager.provider_scores.is_empty());
    }

    #[test]
    fn test_provider_initialization() {
        let config = ReputationConfig::default();
        let mut manager = ReputationManager::new(config);
        
        manager.initialize_provider("provider1".to_string()).unwrap();
        
        let score = manager.get_reputation("provider1").unwrap();
        assert_eq!(score.overall_score, 0.5);
        assert_eq!(score.trend, ReputationTrend::NewProvider);
    }

    #[test]
    fn test_trust_level_calculation() {
        let config = ReputationConfig::default();
        let mut manager = ReputationManager::new(config);
        
        manager.initialize_provider("provider1".to_string()).unwrap();
        
        let trust_level = manager.get_trust_level("provider1");
        assert_eq!(trust_level, TrustLevel::ModerateTrust);
    }
}
