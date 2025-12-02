//! Penalty System for Storage Contracts
//! 
//! Implements automated penalty enforcement for storage contract violations:
//! - Data loss penalties
//! - Availability penalties
//! - Performance penalties
//! - Contract breach penalties

use crate::types::{NodeId, PenaltyType, PenaltyClause};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_crypto::Hash;


/// Storage performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyPerformanceMetrics {
    /// Data integrity score (0.0 to 1.0)
    pub data_integrity: f64,
    /// Uptime percentage (0.0 to 1.0)
    pub uptime: f64,
    /// Average response time in milliseconds
    pub avg_response_time: u64,
    /// Bandwidth utilization ratio
    pub bandwidth_ratio: f64,
    /// Error rate
    pub error_rate: f64,
}

/// Penalty enforcement system
#[derive(Debug)]
pub struct PenaltyEnforcer {
    /// Active penalty clauses by contract
    penalty_clauses: HashMap<Hash, Vec<PenaltyClause>>,
    /// Performance metrics by node
    node_metrics: HashMap<NodeId, PenaltyPerformanceMetrics>,
    /// Penalty history
    penalty_history: Vec<PenaltyEvent>,
}

/// Penalty event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyEvent {
    /// Event ID
    pub id: Hash,
    /// Contract ID
    pub contract_id: Hash,
    /// Node that was penalized
    pub node_id: NodeId,
    /// Type of penalty
    pub penalty_type: PenaltyType,
    /// Penalty amount
    pub penalty_amount: u64,
    /// Timestamp of penalty
    pub timestamp: u64,
    /// Reason for penalty
    pub reason: String,
}

impl PenaltyEnforcer {
    /// Create new penalty enforcer
    pub fn new() -> Self {
        Self {
            penalty_clauses: HashMap::new(),
            node_metrics: HashMap::new(),
            penalty_history: Vec::new(),
        }
    }

    /// Add penalty clauses for a contract
    pub fn add_contract_penalties(&mut self, contract_id: Hash, penalties: Vec<PenaltyClause>) {
        self.penalty_clauses.insert(contract_id, penalties);
    }

    /// Update node performance metrics
    pub fn update_node_metrics(&mut self, node_id: NodeId, metrics: PenaltyPerformanceMetrics) {
        self.node_metrics.insert(node_id, metrics);
    }

    /// Check for penalty violations
    pub fn check_violations(&self, contract_id: &Hash, node_id: &NodeId) -> Result<Vec<PenaltyType>> {
        let penalties = self.penalty_clauses.get(contract_id)
            .ok_or_else(|| anyhow!("Contract not found"))?;

        let metrics = self.node_metrics.get(node_id)
            .ok_or_else(|| anyhow!("Node metrics not found"))?;

        let mut violations = Vec::new();

        for penalty in penalties {
            if self.is_violation(&penalty.penalty_type, metrics)? {
                violations.push(penalty.penalty_type.clone());
            }
        }

        Ok(violations)
    }

    /// Check if metrics constitute a violation
    fn is_violation(&self, penalty_type: &PenaltyType, metrics: &PenaltyPerformanceMetrics) -> Result<bool> {
        match penalty_type {
            PenaltyType::DataLoss => Ok(metrics.data_integrity < 0.99),
            PenaltyType::Unavailability => Ok(metrics.uptime < 0.95),
            PenaltyType::SlowResponse => Ok(metrics.avg_response_time > 5000), // 5 seconds
            PenaltyType::ContractBreach => Ok(metrics.bandwidth_ratio < 0.8),
            PenaltyType::QualityDegradation => {
                // Calculate overall performance from available metrics
                let overall_performance = (metrics.data_integrity + metrics.uptime + 
                                         (1.0 - metrics.error_rate) + metrics.bandwidth_ratio) / 4.0;
                Ok(overall_performance < 0.7)
            },
        }
    }

    /// Enforce penalty for a violation
    pub fn enforce_penalty(
        &mut self,
        contract_id: Hash,
        node_id: NodeId,
        penalty_type: PenaltyType,
        amount: u64,
        reason: String,
    ) -> Result<PenaltyEvent> {
        let event = PenaltyEvent {
            id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
            contract_id,
            node_id,
            penalty_type,
            penalty_amount: amount,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reason,
        };

        self.penalty_history.push(event.clone());

        Ok(event)
    }

    /// Get penalty history for a contract
    pub fn get_contract_penalties(&self, contract_id: &Hash) -> Vec<&PenaltyEvent> {
        self.penalty_history
            .iter()
            .filter(|event| &event.contract_id == contract_id)
            .collect()
    }

    /// Get penalty history for a node
    pub fn get_node_penalties(&self, node_id: &NodeId) -> Vec<&PenaltyEvent> {
        self.penalty_history
            .iter()
            .filter(|event| &event.node_id == node_id)
            .collect()
    }

    /// Calculate total penalties for a node
    pub fn calculate_total_penalties(&self, node_id: &NodeId) -> u64 {
        self.penalty_history
            .iter()
            .filter(|event| &event.node_id == node_id)
            .map(|event| event.penalty_amount)
            .sum()
    }

    /// Get penalty statistics
    pub fn get_penalty_stats(&self) -> PenaltyStats {
        let total_penalties = self.penalty_history.len() as u64;
        let total_amount = self.penalty_history
            .iter()
            .map(|event| event.penalty_amount)
            .sum();

        let mut penalty_counts = HashMap::new();
        for event in &self.penalty_history {
            *penalty_counts.entry(event.penalty_type.clone()).or_insert(0) += 1;
        }

        PenaltyStats {
            total_penalties,
            total_penalty_amount: total_amount,
            penalty_counts,
        }
    }
}

/// Penalty statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyStats {
    /// Total number of penalties issued
    pub total_penalties: u64,
    /// Total penalty amount in ZHTP tokens
    pub total_penalty_amount: u64,
    /// Count of penalties by type
    pub penalty_counts: HashMap<PenaltyType, u64>,
}

impl Default for PenaltyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_penalty_enforcer_creation() {
        let enforcer = PenaltyEnforcer::new();
        assert_eq!(enforcer.penalty_clauses.len(), 0);
        assert_eq!(enforcer.node_metrics.len(), 0);
        assert_eq!(enforcer.penalty_history.len(), 0);
    }

    #[test]
    fn test_violation_detection() {
        let enforcer = PenaltyEnforcer::new();
        
        let metrics = PenaltyPerformanceMetrics {
            data_integrity: 0.98, // Below threshold
            uptime: 0.99,
            avg_response_time: 1000,
            bandwidth_ratio: 0.9,
            error_rate: 0.01,
        };

        assert!(enforcer.is_violation(&PenaltyType::DataLoss, &metrics).unwrap());
        assert!(!enforcer.is_violation(&PenaltyType::Unavailability, &metrics).unwrap());
    }

    #[test]
    fn test_penalty_enforcement() {
        let mut enforcer = PenaltyEnforcer::new();
        let contract_id = Hash::from_bytes(&[1u8; 32]);
        let node_id = NodeId::from_bytes([2u8; 32]);

        let event = enforcer.enforce_penalty(
            contract_id,
            node_id,
            PenaltyType::DataLoss,
            1000,
            "Data integrity below threshold".to_string(),
        ).unwrap();

        assert_eq!(event.penalty_amount, 1000);
        assert_eq!(enforcer.penalty_history.len(), 1);
    }
}
