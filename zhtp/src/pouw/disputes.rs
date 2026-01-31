//! Dispute Investigation API
//!
//! Provides endpoints for investigating and managing PoUW disputes.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Dispute status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeStatus {
    /// Dispute is open and under investigation
    Open,
    /// Dispute is being actively investigated
    UnderInvestigation,
    /// Dispute resolved in favor of the claimant
    ResolvedForClaimant,
    /// Dispute resolved in favor of the node
    ResolvedForNode,
    /// Dispute rejected as invalid
    Rejected,
    /// Dispute closed with no action
    Closed,
}

/// A dispute record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    /// Unique dispute ID
    pub id: String,
    /// Client DID who raised the dispute
    pub client_did: String,
    /// Challenge token ID in question
    pub challenge_id: String,
    /// Receipt ID if applicable
    pub receipt_id: Option<String>,
    /// Type of dispute
    pub dispute_type: DisputeType,
    /// Current status
    pub status: DisputeStatus,
    /// Description of the issue
    pub description: String,
    /// Evidence provided
    pub evidence: Vec<Evidence>,
    /// When the dispute was filed
    pub filed_at: DateTime<Utc>,
    /// When the dispute was last updated
    pub updated_at: DateTime<Utc>,
    /// Resolution details if resolved
    pub resolution: Option<Resolution>,
    /// Investigation notes (internal)
    pub notes: Vec<InvestigationNote>,
}

/// Type of dispute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeType {
    /// Reward not received
    RewardNotReceived,
    /// Incorrect reward amount
    IncorrectRewardAmount,
    /// Receipt wrongly rejected
    ReceiptWronglyRejected,
    /// Challenge not issued
    ChallengeNotIssued,
    /// Double charge/spend
    DoubleSpend,
    /// Other
    Other,
}

/// Evidence attached to a dispute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence
    pub evidence_type: String,
    /// Evidence data (could be hash, signature, etc.)
    pub data: String,
    /// When it was submitted
    pub submitted_at: DateTime<Utc>,
}

/// Resolution of a dispute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    /// Who resolved it
    pub resolved_by: String,
    /// Resolution type
    pub resolution_type: ResolutionType,
    /// Explanation
    pub explanation: String,
    /// Any compensation provided
    pub compensation: Option<Compensation>,
    /// When it was resolved
    pub resolved_at: DateTime<Utc>,
}

/// Resolution type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionType {
    /// Claimant was correct, issue fixed
    ClaimantCorrect,
    /// Node was correct, no issue
    NodeCorrect,
    /// Partial resolution
    PartialResolution,
    /// Cannot determine
    Inconclusive,
}

/// Compensation for resolved disputes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Compensation {
    /// Amount compensated
    pub amount: u64,
    /// Currency/token
    pub currency: String,
    /// Transaction ID if applicable
    pub transaction_id: Option<String>,
}

/// Internal investigation note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationNote {
    /// Who added the note
    pub author: String,
    /// Note content
    pub content: String,
    /// When it was added
    pub added_at: DateTime<Utc>,
}

/// Dispute investigation service
pub struct DisputeService {
    disputes: Arc<RwLock<HashMap<String, Dispute>>>,
    next_id: Arc<RwLock<u64>>,
}

impl DisputeService {
    /// Create a new dispute service
    pub fn new() -> Self {
        Self {
            disputes: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    /// File a new dispute
    pub async fn file_dispute(
        &self,
        client_did: String,
        challenge_id: String,
        receipt_id: Option<String>,
        dispute_type: DisputeType,
        description: String,
    ) -> Dispute {
        let mut next_id = self.next_id.write().await;
        let id = format!("DISPUTE-{:08}", *next_id);
        *next_id += 1;

        let now = Utc::now();
        let dispute = Dispute {
            id: id.clone(),
            client_did,
            challenge_id,
            receipt_id,
            dispute_type,
            status: DisputeStatus::Open,
            description,
            evidence: Vec::new(),
            filed_at: now,
            updated_at: now,
            resolution: None,
            notes: Vec::new(),
        };

        let mut disputes = self.disputes.write().await;
        disputes.insert(id.clone(), dispute.clone());

        dispute
    }

    /// Get a dispute by ID
    pub async fn get_dispute(&self, id: &str) -> Option<Dispute> {
        let disputes = self.disputes.read().await;
        disputes.get(id).cloned()
    }

    /// List disputes with optional filters
    pub async fn list_disputes(
        &self,
        client_did: Option<&str>,
        status: Option<DisputeStatus>,
        limit: usize,
        offset: usize,
    ) -> Vec<Dispute> {
        let disputes = self.disputes.read().await;
        
        disputes
            .values()
            .filter(|d| {
                client_did.map_or(true, |did| d.client_did == did) &&
                status.map_or(true, |s| d.status == s)
            })
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Add evidence to a dispute
    pub async fn add_evidence(
        &self,
        dispute_id: &str,
        evidence_type: String,
        data: String,
    ) -> Result<(), DisputeError> {
        let mut disputes = self.disputes.write().await;
        
        let dispute = disputes
            .get_mut(dispute_id)
            .ok_or(DisputeError::NotFound)?;

        if dispute.status != DisputeStatus::Open && dispute.status != DisputeStatus::UnderInvestigation {
            return Err(DisputeError::DisputeClosed);
        }

        dispute.evidence.push(Evidence {
            evidence_type,
            data,
            submitted_at: Utc::now(),
        });
        dispute.updated_at = Utc::now();

        Ok(())
    }

    /// Update dispute status
    pub async fn update_status(
        &self,
        dispute_id: &str,
        new_status: DisputeStatus,
        note: Option<String>,
        author: &str,
    ) -> Result<(), DisputeError> {
        let mut disputes = self.disputes.write().await;
        
        let dispute = disputes
            .get_mut(dispute_id)
            .ok_or(DisputeError::NotFound)?;

        dispute.status = new_status;
        dispute.updated_at = Utc::now();

        if let Some(note_content) = note {
            dispute.notes.push(InvestigationNote {
                author: author.to_string(),
                content: note_content,
                added_at: Utc::now(),
            });
        }

        Ok(())
    }

    /// Resolve a dispute
    pub async fn resolve_dispute(
        &self,
        dispute_id: &str,
        resolved_by: String,
        resolution_type: ResolutionType,
        explanation: String,
        compensation: Option<Compensation>,
    ) -> Result<(), DisputeError> {
        let mut disputes = self.disputes.write().await;
        
        let dispute = disputes
            .get_mut(dispute_id)
            .ok_or(DisputeError::NotFound)?;

        let status = match resolution_type {
            ResolutionType::ClaimantCorrect => DisputeStatus::ResolvedForClaimant,
            ResolutionType::NodeCorrect => DisputeStatus::ResolvedForNode,
            ResolutionType::PartialResolution => DisputeStatus::ResolvedForClaimant,
            ResolutionType::Inconclusive => DisputeStatus::Closed,
        };

        dispute.status = status;
        dispute.resolution = Some(Resolution {
            resolved_by,
            resolution_type,
            explanation,
            compensation,
            resolved_at: Utc::now(),
        });
        dispute.updated_at = Utc::now();

        Ok(())
    }

    /// Get dispute statistics
    pub async fn get_statistics(&self) -> DisputeStatistics {
        let disputes = self.disputes.read().await;
        
        let mut stats = DisputeStatistics::default();
        stats.total = disputes.len() as u64;

        for dispute in disputes.values() {
            match dispute.status {
                DisputeStatus::Open => stats.open += 1,
                DisputeStatus::UnderInvestigation => stats.under_investigation += 1,
                DisputeStatus::ResolvedForClaimant => stats.resolved_for_claimant += 1,
                DisputeStatus::ResolvedForNode => stats.resolved_for_node += 1,
                DisputeStatus::Rejected => stats.rejected += 1,
                DisputeStatus::Closed => stats.closed += 1,
            }

            match dispute.dispute_type {
                DisputeType::RewardNotReceived => stats.by_type.reward_not_received += 1,
                DisputeType::IncorrectRewardAmount => stats.by_type.incorrect_reward += 1,
                DisputeType::ReceiptWronglyRejected => stats.by_type.receipt_rejected += 1,
                DisputeType::ChallengeNotIssued => stats.by_type.challenge_not_issued += 1,
                DisputeType::DoubleSpend => stats.by_type.double_spend += 1,
                DisputeType::Other => stats.by_type.other += 1,
            }
        }

        stats
    }
}

impl Default for DisputeService {
    fn default() -> Self {
        Self::new()
    }
}

/// Dispute service errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeError {
    /// Dispute not found
    NotFound,
    /// Dispute is already closed
    DisputeClosed,
    /// Invalid operation
    InvalidOperation,
}

impl std::fmt::Display for DisputeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Dispute not found"),
            Self::DisputeClosed => write!(f, "Dispute is already closed"),
            Self::InvalidOperation => write!(f, "Invalid operation"),
        }
    }
}

impl std::error::Error for DisputeError {}

/// Dispute statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisputeStatistics {
    pub total: u64,
    pub open: u64,
    pub under_investigation: u64,
    pub resolved_for_claimant: u64,
    pub resolved_for_node: u64,
    pub rejected: u64,
    pub closed: u64,
    pub by_type: DisputeTypeStats,
}

/// Statistics by dispute type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisputeTypeStats {
    pub reward_not_received: u64,
    pub incorrect_reward: u64,
    pub receipt_rejected: u64,
    pub challenge_not_issued: u64,
    pub double_spend: u64,
    pub other: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_and_retrieve_dispute() {
        let service = DisputeService::new();
        
        let dispute = service.file_dispute(
            "did:sov:test123".to_string(),
            "challenge-001".to_string(),
            Some("receipt-001".to_string()),
            DisputeType::RewardNotReceived,
            "Did not receive reward for valid receipt".to_string(),
        ).await;

        assert!(dispute.id.starts_with("DISPUTE-"));
        assert_eq!(dispute.status, DisputeStatus::Open);

        let retrieved = service.get_dispute(&dispute.id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().client_did, "did:sov:test123");
    }

    #[tokio::test]
    async fn test_add_evidence() {
        let service = DisputeService::new();
        
        let dispute = service.file_dispute(
            "did:sov:test".to_string(),
            "challenge-002".to_string(),
            None,
            DisputeType::ReceiptWronglyRejected,
            "Receipt was valid".to_string(),
        ).await;

        let result = service.add_evidence(
            &dispute.id,
            "signature".to_string(),
            "0xabc123...".to_string(),
        ).await;
        
        assert!(result.is_ok());

        let updated = service.get_dispute(&dispute.id).await.unwrap();
        assert_eq!(updated.evidence.len(), 1);
    }

    #[tokio::test]
    async fn test_resolve_dispute() {
        let service = DisputeService::new();
        
        let dispute = service.file_dispute(
            "did:sov:client".to_string(),
            "challenge-003".to_string(),
            None,
            DisputeType::IncorrectRewardAmount,
            "Reward amount is wrong".to_string(),
        ).await;

        let result = service.resolve_dispute(
            &dispute.id,
            "admin".to_string(),
            ResolutionType::ClaimantCorrect,
            "Verified: reward calculation had a bug".to_string(),
            Some(Compensation {
                amount: 100,
                currency: "SOV".to_string(),
                transaction_id: Some("tx-123".to_string()),
            }),
        ).await;

        assert!(result.is_ok());

        let resolved = service.get_dispute(&dispute.id).await.unwrap();
        assert_eq!(resolved.status, DisputeStatus::ResolvedForClaimant);
        assert!(resolved.resolution.is_some());
    }

    #[tokio::test]
    async fn test_statistics() {
        let service = DisputeService::new();
        
        // File multiple disputes
        service.file_dispute("did:1".into(), "c1".into(), None, DisputeType::RewardNotReceived, "test".into()).await;
        service.file_dispute("did:2".into(), "c2".into(), None, DisputeType::RewardNotReceived, "test".into()).await;
        service.file_dispute("did:3".into(), "c3".into(), None, DisputeType::DoubleSpend, "test".into()).await;

        let stats = service.get_statistics().await;
        assert_eq!(stats.total, 3);
        assert_eq!(stats.open, 3);
        assert_eq!(stats.by_type.reward_not_received, 2);
        assert_eq!(stats.by_type.double_spend, 1);
    }
}
