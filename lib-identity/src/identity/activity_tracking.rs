//! Activity tracking implementation from the original identity.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::IdentityId;

/// Activity tracking for identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityTracker {
    /// Identity activity records
    pub activities: HashMap<IdentityId, ActivityRecord>,
    /// Global activity statistics
    pub global_stats: GlobalActivityStats,
}

/// Activity record for a single identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityRecord {
    /// Identity ID
    pub identity_id: IdentityId,
    /// Last activity timestamp
    pub last_active: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Total activity count
    pub activity_count: u64,
    /// Activity types performed
    pub activity_types: Vec<ActivityType>,
    /// Activity sessions
    pub sessions: Vec<ActivitySession>,
}

/// Types of activities that can be tracked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ActivityType {
    /// Identity creation
    IdentityCreation,
    /// Credential addition
    CredentialAdded,
    /// Wallet creation
    WalletCreated,
    /// Transaction signing
    TransactionSigned,
    /// Recovery operation
    RecoveryPerformed,
    /// Verification request
    VerificationRequested,
    /// Attestation added
    AttestationAdded,
    /// Reputation update
    ReputationUpdated,
    /// Custom activity
    Custom(String),
}

/// Activity session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySession {
    /// Session ID
    pub session_id: String,
    /// Session start time
    pub start_time: u64,
    /// Session end time (None if active)
    pub end_time: Option<u64>,
    /// Activities in this session
    pub activities: Vec<ActivityType>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

/// Global activity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalActivityStats {
    /// Total identities created
    pub total_identities: u64,
    /// Total activities performed
    pub total_activities: u64,
    /// Most active identity
    pub most_active_identity: Option<IdentityId>,
    /// Activity distribution by type
    pub activity_distribution: HashMap<ActivityType, u64>,
    /// Statistics last updated
    pub last_updated: u64,
}

impl ActivityTracker {
    /// Create a new activity tracker
    pub fn new() -> Self {
        Self {
            activities: HashMap::new(),
            global_stats: GlobalActivityStats {
                total_identities: 0,
                total_activities: 0,
                most_active_identity: None,
                activity_distribution: HashMap::new(),
                last_updated: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        }
    }

    /// Record an activity for an identity
    pub fn record_activity(&mut self, identity_id: &IdentityId, activity_type: ActivityType) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update or create activity record
        let record = self.activities.entry(identity_id.clone()).or_insert_with(|| {
            ActivityRecord {
                identity_id: identity_id.clone(),
                last_active: current_time,
                created_at: current_time,
                activity_count: 0,
                activity_types: Vec::new(),
                sessions: Vec::new(),
            }
        });

        // Update record
        record.last_active = current_time;
        record.activity_count += 1;
        record.activity_types.push(activity_type.clone());

        // Update global statistics
        self.global_stats.total_activities += 1;
        *self.global_stats.activity_distribution.entry(activity_type).or_insert(0) += 1;
        
        // Update most active identity
        if self.global_stats.most_active_identity.is_none() || 
           record.activity_count > self.activities.get(&self.global_stats.most_active_identity.as_ref().unwrap()).unwrap().activity_count {
            self.global_stats.most_active_identity = Some(identity_id.clone());
        }

        self.global_stats.last_updated = current_time;
    }

    /// Get activity record for an identity
    pub fn get_activity_record(&self, identity_id: &IdentityId) -> Option<&ActivityRecord> {
        self.activities.get(identity_id)
    }

    /// Get global activity statistics
    pub fn get_global_stats(&self) -> &GlobalActivityStats {
        &self.global_stats
    }

    /// Start a new activity session
    pub fn start_session(&mut self, identity_id: &IdentityId) -> String {
        let session_id = format!("session_{}", self.generate_session_id());
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session = ActivitySession {
            session_id: session_id.clone(),
            start_time: current_time,
            end_time: None,
            activities: Vec::new(),
            metadata: HashMap::new(),
        };

        if let Some(record) = self.activities.get_mut(identity_id) {
            record.sessions.push(session);
        }

        session_id
    }

    /// End an activity session
    pub fn end_session(&mut self, identity_id: &IdentityId, session_id: &str) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(record) = self.activities.get_mut(identity_id) {
            if let Some(session) = record.sessions.iter_mut().find(|s| s.session_id == session_id) {
                session.end_time = Some(current_time);
            }
        }
    }

    /// Add activity to current session
    pub fn add_activity_to_session(&mut self, identity_id: &IdentityId, session_id: &str, activity: ActivityType) {
        if let Some(record) = self.activities.get_mut(identity_id) {
            if let Some(session) = record.sessions.iter_mut().find(|s| s.session_id == session_id) {
                session.activities.push(activity);
            }
        }
    }

    /// Generate a unique session ID
    fn generate_session_id(&self) -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

impl Default for ActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_activity_tracking() {
        let mut tracker = ActivityTracker::new();
        let identity_id = Hash([1u8; 32]);
        
        tracker.record_activity(&identity_id, ActivityType::IdentityCreation);
        tracker.record_activity(&identity_id, ActivityType::WalletCreated);
        
        let record = tracker.get_activity_record(&identity_id).unwrap();
        assert_eq!(record.activity_count, 2);
        assert_eq!(record.activity_types.len(), 2);
        
        let stats = tracker.get_global_stats();
        assert_eq!(stats.total_activities, 2);
    }

    #[test]
    fn test_session_tracking() {
        let mut tracker = ActivityTracker::new();
        let identity_id = Hash([1u8; 32]);
        
        // Create initial record
        tracker.record_activity(&identity_id, ActivityType::IdentityCreation);
        
        let session_id = tracker.start_session(&identity_id);
        tracker.add_activity_to_session(&identity_id, &session_id, ActivityType::WalletCreated);
        tracker.end_session(&identity_id, &session_id);
        
        let record = tracker.get_activity_record(&identity_id).unwrap();
        assert_eq!(record.sessions.len(), 1);
        assert!(record.sessions[0].end_time.is_some());
    }
}
