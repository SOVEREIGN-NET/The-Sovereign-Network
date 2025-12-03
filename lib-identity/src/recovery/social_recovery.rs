//! Social Recovery System
//!
//! Implements social recovery where guardians can help recover a lost identity.
//! Security-focused implementation with rate limiting, expiration, and signature verification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use lib_crypto::{PostQuantumSignature, verify_signature};
use crate::guardian::{Guardian, GuardianConfig};

/// Recovery request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Recovery initiated, waiting for guardian approvals
    Pending,

    /// Threshold met, ready to complete
    Approved,

    /// Recovery was rejected by guardians
    Rejected,

    /// Recovery completed successfully
    Completed,

    /// Recovery expired due to timeout
    Expired,

    /// Recovery was cancelled
    Cancelled,
}

/// A guardian's approval for a recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianApproval {
    /// Guardian's DID
    pub guardian_did: String,

    /// Guardian's signature over recovery_id
    pub signature: PostQuantumSignature,

    /// When the approval was given
    pub approved_at: DateTime<Utc>,
}

/// A social recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// Unique recovery request ID
    pub recovery_id: String,

    /// DID of the identity being recovered
    pub identity_did: String,

    /// Status of the recovery
    pub status: RecoveryStatus,

    /// Required number of approvals
    pub threshold: usize,

    /// Guardian approvals received
    pub approvals: HashMap<String, GuardianApproval>,

    /// When the recovery was initiated
    pub initiated_at: DateTime<Utc>,

    /// When the recovery expires (24-48 hours from initiation)
    pub expires_at: DateTime<Utc>,

    /// Device/context that initiated the recovery
    pub requester_device: String,

    /// IP address that initiated the recovery (for rate limiting)
    pub requester_ip: String,
}

impl RecoveryRequest {
    /// Create a new recovery request
    pub fn new(
        identity_did: String,
        threshold: usize,
        requester_device: String,
        requester_ip: String,
        expiration_hours: i64,
    ) -> Self {
        // Generate unique recovery ID using CSPRNG
        use rand::RngCore;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let recovery_id = hex::encode(id_bytes);

        let now = Utc::now();
        let expires_at = now + Duration::hours(expiration_hours);

        Self {
            recovery_id,
            identity_did,
            status: RecoveryStatus::Pending,
            threshold,
            approvals: HashMap::new(),
            initiated_at: now,
            expires_at,
            requester_device,
            requester_ip,
        }
    }

    /// Check if the recovery request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Add a guardian approval with signature verification
    pub fn add_approval(
        &mut self,
        guardian: &Guardian,
        signature: PostQuantumSignature,
    ) -> Result<(), String> {
        // Security: Check expiration
        if self.is_expired() {
            self.status = RecoveryStatus::Expired;
            return Err("Recovery request has expired".to_string());
        }

        // Security: Check status
        if self.status != RecoveryStatus::Pending {
            return Err(format!("Recovery request is not pending (status: {:?})", self.status));
        }

        // Security: Check for duplicate approval
        if self.approvals.contains_key(&guardian.guardian_did) {
            return Err("Guardian has already approved this recovery".to_string());
        }

        // Security: Verify signature over recovery_id
        let message = self.recovery_id.as_bytes();
        let public_key_bytes = guardian.public_key.as_bytes();

        let is_valid = verify_signature(message, &signature.signature, &public_key_bytes)
            .map_err(|e| format!("Signature verification failed: {}", e))?;

        if !is_valid {
            return Err("Invalid guardian signature".to_string());
        }

        // Add approval
        let approval = GuardianApproval {
            guardian_did: guardian.guardian_did.clone(),
            signature,
            approved_at: Utc::now(),
        };

        self.approvals.insert(guardian.guardian_did.clone(), approval);

        // Check if threshold is met
        if self.approvals.len() >= self.threshold {
            self.status = RecoveryStatus::Approved;
        }

        Ok(())
    }

    /// Reject approval from a guardian
    pub fn reject_approval(&mut self, _guardian_did: &str) -> Result<(), String> {
        // Security: Check expiration
        if self.is_expired() {
            self.status = RecoveryStatus::Expired;
            return Err("Recovery request has expired".to_string());
        }

        // Security: Check status
        if self.status != RecoveryStatus::Pending {
            return Err(format!("Recovery request is not pending (status: {:?})", self.status));
        }

        // Mark as rejected
        self.status = RecoveryStatus::Rejected;

        Ok(())
    }

    /// Complete the recovery (only if threshold met)
    pub fn complete(&mut self) -> Result<(), String> {
        // Security: Check expiration
        if self.is_expired() {
            self.status = RecoveryStatus::Expired;
            return Err("Recovery request has expired".to_string());
        }

        // Security: Check status
        if self.status != RecoveryStatus::Approved {
            return Err(format!("Recovery is not approved (status: {:?})", self.status));
        }

        // Security: Double-check threshold
        if self.approvals.len() < self.threshold {
            return Err(format!(
                "Insufficient approvals: {} of {} required",
                self.approvals.len(),
                self.threshold
            ));
        }

        self.status = RecoveryStatus::Completed;
        Ok(())
    }

    /// Get approval count
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }
}

/// Manager for social recovery requests
#[derive(Debug, Default)]
pub struct SocialRecoveryManager {
    /// Active recovery requests
    requests: HashMap<String, RecoveryRequest>,

    /// Rate limiting: Track recovery attempts per IP
    recovery_attempts: HashMap<String, Vec<DateTime<Utc>>>,
}

impl SocialRecoveryManager {
    /// Create a new social recovery manager
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            recovery_attempts: HashMap::new(),
        }
    }

    /// Check rate limit for recovery initiation (Security: Prevent abuse)
    pub fn check_rate_limit(&mut self, ip: &str, max_attempts: usize, window_hours: i64) -> Result<(), String> {
        let now = Utc::now();
        let window_start = now - Duration::hours(window_hours);

        // Get or create attempts list for this IP
        let attempts = self.recovery_attempts.entry(ip.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&timestamp| timestamp > window_start);

        // Check if limit exceeded
        if attempts.len() >= max_attempts {
            return Err(format!(
                "Rate limit exceeded: {} recovery attempts in {} hours",
                max_attempts, window_hours
            ));
        }

        // Record this attempt
        attempts.push(now);

        Ok(())
    }

    /// Initiate a new recovery request
    pub fn initiate_recovery(
        &mut self,
        identity_did: String,
        guardian_config: &GuardianConfig,
        requester_device: String,
        requester_ip: String,
    ) -> Result<String, String> {
        // Security: Check rate limit (3 attempts per 24 hours per IP)
        self.check_rate_limit(&requester_ip, 3, 24)?;

        // Security: Validate guardian configuration
        guardian_config.validate_threshold()?;

        // Check for existing pending recovery for this identity
        let existing_pending = self.requests.values().any(|r| {
            r.identity_did == identity_did
                && r.status == RecoveryStatus::Pending
                && !r.is_expired()
        });

        if existing_pending {
            return Err("A recovery request is already pending for this identity".to_string());
        }

        // Create recovery request (48 hour expiration)
        let request = RecoveryRequest::new(
            identity_did,
            guardian_config.threshold,
            requester_device,
            requester_ip,
            48,
        );

        let recovery_id = request.recovery_id.clone();
        self.requests.insert(recovery_id.clone(), request);

        Ok(recovery_id)
    }

    /// Get a recovery request
    pub fn get_request(&self, recovery_id: &str) -> Option<&RecoveryRequest> {
        self.requests.get(recovery_id)
    }

    /// Get a mutable recovery request
    pub fn get_request_mut(&mut self, recovery_id: &str) -> Option<&mut RecoveryRequest> {
        self.requests.get_mut(recovery_id)
    }

    /// Get pending recovery requests for a guardian
    pub fn get_pending_for_guardian(&self, guardian_did: &str) -> Vec<&RecoveryRequest> {
        self.requests
            .values()
            .filter(|r| {
                r.status == RecoveryStatus::Pending
                    && !r.is_expired()
                    && !r.approvals.contains_key(guardian_did)
            })
            .collect()
    }

    /// Get all pending recovery requests (for guardian endpoint filtering)
    pub fn get_all_pending_requests(&self) -> Vec<&RecoveryRequest> {
        self.requests
            .values()
            .filter(|r| r.status == RecoveryStatus::Pending && !r.is_expired())
            .collect()
    }

    /// Clean up expired requests
    pub fn cleanup_expired(&mut self) {
        self.requests.retain(|_, request| {
            if request.is_expired() && request.status == RecoveryStatus::Pending {
                false // Remove expired pending requests
            } else {
                true // Keep all other requests
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::{KeyPair, PublicKey};

    #[test]
    fn test_recovery_request_creation() {
        let request = RecoveryRequest::new(
            "did:zhtp:alice".to_string(),
            2,
            "new-phone".to_string(),
            "192.168.1.1".to_string(),
            48,
        );

        assert_eq!(request.status, RecoveryStatus::Pending);
        assert_eq!(request.threshold, 2);
        assert_eq!(request.approvals.len(), 0);
        assert!(!request.is_expired());
    }

    #[test]
    fn test_rate_limiting() {
        let mut manager = SocialRecoveryManager::new();

        // First 3 attempts should succeed
        assert!(manager.check_rate_limit("192.168.1.1", 3, 24).is_ok());
        assert!(manager.check_rate_limit("192.168.1.1", 3, 24).is_ok());
        assert!(manager.check_rate_limit("192.168.1.1", 3, 24).is_ok());

        // 4th attempt should fail
        assert!(manager.check_rate_limit("192.168.1.1", 3, 24).is_err());

        // Different IP should succeed
        assert!(manager.check_rate_limit("192.168.1.2", 3, 24).is_ok());
    }

    #[test]
    fn test_initiate_recovery() {
        let mut manager = SocialRecoveryManager::new();
        let mut config = GuardianConfig::new(2, 5);

        let pubkey1 = PublicKey::new(vec![1, 2, 3, 4]);
        let pubkey2 = PublicKey::new(vec![5, 6, 7, 8]);

        config.add_guardian("did:zhtp:alice".to_string(), pubkey1, "Alice".to_string()).unwrap();
        config.add_guardian("did:zhtp:bob".to_string(), pubkey2, "Bob".to_string()).unwrap();

        let result = manager.initiate_recovery(
            "did:zhtp:carol".to_string(),
            &config,
            "new-phone".to_string(),
            "192.168.1.1".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_duplicate_pending_recovery() {
        let mut manager = SocialRecoveryManager::new();
        let mut config = GuardianConfig::new(2, 5);

        let pubkey1 = PublicKey::new(vec![1, 2, 3, 4]);
        let pubkey2 = PublicKey::new(vec![5, 6, 7, 8]);

        config.add_guardian("did:zhtp:alice".to_string(), pubkey1, "Alice".to_string()).unwrap();
        config.add_guardian("did:zhtp:bob".to_string(), pubkey2, "Bob".to_string()).unwrap();

        // First recovery should succeed
        let result1 = manager.initiate_recovery(
            "did:zhtp:carol".to_string(),
            &config,
            "new-phone".to_string(),
            "192.168.1.1".to_string(),
        );
        assert!(result1.is_ok());

        // Second recovery for same identity should fail
        let result2 = manager.initiate_recovery(
            "did:zhtp:carol".to_string(),
            &config,
            "new-phone".to_string(),
            "192.168.1.2".to_string(),
        );
        assert!(result2.is_err());
    }
}
