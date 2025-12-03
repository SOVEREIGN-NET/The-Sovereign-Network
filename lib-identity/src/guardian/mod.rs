//! Guardian Management System
//!
//! Manages trusted guardians for social recovery of identities.
//! Guardians can help recover an account if the user loses their recovery phrase.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use lib_crypto::PublicKey;

/// A trusted guardian who can help recover an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    /// Unique guardian identifier
    pub guardian_id: String,

    /// Guardian's DID
    pub guardian_did: String,

    /// Guardian's public key for signature verification
    pub public_key: PublicKey,

    /// Human-readable name for the guardian
    pub name: String,

    /// When the guardian was added
    pub added_at: DateTime<Utc>,

    /// Status of the guardian
    pub status: GuardianStatus,
}

/// Guardian status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuardianStatus {
    /// Guardian is active and can participate in recovery
    Active,

    /// Guardian has been removed
    Removed,

    /// Guardian is pending acceptance (optional future feature)
    Pending,
}

/// Guardian configuration for an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    /// List of guardians
    pub guardians: HashMap<String, Guardian>,

    /// Number of guardian approvals required for recovery (e.g., 2 of 3)
    pub threshold: usize,

    /// Maximum number of guardians allowed
    pub max_guardians: usize,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            guardians: HashMap::new(),
            threshold: 2,
            max_guardians: 5,
        }
    }
}

impl GuardianConfig {
    /// Create a new guardian configuration
    pub fn new(threshold: usize, max_guardians: usize) -> Self {
        Self {
            guardians: HashMap::new(),
            threshold,
            max_guardians,
        }
    }

    /// Add a guardian
    pub fn add_guardian(
        &mut self,
        guardian_did: String,
        public_key: PublicKey,
        name: String,
    ) -> Result<String, String> {
        // Security: Validate max guardians limit
        if self.guardians.len() >= self.max_guardians {
            return Err(format!("Maximum number of guardians ({}) reached", self.max_guardians));
        }

        // Security: Check for duplicate DID
        if self.guardians.values().any(|g| g.guardian_did == guardian_did) {
            return Err("Guardian with this DID already exists".to_string());
        }

        // Generate unique guardian ID using CSPRNG
        use rand::RngCore;
        let mut id_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let guardian_id = hex::encode(id_bytes);

        let guardian = Guardian {
            guardian_id: guardian_id.clone(),
            guardian_did,
            public_key,
            name,
            added_at: Utc::now(),
            status: GuardianStatus::Active,
        };

        self.guardians.insert(guardian_id.clone(), guardian);

        Ok(guardian_id)
    }

    /// Remove a guardian
    pub fn remove_guardian(&mut self, guardian_id: &str) -> Result<(), String> {
        if let Some(guardian) = self.guardians.get_mut(guardian_id) {
            guardian.status = GuardianStatus::Removed;
            Ok(())
        } else {
            Err("Guardian not found".to_string())
        }
    }

    /// Get active guardians
    pub fn get_active_guardians(&self) -> Vec<&Guardian> {
        self.guardians
            .values()
            .filter(|g| g.status == GuardianStatus::Active)
            .collect()
    }

    /// Get a guardian by ID
    pub fn get_guardian(&self, guardian_id: &str) -> Option<&Guardian> {
        self.guardians.get(guardian_id)
    }

    /// Validate threshold is achievable with active guardians
    pub fn validate_threshold(&self) -> Result<(), String> {
        let active_count = self.get_active_guardians().len();

        if active_count < self.threshold {
            return Err(format!(
                "Not enough active guardians ({}) to meet threshold ({})",
                active_count, self.threshold
            ));
        }

        Ok(())
    }

    /// Update threshold (with validation)
    pub fn set_threshold(&mut self, new_threshold: usize) -> Result<(), String> {
        let active_count = self.get_active_guardians().len();

        if new_threshold > active_count {
            return Err(format!(
                "Threshold ({}) cannot exceed active guardians ({})",
                new_threshold, active_count
            ));
        }

        if new_threshold == 0 {
            return Err("Threshold must be at least 1".to_string());
        }

        self.threshold = new_threshold;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_guardian() {
        let mut config = GuardianConfig::default();
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);

        let result = config.add_guardian(
            "did:zhtp:alice".to_string(),
            pubkey,
            "Alice".to_string(),
        );

        assert!(result.is_ok());
        assert_eq!(config.guardians.len(), 1);
    }

    #[test]
    fn test_max_guardians_limit() {
        let mut config = GuardianConfig::new(2, 2);
        let pubkey1 = PublicKey::new(vec![1, 2, 3, 4]);
        let pubkey2 = PublicKey::new(vec![5, 6, 7, 8]);
        let pubkey3 = PublicKey::new(vec![9, 10, 11, 12]);

        assert!(config.add_guardian("did:zhtp:alice".to_string(), pubkey1, "Alice".to_string()).is_ok());
        assert!(config.add_guardian("did:zhtp:bob".to_string(), pubkey2, "Bob".to_string()).is_ok());
        assert!(config.add_guardian("did:zhtp:carol".to_string(), pubkey3, "Carol".to_string()).is_err());
    }

    #[test]
    fn test_duplicate_guardian_did() {
        let mut config = GuardianConfig::default();
        let pubkey1 = PublicKey::new(vec![1, 2, 3, 4]);
        let pubkey2 = PublicKey::new(vec![5, 6, 7, 8]);

        assert!(config.add_guardian("did:zhtp:alice".to_string(), pubkey1, "Alice".to_string()).is_ok());
        assert!(config.add_guardian("did:zhtp:alice".to_string(), pubkey2, "Alice2".to_string()).is_err());
    }

    #[test]
    fn test_remove_guardian() {
        let mut config = GuardianConfig::default();
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);

        let guardian_id = config.add_guardian(
            "did:zhtp:alice".to_string(),
            pubkey,
            "Alice".to_string(),
        ).unwrap();

        assert!(config.remove_guardian(&guardian_id).is_ok());
        assert_eq!(config.get_active_guardians().len(), 0);
    }

    #[test]
    fn test_threshold_validation() {
        let mut config = GuardianConfig::new(2, 5);
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);

        // No guardians, threshold not met
        assert!(config.validate_threshold().is_err());

        // Add 2 guardians, threshold met
        config.add_guardian("did:zhtp:alice".to_string(), pubkey.clone(), "Alice".to_string()).unwrap();
        config.add_guardian("did:zhtp:bob".to_string(), pubkey, "Bob".to_string()).unwrap();
        assert!(config.validate_threshold().is_ok());
    }

    #[test]
    fn test_set_threshold() {
        let mut config = GuardianConfig::new(2, 5);
        let pubkey = PublicKey::new(vec![1, 2, 3, 4]);

        config.add_guardian("did:zhtp:alice".to_string(), pubkey.clone(), "Alice".to_string()).unwrap();
        config.add_guardian("did:zhtp:bob".to_string(), pubkey.clone(), "Bob".to_string()).unwrap();
        config.add_guardian("did:zhtp:carol".to_string(), pubkey, "Carol".to_string()).unwrap();

        // Valid threshold
        assert!(config.set_threshold(2).is_ok());
        assert_eq!(config.threshold, 2);

        // Threshold too high
        assert!(config.set_threshold(5).is_err());

        // Threshold zero
        assert!(config.set_threshold(0).is_err());
    }
}
