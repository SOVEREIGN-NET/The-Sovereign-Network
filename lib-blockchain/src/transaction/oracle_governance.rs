//! Oracle Governance Transaction Data
//!
//! Payload types for oracle governance transactions (ORACLE-6).

use serde::{Deserialize, Serialize};

/// Data for OracleAttestation transaction (ORACLE-9).
/// 
/// Validator submits a signed price attestation for the current epoch.
/// The signature is verified during block execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OracleAttestationData {
    /// Epoch being attested to (must match current block epoch).
    pub epoch_id: u64,
    /// SOV/USD price in fixed-point (8 decimal places, 1e8 = $1.00).
    pub sov_usd_price: u128,
    /// Unix timestamp when attestation was created.
    pub timestamp: u64,
    /// Validator's key_id (blake3 of consensus public key).
    pub validator_pubkey: [u8; 32],
    /// Dilithium signature over the attestation payload.
    pub signature: Vec<u8>,
}

/// Data for UpdateOracleCommittee transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OracleCommitteeUpdateData {
    /// New committee members (validator key_ids, blake3 of consensus_key).
    pub new_members: Vec<[u8; 32]>,
    /// Epoch when this update becomes active (must be current_epoch + 1 or later).
    pub activate_at_epoch: u64,
    /// Reason for the update.
    pub reason: String,
}

/// Data for UpdateOracleConfig transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OracleConfigUpdateData {
    /// New epoch duration in seconds.
    pub epoch_duration_secs: u64,
    /// Maximum age of a price source before it's rejected.
    pub max_source_age_secs: u64,
    /// Maximum price deviation in basis points (100 = 1%).
    pub max_deviation_bps: u32,
    /// Maximum allowed staleness (in epochs) for consumers.
    pub max_price_staleness_epochs: u64,
    /// Epoch when this update becomes active.
    pub activate_at_epoch: u64,
    /// Reason for the update.
    pub reason: String,
}

/// Data for CancelOracleUpdate transaction (ORACLE-11).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CancelOracleUpdateData {
    /// Cancel pending committee update.
    pub cancel_committee_update: bool,
    /// Cancel pending config update.
    pub cancel_config_update: bool,
    /// Reason for cancellation.
    pub reason: String,
}

impl CancelOracleUpdateData {
    /// Validate the cancellation data.
    /// At least one of the flags must be true.
    pub fn validate(&self) -> Result<(), String> {
        if !self.cancel_committee_update && !self.cancel_config_update {
            return Err("must specify at least one update to cancel".to_string());
        }
        Ok(())
    }
}

impl OracleCommitteeUpdateData {
    /// Validate the committee update data.
    pub fn validate(&self, current_epoch: u64) -> Result<(), String> {
        // Must have at least one member
        if self.new_members.is_empty() {
            return Err("committee must not be empty".to_string());
        }

        // Check for duplicates
        let mut seen = std::collections::HashSet::new();
        for member in &self.new_members {
            if !seen.insert(member) {
                return Err(format!("duplicate member: {}", hex::encode(member)));
            }
        }

        // Activation epoch must be in the future
        if self.activate_at_epoch <= current_epoch {
            return Err(format!(
                "activate_at_epoch ({}) must be greater than current_epoch ({})",
                self.activate_at_epoch, current_epoch
            ));
        }

        Ok(())
    }
}

impl OracleConfigUpdateData {
    /// Validate the config update data.
    pub fn validate(&self, current_epoch: u64) -> Result<(), String> {
        // Epoch duration must be positive
        if self.epoch_duration_secs == 0 {
            return Err("epoch_duration_secs must be greater than 0".to_string());
        }

        // Max source age must be positive
        if self.max_source_age_secs == 0 {
            return Err("max_source_age_secs must be greater than 0".to_string());
        }

        // Max deviation must be <= 10000 (100%)
        if self.max_deviation_bps > 10_000 {
            return Err(format!(
                "max_deviation_bps ({}) must be <= 10000",
                self.max_deviation_bps
            ));
        }

        // Max price staleness must be positive
        if self.max_price_staleness_epochs == 0 {
            return Err("max_price_staleness_epochs must be greater than 0".to_string());
        }

        // Activation epoch must be in the future
        if self.activate_at_epoch <= current_epoch {
            return Err(format!(
                "activate_at_epoch ({}) must be greater than current_epoch ({})",
                self.activate_at_epoch, current_epoch
            ));
        }

        // Cross-field validation: max_source_age should be less than epoch_duration
        // to prevent oracle always abstaining
        if self.max_source_age_secs >= self.epoch_duration_secs {
            return Err(format!(
                "max_source_age_secs ({}) should be less than epoch_duration_secs ({})",
                self.max_source_age_secs, self.epoch_duration_secs
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_update_validation() {
        let valid = OracleCommitteeUpdateData {
            new_members: vec![[1u8; 32], [2u8; 32]],
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(valid.validate(5).is_ok());

        // Empty committee
        let empty = OracleCommitteeUpdateData {
            new_members: vec![],
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(empty.validate(5).is_err());

        // Duplicate members
        let dup = OracleCommitteeUpdateData {
            new_members: vec![[1u8; 32], [1u8; 32]],
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(dup.validate(5).is_err());

        // Past activation
        let past = OracleCommitteeUpdateData {
            new_members: vec![[1u8; 32]],
            activate_at_epoch: 5,
            reason: "Test".to_string(),
        };
        assert!(past.validate(5).is_err());
    }

    #[test]
    fn config_update_validation() {
        let valid = OracleConfigUpdateData {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 10,
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(valid.validate(5).is_ok());

        // Zero epoch duration
        let zero_epoch = OracleConfigUpdateData {
            epoch_duration_secs: 0,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 10,
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(zero_epoch.validate(5).is_err());

        // Excessive deviation
        let high_dev = OracleConfigUpdateData {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 15_000,
            max_price_staleness_epochs: 10,
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(high_dev.validate(5).is_err());

        // source_age >= epoch_duration
        let bad_age = OracleConfigUpdateData {
            epoch_duration_secs: 300,
            max_source_age_secs: 300,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 10,
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(bad_age.validate(5).is_err());

        // Zero max_price_staleness_epochs
        let zero_staleness = OracleConfigUpdateData {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 0,
            activate_at_epoch: 10,
            reason: "Test".to_string(),
        };
        assert!(zero_staleness.validate(5).is_err());

        // Past activation
        let past = OracleConfigUpdateData {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 10,
            activate_at_epoch: 3,
            reason: "Test".to_string(),
        };
        assert!(past.validate(5).is_err());
    }
}
