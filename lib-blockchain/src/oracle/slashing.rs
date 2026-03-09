//! Oracle Slashing Module
//!
//! Implements §9 of Oracle Spec v1: penalties for misbehavior.
//! - Double-sign: Two different prices for same epoch
//! - Wrong-epoch: Attestation for non-current epoch
//! - Deviation-band: Attestation price exceeds max deviation from median

use serde::{Deserialize, Serialize};

/// Reason for oracle slashing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleSlashReason {
    /// Two different prices attested for the same epoch.
    ConflictingAttestation,
    /// Attestation stamped for an epoch other than current.
    WrongEpoch,
    /// Attestation price exceeds maximum allowed deviation from median.
    /// Spec §9: Validators attesting prices outside the configured deviation
    /// band are slashed to prevent manipulation attempts.
    DeviationBand,
}

impl std::fmt::Display for OracleSlashReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OracleSlashReason::ConflictingAttestation => write!(f, "conflicting_attestation"),
            OracleSlashReason::WrongEpoch => write!(f, "wrong_epoch"),
            OracleSlashReason::DeviationBand => write!(f, "deviation_band"),
        }
    }
}

/// Record of an oracle slash event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleSlashEvent {
    /// Validator key_id that was slashed (blake3 of consensus_key).
    pub validator_key_id: [u8; 32],
    /// Reason for the slash.
    pub reason: OracleSlashReason,
    /// Epoch where the violation occurred.
    pub epoch_id: u64,
    /// SOV atomic units removed from stake.
    pub slash_amount: u64,
    /// Block height where slash was recorded.
    pub slashed_at_height: u64,
    /// Committee removal timing.
    /// If Some(epoch), validator will be removed from committee at the start of the specified epoch.
    /// If None, removal happens immediately (legacy behavior for V0 protocol).
    pub committee_removal_at_epoch: Option<u64>,
}

/// Committee removal queue entry for epoch-safe removal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitteeRemovalEntry {
    /// Validator key_id to remove.
    pub validator_key_id: [u8; 32],
    /// Epoch at which removal should occur.
    pub remove_at_epoch: u64,
    /// Reason for removal (links to slash event).
    pub reason: OracleSlashReason,
}

/// Slashing configuration for oracle protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleSlashingConfig {
    /// Slash fraction in basis points (100 = 1% of stake).
    pub slash_fraction_bps: u16,
}

impl Default for OracleSlashingConfig {
    fn default() -> Self {
        Self {
            slash_fraction_bps: 100, // 1% default
        }
    }
}

impl OracleSlashingConfig {
    /// Create with custom slash fraction.
    pub fn with_slash_fraction(bps: u16) -> Self {
        Self {
            slash_fraction_bps: bps,
        }
    }

    /// Calculate slash amount from stake.
    pub fn calculate_slash(&self, stake: u64) -> u64 {
        (stake as u128)
            .saturating_mul(self.slash_fraction_bps as u128)
            .saturating_div(10_000) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_reason_display() {
        assert_eq!(
            OracleSlashReason::ConflictingAttestation.to_string(),
            "conflicting_attestation"
        );
        assert_eq!(OracleSlashReason::WrongEpoch.to_string(), "wrong_epoch");
        assert_eq!(OracleSlashReason::DeviationBand.to_string(), "deviation_band");
    }

    #[test]
    fn slashing_config_default() {
        let config = OracleSlashingConfig::default();
        assert_eq!(config.slash_fraction_bps, 100);
    }

    #[test]
    fn calculate_slash_amounts() {
        let config = OracleSlashingConfig::default(); // 1%

        // 1% of 10,000 = 100
        assert_eq!(config.calculate_slash(10_000), 100);

        // 1% of 1,000,000 = 10,000
        assert_eq!(config.calculate_slash(1_000_000), 10_000);

        // Custom 5% config
        let config_5pct = OracleSlashingConfig::with_slash_fraction(500);
        assert_eq!(config_5pct.calculate_slash(1_000_000), 50_000);
    }

    #[test]
    fn slash_event_serialization() {
        let event = OracleSlashEvent {
            validator_key_id: [1u8; 32],
            reason: OracleSlashReason::ConflictingAttestation,
            epoch_id: 100,
            slash_amount: 5000,
            slashed_at_height: 1000,
            committee_removal_at_epoch: Some(101), // Next epoch removal
        };

        let serialized = bincode::serialize(&event).unwrap();
        let deserialized: OracleSlashEvent = bincode::deserialize(&serialized).unwrap();

        assert_eq!(event, deserialized);
    }

    #[test]
    fn committee_removal_entry_serialization() {
        let entry = CommitteeRemovalEntry {
            validator_key_id: [1u8; 32],
            remove_at_epoch: 100,
            reason: OracleSlashReason::DeviationBand,
        };

        let serialized = bincode::serialize(&entry).unwrap();
        let deserialized: CommitteeRemovalEntry = bincode::deserialize(&serialized).unwrap();

        assert_eq!(entry, deserialized);
    }
}
