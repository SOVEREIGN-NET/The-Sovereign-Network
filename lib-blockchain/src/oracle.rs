//! Oracle Protocol v1 consensus state types.
//!
//! This module contains deterministic state models used by consensus to manage:
//! - oracle committee membership
//! - oracle configuration
//! - per-epoch finalized prices

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::collections::BTreeMap;

/// Fixed-point scale for SOV/USD oracle prices (8 decimals).
pub const ORACLE_PRICE_SCALE: u128 = 100_000_000;
/// Domain separator for oracle attestation signatures.
pub const ORACLE_ATTESTATION_DOMAIN: &str = "SOVN_ORACLE_V1";

/// Canonical payload covered by oracle attestation signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OraclePriceAttestationPayload {
    pub epoch_id: u64,
    pub sov_usd_price: u128,
    pub timestamp: u64,
    pub validator_pubkey: [u8; 32],
}

/// Canonical oracle attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OraclePriceAttestation {
    pub epoch_id: u64,
    pub sov_usd_price: u128,
    pub timestamp: u64,
    pub validator_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleAttestationValidationError {
    EncodeError(String),
    WrongEpoch { expected: u64, got: u64 },
    NonCommitteeSigner([u8; 32]),
    DuplicateSigner([u8; 32]),
    MissingSignerPublicKey([u8; 32]),
    InvalidSignature,
}

impl OraclePriceAttestation {
    pub fn payload(&self) -> OraclePriceAttestationPayload {
        OraclePriceAttestationPayload {
            epoch_id: self.epoch_id,
            sov_usd_price: self.sov_usd_price,
            timestamp: self.timestamp,
            validator_pubkey: self.validator_pubkey,
        }
    }

    /// Deterministic binary payload encoding.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, OracleAttestationValidationError> {
        bincode::serialize(&self.payload())
            .map_err(|e| OracleAttestationValidationError::EncodeError(e.to_string()))
    }

    /// Blake3 hash of `domain || payload`.
    pub fn signing_digest_with_domain(
        &self,
        domain: &[u8],
    ) -> Result<[u8; 32], OracleAttestationValidationError> {
        let payload_bytes = self.canonical_payload_bytes()?;
        let mut preimage = Vec::with_capacity(domain.len() + payload_bytes.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&payload_bytes);
        Ok(lib_crypto::hash_blake3(&preimage))
    }

    /// Blake3 hash of `SOVN_ORACLE_V1 || payload`.
    pub fn signing_digest(&self) -> Result<[u8; 32], OracleAttestationValidationError> {
        self.signing_digest_with_domain(ORACLE_ATTESTATION_DOMAIN.as_bytes())
    }

    /// Verify signature against a resolved validator signing key.
    pub fn verify_signature_with_domain(
        &self,
        resolved_signing_pubkey: &[u8],
        domain: &[u8],
    ) -> Result<(), OracleAttestationValidationError> {
        let digest = self.signing_digest_with_domain(domain)?;
        let ok = lib_crypto::post_quantum::dilithium::dilithium_verify(
            &digest,
            &self.signature,
            resolved_signing_pubkey,
        )
        .map_err(|_| OracleAttestationValidationError::InvalidSignature)?;
        if ok {
            Ok(())
        } else {
            Err(OracleAttestationValidationError::InvalidSignature)
        }
    }

    pub fn verify_signature(
        &self,
        resolved_signing_pubkey: &[u8],
    ) -> Result<(), OracleAttestationValidationError> {
        self.verify_signature_with_domain(
            resolved_signing_pubkey,
            ORACLE_ATTESTATION_DOMAIN.as_bytes(),
        )
    }
}

/// Governance-controlled oracle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleConfig {
    /// Epoch duration in seconds.
    pub epoch_duration_secs: u64,
    /// Maximum accepted source age in seconds.
    pub max_source_age_secs: u64,
    /// Maximum allowed deviation from median in basis points.
    pub max_deviation_bps: u32,
    /// Maximum allowed staleness (in epochs) for consumers.
    pub max_price_staleness_epochs: u64,
    /// Fixed-point price scale. Must remain 1e8 for v1.
    pub price_scale: u128,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 2,
            price_scale: ORACLE_PRICE_SCALE,
        }
    }
}

/// Pending governance committee update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCommitteeUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// New committee members (validator public keys).
    pub members: Vec<[u8; 32]>,
}

/// Pending governance config update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingConfigUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// Config values that become active at `activate_at_epoch`.
    pub config: OracleConfig,
}

/// Active oracle committee state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleCommitteeState {
    /// Active committee members (sorted, deduplicated).
    pub members: Vec<[u8; 32]>,
    /// Pending update, if scheduled.
    pub pending_update: Option<PendingCommitteeUpdate>,
}

impl OracleCommitteeState {
    /// Threshold formula: floor(2N/3)+1.
    pub fn threshold(&self) -> u16 {
        let n = self.members.len() as u16;
        if n == 0 { 0 } else { (2 * n) / 3 + 1 }
    }
}

/// Canonical finalized price for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedOraclePrice {
    pub epoch_id: u64,
    #[serde(alias = "price")]
    pub sov_usd_price: u128,
}

/// Oracle aggregation/finalization status for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleEpochState {
    /// First price to hit threshold for this epoch.
    pub winning_price: Option<u128>,
    /// Whether this epoch is finalized.
    pub finalized: bool,
}

/// Root oracle consensus state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleState {
    #[serde(default)]
    pub config: OracleConfig,
    #[serde(default)]
    pub committee: OracleCommitteeState,
    /// Pending config update, if scheduled.
    #[serde(default)]
    pub pending_config_update: Option<PendingConfigUpdate>,
    /// One immutable finalized price per epoch.
    #[serde(default)]
    pub finalized_prices: BTreeMap<u64, FinalizedOraclePrice>,
    /// Per-epoch transient/finalization status.
    #[serde(default)]
    pub epoch_state: BTreeMap<u64, OracleEpochState>,
}

impl OracleState {
    /// Deterministic epoch id derived from canonical block timestamp.
    pub fn epoch_id(&self, block_timestamp: u64) -> u64 {
        let duration = self.config.epoch_duration_secs.max(1);
        block_timestamp / duration
    }

    /// Queue a committee update for activation at the next epoch boundary.
    pub fn schedule_committee_update(
        &mut self,
        members: Vec<[u8; 32]>,
        current_epoch: u64,
    ) -> Result<(), String> {
        if members.is_empty() {
            return Err("oracle committee must not be empty".to_string());
        }

        let uniq_len = members.iter().copied().collect::<BTreeSet<_>>().len();
        if uniq_len != members.len() {
            return Err("oracle committee must not contain duplicate members".to_string());
        }

        self.committee.pending_update = Some(PendingCommitteeUpdate {
            activate_at_epoch: current_epoch.saturating_add(1),
            members,
        });
        Ok(())
    }

    /// Queue an oracle config update for activation at the next epoch boundary.
    pub fn schedule_config_update(
        &mut self,
        config: OracleConfig,
        current_epoch: u64,
    ) -> Result<(), String> {
        if config.epoch_duration_secs == 0 {
            return Err("oracle epoch duration must be > 0".to_string());
        }
        if config.max_source_age_secs == 0 {
            return Err("oracle max source age must be > 0".to_string());
        }
        if config.max_deviation_bps > 10_000 {
            return Err("oracle max deviation bps must be <= 10000".to_string());
        }
        if config.price_scale == 0 {
            return Err("oracle price scale must be > 0".to_string());
        }

        self.pending_config_update = Some(PendingConfigUpdate {
            activate_at_epoch: current_epoch.saturating_add(1),
            config,
        });
        Ok(())
    }

    /// Apply pending committee/config updates once activation epoch is reached.
    pub fn apply_pending_updates(&mut self, current_epoch: u64) {
        if let Some(pending) = &self.committee.pending_update {
            if current_epoch >= pending.activate_at_epoch {
                self.committee.members = pending.members.clone();
                self.committee.pending_update = None;
            }
        }

        if let Some(pending) = &self.pending_config_update {
            if current_epoch >= pending.activate_at_epoch {
                self.config = pending.config.clone();
                self.pending_config_update = None;
            }
        }
    }

    /// Deterministic attestation validation for the current epoch.
    pub fn validate_attestation<R>(
        &self,
        attestation: &OraclePriceAttestation,
        current_epoch: u64,
        seen_signers: &BTreeSet<[u8; 32]>,
        resolve_signing_pubkey: R,
    ) -> Result<(), OracleAttestationValidationError>
    where
        R: Fn([u8; 32]) -> Option<Vec<u8>>,
    {
        if attestation.epoch_id != current_epoch {
            return Err(OracleAttestationValidationError::WrongEpoch {
                expected: current_epoch,
                got: attestation.epoch_id,
            });
        }
        if !self
            .committee
            .members
            .iter()
            .any(|member| *member == attestation.validator_pubkey)
        {
            return Err(OracleAttestationValidationError::NonCommitteeSigner(
                attestation.validator_pubkey,
            ));
        }
        if seen_signers.contains(&attestation.validator_pubkey) {
            return Err(OracleAttestationValidationError::DuplicateSigner(
                attestation.validator_pubkey,
            ));
        }

        let signing_pubkey = resolve_signing_pubkey(attestation.validator_pubkey).ok_or(
            OracleAttestationValidationError::MissingSignerPublicKey(attestation.validator_pubkey),
        )?;
        attestation.verify_signature(&signing_pubkey)
    }

    /// Finalize a price for an epoch exactly once.
    ///
    /// Returns `true` if the price was written, `false` if that epoch already has
    /// a finalized price (first-write-wins).
    pub fn try_finalize_price(&mut self, finalized_price: FinalizedOraclePrice) -> bool {
        let epoch_id = finalized_price.epoch_id;
        if self.finalized_prices.contains_key(&epoch_id) {
            return false;
        }
        self.finalized_prices.insert(epoch_id, finalized_price);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_threshold_defaults_to_supermajority() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 3);
    }

    #[test]
    fn committee_threshold_for_small_sets() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32]],
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 2);
    }

    #[test]
    fn pending_committee_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        state.committee.members = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        state
            .schedule_committee_update(vec![[9u8; 32], [8u8; 32], [7u8; 32]], 12)
            .expect("schedule must succeed");

        state.apply_pending_updates(12);
        assert_eq!(state.committee.members, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);

        state.apply_pending_updates(13);
        assert_eq!(state.committee.members, vec![[9u8; 32], [8u8; 32], [7u8; 32]]);
        assert!(state.committee.pending_update.is_none());
    }

    #[test]
    fn pending_config_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        let mut next = state.config.clone();
        next.max_price_staleness_epochs = 5;
        next.max_deviation_bps = 350;

        state
            .schedule_config_update(next.clone(), 3)
            .expect("schedule must succeed");

        state.apply_pending_updates(3);
        assert_ne!(state.config.max_price_staleness_epochs, 5);
        assert_ne!(state.config.max_deviation_bps, 350);

        state.apply_pending_updates(4);
        assert_eq!(state.config.max_price_staleness_epochs, 5);
        assert_eq!(state.config.max_deviation_bps, 350);
        assert!(state.pending_config_update.is_none());
    }

    #[test]
    fn attestation_payload_encoding_is_deterministic() {
        let attestation = OraclePriceAttestation {
            epoch_id: 7,
            sov_usd_price: 123_456_789,
            timestamp: 1_700_000_123,
            validator_pubkey: [9u8; 32],
            signature: vec![1u8; 32],
        };

        let a = attestation
            .canonical_payload_bytes()
            .expect("payload encoding should succeed");
        let b = attestation
            .canonical_payload_bytes()
            .expect("payload encoding should succeed");
        assert_eq!(a, b);
    }

    #[test]
    fn attestation_signature_verifies_with_domain() {
        let keypair = lib_crypto::keypair::generation::KeyPair::generate()
            .expect("keypair generation must succeed");
        let validator_key_id = keypair.public_key.key_id;

        let mut attestation = OraclePriceAttestation {
            epoch_id: 11,
            sov_usd_price: 222_000_000,
            timestamp: 1_700_000_222,
            validator_pubkey: validator_key_id,
            signature: Vec::new(),
        };

        let digest = attestation.signing_digest().expect("digest should build");
        let sig = keypair.sign(&digest).expect("signing must succeed");
        attestation.signature = sig.signature;

        attestation
            .verify_signature(&keypair.public_key.dilithium_pk)
            .expect("signature should verify");
    }

    #[test]
    fn attestation_signature_fails_with_wrong_domain() {
        let keypair = lib_crypto::keypair::generation::KeyPair::generate()
            .expect("keypair generation must succeed");
        let validator_key_id = keypair.public_key.key_id;

        let mut attestation = OraclePriceAttestation {
            epoch_id: 11,
            sov_usd_price: 333_000_000,
            timestamp: 1_700_000_333,
            validator_pubkey: validator_key_id,
            signature: Vec::new(),
        };

        let digest = attestation.signing_digest().expect("digest should build");
        let sig = keypair.sign(&digest).expect("signing must succeed");
        attestation.signature = sig.signature;

        let result = attestation.verify_signature_with_domain(
            &keypair.public_key.dilithium_pk,
            b"SOVN_ORACLE_WRONG_DOMAIN",
        );
        assert!(matches!(
            result,
            Err(OracleAttestationValidationError::InvalidSignature)
        ));
    }

    #[test]
    fn oracle_state_attestation_validation_rejects_non_committee() {
        let keypair = lib_crypto::keypair::generation::KeyPair::generate()
            .expect("keypair generation must succeed");
        let validator_key_id = keypair.public_key.key_id;

        let mut attestation = OraclePriceAttestation {
            epoch_id: 5,
            sov_usd_price: 999_000_000,
            timestamp: 1_700_000_555,
            validator_pubkey: validator_key_id,
            signature: Vec::new(),
        };
        let digest = attestation.signing_digest().expect("digest should build");
        let sig = keypair.sign(&digest).expect("signing must succeed");
        attestation.signature = sig.signature;

        let state = OracleState::default();
        let seen = BTreeSet::new();
        let result = state.validate_attestation(&attestation, 5, &seen, |_id| {
            Some(keypair.public_key.dilithium_pk.clone())
        });
        assert!(matches!(
            result,
            Err(OracleAttestationValidationError::NonCommitteeSigner(_))
        ));
    }

    #[test]
    fn finalize_price_is_first_write_wins_per_epoch() {
        let mut state = OracleState::default();
        let first = FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 100_000_000,
        };
        let second = FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 200_000_000,
        };

        assert!(state.try_finalize_price(first.clone()));
        assert!(
            !state.try_finalize_price(second),
            "second finalized price for same epoch must be rejected"
        );
        assert_eq!(state.finalized_prices.get(&7), Some(&first));
    }

    #[test]
    fn finalize_price_allows_distinct_epochs() {
        let mut state = OracleState::default();
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 1,
            sov_usd_price: 100_000_000,
        }));
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 2,
            sov_usd_price: 120_000_000,
        }));
        assert_eq!(state.finalized_prices.len(), 2);
    }
}
