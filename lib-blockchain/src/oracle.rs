//! Oracle Protocol v1 consensus state types.
//!
//! This module contains deterministic state models used by consensus to manage:
//! - oracle committee membership
//! - oracle configuration
//! - per-epoch finalized prices

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleAttestationAdmission {
    /// Accepted for aggregation but threshold not yet reached.
    Accepted,
    /// Ignored because message epoch is outside the current epoch.
    IgnoredOutsideCurrentEpoch { current_epoch: u64, attested_epoch: u64 },
    /// Duplicate signer for the same epoch/price; ignored.
    IgnoredDuplicateSigner([u8; 32]),
    /// Epoch already finalized with same price; ignored.
    IgnoredAfterFinalization { epoch_id: u64, price: u128 },
    /// First candidate to reach threshold for epoch.
    Finalized(FinalizedOraclePrice),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleAttestationAdmissionError {
    Validation(OracleAttestationValidationError),
    /// Signer submitted a second, conflicting price for same epoch.
    ConflictingSigner {
        signer: [u8; 32],
        existing_price: u128,
        attempted_price: u128,
    },
    /// Epoch already finalized with a different price.
    ConflictingFinalizedPrice {
        epoch_id: u64,
        finalized_price: u128,
        attempted_price: u128,
    },
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
    #[serde(
        default = "default_price_scale",
        deserialize_with = "deserialize_price_scale"
    )]
    price_scale: u128,
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

fn default_price_scale() -> u128 {
    ORACLE_PRICE_SCALE
}

fn deserialize_price_scale<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u128::deserialize(deserializer)?;
    if value != ORACLE_PRICE_SCALE {
        return Err(serde::de::Error::custom(format!(
            "invalid oracle price_scale {}; expected {}",
            value, ORACLE_PRICE_SCALE
        )));
    }
    Ok(value)
}

impl OracleConfig {
    pub fn price_scale(&self) -> u128 {
        self.price_scale
    }

    pub fn max_price_staleness_epochs(&self) -> u64 {
        self.max_price_staleness_epochs
    }
}

/// Pending governance committee update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCommitteeUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// New committee members (validator public keys).
    #[serde(default, deserialize_with = "deserialize_members_sorted_dedup")]
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
    #[serde(default, deserialize_with = "deserialize_members_sorted_dedup")]
    members: Vec<[u8; 32]>,
    /// Pending update, if scheduled.
    pending_update: Option<PendingCommitteeUpdate>,
}

impl OracleCommitteeState {
    pub fn new(members: Vec<[u8; 32]>, pending_update: Option<PendingCommitteeUpdate>) -> Self {
        Self {
            members: normalize_members(members),
            pending_update: normalize_pending_update(pending_update),
        }
    }

    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    pub fn pending_update(&self) -> Option<&PendingCommitteeUpdate> {
        self.pending_update.as_ref()
    }

    pub fn set_members(&mut self, members: Vec<[u8; 32]>) {
        self.members = normalize_members(members);
    }

    pub fn set_pending_update(&mut self, pending_update: Option<PendingCommitteeUpdate>) {
        self.pending_update = normalize_pending_update(pending_update);
    }

    /// Threshold formula: floor(2N/3)+1.
    pub fn threshold(&self) -> u16 {
        let n = self.members.len() as u64;
        let threshold = (2 * n) / 3 + 1;
        threshold.min(u16::MAX as u64) as u16
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
    /// Candidate signatures grouped by price.
    #[serde(default)]
    pub price_signers: BTreeMap<u128, BTreeSet<[u8; 32]>>,
    /// Signer -> attested price for conflict detection.
    #[serde(default)]
    pub signer_prices: BTreeMap<[u8; 32], u128>,
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
    #[serde(default, deserialize_with = "deserialize_finalized_prices")]
    finalized_prices: BTreeMap<u64, FinalizedOraclePrice>,
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
            members: normalize_members(members),
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
        if config.price_scale() != ORACLE_PRICE_SCALE {
            return Err("oracle price scale must be canonical 1e8".to_string());
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
                self.committee.members = normalize_members(pending.members.clone());
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

    /// Finalize a price for an epoch exactly once.
    ///
    /// Returns `true` if the price was written, `false` if that epoch already has
    /// a finalized price (first-write-wins).
    pub fn try_finalize_price(&mut self, finalized_price: FinalizedOraclePrice) -> bool {
        let epoch_id = finalized_price.epoch_id;
        if self.finalized_prices.contains_key(&epoch_id) {
            return false;
        }
        let winning_price = finalized_price.sov_usd_price;
        self.finalized_prices.insert(epoch_id, finalized_price);
        let epoch_state = self.epoch_state.entry(epoch_id).or_default();
        epoch_state.winning_price = Some(winning_price);
        epoch_state.finalized = true;
        true
    }

    pub fn finalized_price(&self, epoch_id: u64) -> Option<&FinalizedOraclePrice> {
        self.finalized_prices.get(&epoch_id)
    }

    pub fn finalized_prices_len(&self) -> usize {
        self.finalized_prices.len()
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

    /// Admission precheck (non-mutating) used by both gossip admission and block execution.
    pub fn precheck_attestation<R>(
        &self,
        attestation: &OraclePriceAttestation,
        current_epoch: u64,
        resolve_signing_pubkey: R,
    ) -> Result<OracleAttestationAdmission, OracleAttestationAdmissionError>
    where
        R: Fn([u8; 32]) -> Option<Vec<u8>>,
    {
        if attestation.epoch_id != current_epoch {
            return Ok(OracleAttestationAdmission::IgnoredOutsideCurrentEpoch {
                current_epoch,
                attested_epoch: attestation.epoch_id,
            });
        }

        if let Some(finalized) = self.finalized_prices.get(&current_epoch) {
            if finalized.sov_usd_price == attestation.sov_usd_price {
                return Ok(OracleAttestationAdmission::IgnoredAfterFinalization {
                    epoch_id: current_epoch,
                    price: finalized.sov_usd_price,
                });
            }
            return Err(OracleAttestationAdmissionError::ConflictingFinalizedPrice {
                epoch_id: current_epoch,
                finalized_price: finalized.sov_usd_price,
                attempted_price: attestation.sov_usd_price,
            });
        }

        let epoch_state = self.epoch_state.get(&current_epoch);
        if let Some(state) = epoch_state {
            if state.finalized {
                if let Some(winning) = state.winning_price {
                    if winning == attestation.sov_usd_price {
                        return Ok(OracleAttestationAdmission::IgnoredAfterFinalization {
                            epoch_id: current_epoch,
                            price: winning,
                        });
                    }
                    return Err(OracleAttestationAdmissionError::ConflictingFinalizedPrice {
                        epoch_id: current_epoch,
                        finalized_price: winning,
                        attempted_price: attestation.sov_usd_price,
                    });
                } else {
                    // Defensive guard: epoch is marked finalized but has no winning_price.
                    // This state should not normally occur, but if it does, we must avoid
                    // mutating signer state for an already-finalized epoch. Treat this
                    // attestation as if it arrived after finalization and ignore it.
                    return Ok(OracleAttestationAdmission::IgnoredAfterFinalization {
                        epoch_id: current_epoch,
                        price: attestation.sov_usd_price,
                    });
                }
            }
        }

        if let Some(state) = epoch_state {
            if let Some(existing_price) = state.signer_prices.get(&attestation.validator_pubkey) {
                if *existing_price == attestation.sov_usd_price {
                    return Ok(OracleAttestationAdmission::IgnoredDuplicateSigner(
                        attestation.validator_pubkey,
                    ));
                }
                return Err(OracleAttestationAdmissionError::ConflictingSigner {
                    signer: attestation.validator_pubkey,
                    existing_price: *existing_price,
                    attempted_price: attestation.sov_usd_price,
                });
            }
        }

        let seen_signers = epoch_state
            .map(|state| state.signer_prices.keys().copied().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        self.validate_attestation(
            attestation,
            current_epoch,
            &seen_signers,
            resolve_signing_pubkey,
        )
        .map_err(OracleAttestationAdmissionError::Validation)?;

        Ok(OracleAttestationAdmission::Accepted)
    }

    /// Mutating attestation admission + deterministic finalization.
    pub fn process_attestation<R>(
        &mut self,
        attestation: &OraclePriceAttestation,
        current_epoch: u64,
        resolve_signing_pubkey: R,
    ) -> Result<OracleAttestationAdmission, OracleAttestationAdmissionError>
    where
        R: Fn([u8; 32]) -> Option<Vec<u8>>,
    {
        let precheck =
            self.precheck_attestation(attestation, current_epoch, resolve_signing_pubkey)?;
        if !matches!(precheck, OracleAttestationAdmission::Accepted) {
            return Ok(precheck);
        }

        let threshold = self.committee.threshold() as usize;

        let epoch_state = self.epoch_state.entry(current_epoch).or_default();
        epoch_state
            .signer_prices
            .insert(attestation.validator_pubkey, attestation.sov_usd_price);
        let signer_set = epoch_state
            .price_signers
            .entry(attestation.sov_usd_price)
            .or_default();
        signer_set.insert(attestation.validator_pubkey);

        if !epoch_state.finalized && signer_set.len() >= threshold {
            epoch_state.finalized = true;
            epoch_state.winning_price = Some(attestation.sov_usd_price);

            let finalized = FinalizedOraclePrice {
                epoch_id: current_epoch,
                sov_usd_price: attestation.sov_usd_price,
            };

            if let Some(existing) = self.finalized_prices.get(&current_epoch) {
                if existing.sov_usd_price != finalized.sov_usd_price {
                    return Err(OracleAttestationAdmissionError::ConflictingFinalizedPrice {
                        epoch_id: current_epoch,
                        finalized_price: existing.sov_usd_price,
                        attempted_price: finalized.sov_usd_price,
                    });
                }
            } else {
                self.finalized_prices.insert(current_epoch, finalized.clone());
            }

            return Ok(OracleAttestationAdmission::Finalized(finalized));
        }

        Ok(OracleAttestationAdmission::Accepted)
    }

    pub fn latest_finalized_epoch(&self) -> Option<u64> {
        self.finalized_prices.keys().max().copied()
    }

    pub fn config(&self) -> &OracleConfig {
        &self.config
    }
}

fn normalize_members(mut members: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    members.sort_unstable();
    members.dedup();
    members
}

fn normalize_pending_update(
    pending_update: Option<PendingCommitteeUpdate>,
) -> Option<PendingCommitteeUpdate> {
    pending_update.map(|mut update| {
        update.members = normalize_members(update.members);
        update
    })
}

fn deserialize_members_sorted_dedup<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let members = Vec::<[u8; 32]>::deserialize(deserializer)?;
    Ok(normalize_members(members))
}

fn deserialize_finalized_prices<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<u64, FinalizedOraclePrice>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<u64, FinalizedOraclePrice>::deserialize(deserializer)?;
    for (epoch_key, price) in &map {
        if *epoch_key != price.epoch_id {
            return Err(serde::de::Error::custom(format!(
                "finalized_prices key {} does not match payload epoch_id {}",
                epoch_key, price.epoch_id
            )));
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_threshold_defaults_to_supermajority() {
        let committee =
            OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]], None);
        assert_eq!(committee.threshold(), 3);
    }

    #[test]
    fn committee_threshold_for_small_sets() {
        let committee = OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32]], None);
        assert_eq!(committee.threshold(), 2);
    }

    #[test]
    fn committee_threshold_empty_is_one() {
        let committee = OracleCommitteeState::default();
        assert_eq!(committee.threshold(), 1);
    }

    #[test]
    fn committee_members_are_normalized() {
        let committee = OracleCommitteeState::new(vec![[2u8; 32], [1u8; 32], [2u8; 32]], None);
        assert_eq!(committee.members().len(), 2);
        assert_eq!(committee.members()[0], [1u8; 32]);
        assert_eq!(committee.members()[1], [2u8; 32]);
    }

    #[test]
    fn pending_committee_update_members_are_normalized() {
        let pending = PendingCommitteeUpdate {
            activate_at_epoch: 10,
            members: vec![[3u8; 32], [1u8; 32], [3u8; 32], [2u8; 32]],
        };
        let committee = OracleCommitteeState::new(vec![], Some(pending));
        let pending = committee
            .pending_update()
            .expect("pending update must be set");
        assert_eq!(pending.members, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
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
        assert_eq!(state.finalized_price(7), Some(&first));
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
        assert_eq!(state.finalized_prices_len(), 2);
    }

    #[test]
    fn finalize_price_sets_epoch_state_winning_price_and_finalized_flag() {
        let mut state = OracleState::default();
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 123_000_000,
        }));
        let epoch_state = state.epoch_state.get(&7).expect("epoch state must exist");
        assert_eq!(epoch_state.winning_price, Some(123_000_000));
        assert!(epoch_state.finalized);
    }

    #[test]
    fn deserialize_rejects_noncanonical_price_scale() {
        let invalid = r#"{
            "epoch_duration_secs":300,
            "max_source_age_secs":60,
            "max_deviation_bps":500,
            "max_price_staleness_epochs":2,
            "price_scale":123
        }"#;
        let err =
            serde_json::from_str::<OracleConfig>(invalid).expect_err("must reject non-1e8 scale");
        assert!(
            err.to_string().contains("invalid oracle price_scale"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn deserialize_rejects_mismatched_finalized_price_epoch_key() {
        let invalid = r#"{
            "finalized_prices": {
                "7": { "epoch_id": 8, "sov_usd_price": 100000000 }
            },
            "epoch_state": {}
        }"#;
        let err =
            serde_json::from_str::<OracleState>(invalid).expect_err("must reject mismatched key");
        assert!(
            err.to_string().contains("does not match payload epoch_id"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn pending_committee_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        state.committee.set_members(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        state
            .schedule_committee_update(vec![[9u8; 32], [8u8; 32], [7u8; 32]], 12)
            .expect("schedule must succeed");

        state.apply_pending_updates(12);
        assert_eq!(state.committee.members(), &[[1u8; 32], [2u8; 32], [3u8; 32]]);

        state.apply_pending_updates(13);
        assert_eq!(state.committee.members(), &[[7u8; 32], [8u8; 32], [9u8; 32]]);
        assert!(state.committee.pending_update().is_none());
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
    fn oracle_finalizes_first_price_to_threshold_and_rejects_conflicts() {
        let k1 = lib_crypto::keypair::generation::KeyPair::generate().expect("k1");
        let k2 = lib_crypto::keypair::generation::KeyPair::generate().expect("k2");
        let k3 = lib_crypto::keypair::generation::KeyPair::generate().expect("k3");
        let k4 = lib_crypto::keypair::generation::KeyPair::generate().expect("k4");

        let mut state = OracleState::default();
        state.committee.members = vec![
            k1.public_key.key_id,
            k2.public_key.key_id,
            k3.public_key.key_id,
            k4.public_key.key_id,
        ];
        let epoch = 42;

        let mk_att = |kp: &lib_crypto::keypair::generation::KeyPair, price: u128| {
            let mut att = OraclePriceAttestation {
                epoch_id: epoch,
                sov_usd_price: price,
                timestamp: 1_700_000_000,
                validator_pubkey: kp.public_key.key_id,
                signature: Vec::new(),
            };
            let digest = att.signing_digest().expect("digest");
            let sig = kp.sign(&digest).expect("sign");
            att.signature = sig.signature;
            att
        };

        let att1 = mk_att(&k1, 200_000_000);
        let att2 = mk_att(&k2, 200_000_000);
        let att3 = mk_att(&k3, 200_000_000);
        let conflicting = mk_att(&k4, 201_000_000);

        let resolver = |id: [u8; 32]| -> Option<Vec<u8>> {
            if id == k1.public_key.key_id {
                Some(k1.public_key.dilithium_pk.clone())
            } else if id == k2.public_key.key_id {
                Some(k2.public_key.dilithium_pk.clone())
            } else if id == k3.public_key.key_id {
                Some(k3.public_key.dilithium_pk.clone())
            } else if id == k4.public_key.key_id {
                Some(k4.public_key.dilithium_pk.clone())
            } else {
                None
            }
        };

        assert!(matches!(
            state.process_attestation(&att1, epoch, resolver),
            Ok(OracleAttestationAdmission::Accepted)
        ));
        assert!(matches!(
            state.process_attestation(&att2, epoch, resolver),
            Ok(OracleAttestationAdmission::Accepted)
        ));

        let finalized = state
            .process_attestation(&att3, epoch, resolver)
            .expect("third signer should finalize");
        assert!(matches!(
            finalized,
            OracleAttestationAdmission::Finalized(FinalizedOraclePrice {
                epoch_id: 42,
                sov_usd_price: 200_000_000
            })
        ));

        let conflict = state.process_attestation(&conflicting, epoch, resolver);
        assert!(matches!(
            conflict,
            Err(OracleAttestationAdmissionError::ConflictingFinalizedPrice {
                finalized_price: 200_000_000,
                attempted_price: 201_000_000,
                ..
            })
        ));
    }

    #[test]
    fn oracle_ignores_out_of_epoch_and_duplicate_attestations() {
        let keypair = lib_crypto::keypair::generation::KeyPair::generate().expect("keypair");
        let mut state = OracleState::default();
        state.committee.members = vec![keypair.public_key.key_id, [2u8; 32], [3u8; 32]];

        let mut wrong_epoch = OraclePriceAttestation {
            epoch_id: 7,
            sov_usd_price: 222_000_000,
            timestamp: 1_700_000_001,
            validator_pubkey: keypair.public_key.key_id,
            signature: Vec::new(),
        };
        let digest = wrong_epoch.signing_digest().expect("digest");
        wrong_epoch.signature = keypair.sign(&digest).expect("sign").signature;

        let resolver = |id: [u8; 32]| -> Option<Vec<u8>> {
            if id == keypair.public_key.key_id {
                Some(keypair.public_key.dilithium_pk.clone())
            } else {
                Some(vec![0u8; 32])
            }
        };

        let ignored = state
            .process_attestation(&wrong_epoch, 8, resolver)
            .expect("must ignore");
        assert!(matches!(
            ignored,
            OracleAttestationAdmission::IgnoredOutsideCurrentEpoch {
                current_epoch: 8,
                attested_epoch: 7
            }
        ));
        assert!(state.epoch_state.get(&8).is_none());

        let mut current = OraclePriceAttestation {
            epoch_id: 8,
            ..wrong_epoch.clone()
        };
        let digest_current = current.signing_digest().expect("digest");
        current.signature = keypair.sign(&digest_current).expect("sign").signature;
        let _ = state
            .process_attestation(&current, 8, resolver)
            .expect("first admission should pass");
        let duplicate = state
            .process_attestation(&current, 8, resolver)
            .expect("duplicate should be ignored");
        assert!(matches!(
            duplicate,
            OracleAttestationAdmission::IgnoredDuplicateSigner(_)
        ));
    }

    #[test]
    fn oracle_precheck_matches_execution_admission() {
        let k1 = lib_crypto::keypair::generation::KeyPair::generate().expect("k1");
        let k2 = lib_crypto::keypair::generation::KeyPair::generate().expect("k2");
        let k3 = lib_crypto::keypair::generation::KeyPair::generate().expect("k3");

        let mut state = OracleState::default();
        state.committee.members = vec![k1.public_key.key_id, k2.public_key.key_id, k3.public_key.key_id];
        let epoch = 13;

        let mut att = OraclePriceAttestation {
            epoch_id: epoch,
            sov_usd_price: 300_000_000,
            timestamp: 1_700_000_010,
            validator_pubkey: k1.public_key.key_id,
            signature: Vec::new(),
        };
        let digest = att.signing_digest().expect("digest");
        att.signature = k1.sign(&digest).expect("sign").signature;

        let resolver = |id: [u8; 32]| -> Option<Vec<u8>> {
            if id == k1.public_key.key_id {
                Some(k1.public_key.dilithium_pk.clone())
            } else if id == k2.public_key.key_id {
                Some(k2.public_key.dilithium_pk.clone())
            } else if id == k3.public_key.key_id {
                Some(k3.public_key.dilithium_pk.clone())
            } else {
                None
            }
        };

        let pre = state
            .precheck_attestation(&att, epoch, resolver)
            .expect("precheck should pass");
        let exec = state
            .process_attestation(&att, epoch, resolver)
            .expect("execution should pass");
        assert_eq!(pre, exec);
    }

    #[test]
    fn oracle_replay_reconstructs_identical_finalized_prices() {
        let k1 = lib_crypto::keypair::generation::KeyPair::generate().expect("k1");
        let k2 = lib_crypto::keypair::generation::KeyPair::generate().expect("k2");
        let k3 = lib_crypto::keypair::generation::KeyPair::generate().expect("k3");

        let committee = vec![k1.public_key.key_id, k2.public_key.key_id, k3.public_key.key_id];
        let epoch = 22;
        let price = 250_000_000u128;

        let mk = |kp: &lib_crypto::keypair::generation::KeyPair| {
            let mut att = OraclePriceAttestation {
                epoch_id: epoch,
                sov_usd_price: price,
                timestamp: 1_700_000_100,
                validator_pubkey: kp.public_key.key_id,
                signature: Vec::new(),
            };
            let digest = att.signing_digest().expect("digest");
            att.signature = kp.sign(&digest).expect("sign").signature;
            att
        };
        let attestations = vec![mk(&k1), mk(&k2), mk(&k3)];

        let resolver = |id: [u8; 32]| -> Option<Vec<u8>> {
            if id == k1.public_key.key_id {
                Some(k1.public_key.dilithium_pk.clone())
            } else if id == k2.public_key.key_id {
                Some(k2.public_key.dilithium_pk.clone())
            } else if id == k3.public_key.key_id {
                Some(k3.public_key.dilithium_pk.clone())
            } else {
                None
            }
        };

        let mut a = OracleState::default();
        a.committee.members = committee.clone();
        for att in &attestations {
            a.process_attestation(att, epoch, resolver).expect("process");
        }

        let snapshot = bincode::serialize(&a).expect("serialize oracle state");
        let restored: OracleState = bincode::deserialize(&snapshot).expect("deserialize oracle state");

        let mut b = OracleState::default();
        b.committee.members = committee;
        for att in &attestations {
            b.process_attestation(att, epoch, resolver).expect("replay");
        }

        assert_eq!(restored.finalized_prices, b.finalized_prices);
        assert_eq!(restored.epoch_state, b.epoch_state);
    }
}
