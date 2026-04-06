#![allow(dead_code)]

//! OracleTestHarness - Integration test infrastructure for ORACLE-16
//!
//! Provides a test harness for end-to-end oracle testing including:
//! - Multi-validator setup with committee membership
//! - Block mining with timestamp advancement
//! - Attestation production and processing
//! - Epoch advancement and price finalization

use lib_blockchain::{
    oracle::{
        OracleAttestationAdmission, OracleAttestationAdmissionError, OracleConfig,
        OraclePriceAttestation,
    },
    types::{Difficulty, Hash},
    Block, BlockHeader, Blockchain,
};
use lib_crypto::keypair::generation::KeyPair;

/// Test harness for oracle integration tests
pub struct OracleTestHarness {
    /// The blockchain under test
    pub blockchain: Blockchain,
    /// Validators with their keypairs (consensus_key, networking_key, rewards_key)
    pub validators: Vec<ValidatorKeys>,
    /// Default mock price to use for attestations
    pub mock_price: u128,
    /// Current block height for mining
    pub current_height: u64,
    /// Current timestamp for mining
    pub current_timestamp: u64,
}

/// Keys for a single validator
pub struct ValidatorKeys {
    /// Keypair for consensus signing (used for attestations)
    pub consensus_keypair: KeyPair,
    /// Keypair for networking
    pub networking_keypair: KeyPair,
    /// Keypair for rewards
    pub rewards_keypair: KeyPair,
    /// The validator's key_id (hash of consensus public key)
    pub key_id: [u8; 32],
}

impl ValidatorKeys {
    /// Generate a new validator with random keys
    pub fn generate() -> Self {
        let consensus_keypair = KeyPair::generate().expect("keypair generation must succeed");
        let networking_keypair = KeyPair::generate().expect("keypair generation must succeed");
        let rewards_keypair = KeyPair::generate().expect("keypair generation must succeed");

        let key_id = consensus_keypair.public_key.key_id;

        Self {
            consensus_keypair,
            networking_keypair,
            rewards_keypair,
            key_id,
        }
    }
}

impl OracleTestHarness {
    /// Create a new test harness with N validators, all in the oracle committee
    pub fn new(validator_count: usize) -> Self {
        let mut blockchain = Blockchain::default();
        let mut validators = Vec::with_capacity(validator_count);
        let mut committee_members = Vec::with_capacity(validator_count);

        // Generate validators
        for _ in 0..validator_count {
            let validator = ValidatorKeys::generate();
            committee_members.push(validator.key_id);
            validators.push(validator);
        }

        // Initialize oracle committee with all validators
        blockchain
            .init_oracle_committee(committee_members)
            .expect("committee init should succeed");

        // Set initial timestamp to be in epoch 0
        let epoch_duration = blockchain.oracle_state.config().epoch_duration_secs;
        let current_timestamp = epoch_duration / 2; // Middle of epoch 0

        Self {
            blockchain,
            validators,
            mock_price: 100_000_000, // $1.00 in ORACLE_PRICE_SCALE
            current_height: 0,
            current_timestamp,
        }
    }

    /// Get the current oracle epoch
    pub fn current_epoch(&self) -> u64 {
        self.blockchain
            .oracle_state
            .epoch_id(self.current_timestamp)
    }

    /// Get the epoch duration from config
    pub fn epoch_duration(&self) -> u64 {
        self.blockchain.oracle_state.config().epoch_duration_secs
    }

    /// Get the committee threshold
    pub fn threshold(&self) -> usize {
        self.blockchain.oracle_state.committee.threshold() as usize
    }

    /// Advance blockchain by N blocks with timestamp advancement
    pub fn mine_blocks(&mut self, count: u64) {
        let epoch_duration = self.epoch_duration();
        // Advance timestamp by a fraction of epoch duration per block
        let time_per_block = epoch_duration / 10;

        for _ in 0..count {
            self.current_height += 1;
            self.current_timestamp += time_per_block;

            // Apply pending updates at the new epoch
            let epoch = self
                .blockchain
                .oracle_state
                .epoch_id(self.current_timestamp);
            self.blockchain.oracle_state.apply_pending_updates(epoch);

            // Note: In a real test we'd create and process actual blocks
            // For harness purposes, we just advance timestamps and apply updates
        }
    }

    /// Mine blocks until we advance to the next oracle epoch
    pub fn advance_oracle_epoch(&mut self) {
        let current_epoch = self.current_epoch();

        // Mine blocks until we enter the next epoch
        while self.current_epoch() <= current_epoch {
            self.mine_blocks(1);
        }
    }

    /// Produce a valid oracle attestation from validator at index `idx`
    pub fn produce_attestation(
        &self,
        validator_idx: usize,
        epoch_id: u64,
        price: u128,
    ) -> OraclePriceAttestation {
        let validator = &self.validators[validator_idx];

        // Calculate timestamp for this epoch
        let epoch_duration = self.epoch_duration();
        let timestamp = epoch_id * epoch_duration + epoch_duration / 2;

        let mut attestation = OraclePriceAttestation {
            epoch_id,
            sov_usd_price: price,
            cbe_usd_price: None,
            timestamp,
            validator_pubkey: validator.key_id,
            signature: Vec::new(),
        };

        // Sign the attestation
        let digest = attestation.signing_digest().expect("digest should build");
        let sig = validator
            .consensus_keypair
            .sign(&digest)
            .expect("signing must succeed");
        attestation.signature = sig.signature;

        attestation
    }

    /// Produce an attestation with a custom timestamp (for testing edge cases)
    pub fn produce_attestation_with_timestamp(
        &self,
        validator_idx: usize,
        epoch_id: u64,
        price: u128,
        timestamp: u64,
    ) -> OraclePriceAttestation {
        let validator = &self.validators[validator_idx];

        let mut attestation = OraclePriceAttestation {
            epoch_id,
            sov_usd_price: price,
            cbe_usd_price: None,
            timestamp,
            validator_pubkey: validator.key_id,
            signature: Vec::new(),
        };

        let digest = attestation.signing_digest().expect("digest should build");
        let sig = validator
            .consensus_keypair
            .sign(&digest)
            .expect("signing must succeed");
        attestation.signature = sig.signature;

        attestation
    }

    /// Process an attestation as if received from gossip
    pub fn process_attestation(
        &mut self,
        attestation: OraclePriceAttestation,
    ) -> Result<OracleAttestationAdmission, OracleAttestationAdmissionError> {
        let current_epoch = self.current_epoch();

        // Resolver function to look up validator signing keys
        let resolver = |key_id: [u8; 32]| -> Option<Vec<u8>> {
            self.validators
                .iter()
                .find(|v| v.key_id == key_id)
                .map(|v| v.consensus_keypair.public_key.dilithium_pk.to_vec())
        };

        // Process the attestation
        self.blockchain
            .oracle_state
            .process_attestation(&attestation, current_epoch, resolver)
    }

    /// Process N attestations from the first N validators to finalize an epoch
    /// Returns the finalized price if threshold was reached
    pub fn finalize_epoch(&mut self, epoch_id: u64, price: u128) -> Option<u128> {
        let threshold = self.threshold();

        for i in 0..threshold {
            let attestation = self.produce_attestation(i, epoch_id, price);
            match self.process_attestation(attestation) {
                Ok(OracleAttestationAdmission::Finalized(finalized)) => {
                    return Some(finalized.sov_usd_price);
                }
                Ok(_) => continue,
                Err(_) => return None,
            }
        }

        None
    }

    /// Get the key_id for a validator at index
    pub fn validator_key_id(&self, idx: usize) -> [u8; 32] {
        self.validators[idx].key_id
    }

    /// Add a new validator to the test (but not to committee yet)
    pub fn add_validator(&mut self) -> &ValidatorKeys {
        let validator = ValidatorKeys::generate();
        self.validators.push(validator);
        self.validators.last().unwrap()
    }

    /// Create a block at a specific timestamp (without processing it)
    #[allow(dead_code)]
    fn create_block_at_timestamp(&self, timestamp: u64) -> Block {
        let header = BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp,
            height: self.current_height,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        };

        Block {
            header,
            transactions: vec![],
        }
    }

    /// Get the finalized price for an epoch
    pub fn get_finalized_price(&self, epoch_id: u64) -> Option<u128> {
        self.blockchain
            .oracle_state
            .finalized_price(epoch_id)
            .map(|p| p.sov_usd_price)
    }

    /// Check if a validator is in the current committee
    pub fn is_committee_member(&self, key_id: [u8; 32]) -> bool {
        self.blockchain
            .oracle_state
            .committee
            .members()
            .contains(&key_id)
    }

    /// Schedule a committee update
    pub fn schedule_committee_update(
        &mut self,
        members: Vec<[u8; 32]>,
        activate_at_epoch: u64,
    ) -> Result<(), String> {
        let current_epoch = self
            .blockchain
            .oracle_state
            .epoch_id(self.current_timestamp);
        self.blockchain.oracle_state.schedule_committee_update(
            members,
            activate_at_epoch,
            current_epoch,
            None,
        )
    }

    /// Schedule a config update
    pub fn schedule_config_update(
        &mut self,
        config: OracleConfig,
        activate_at_epoch: u64,
    ) -> Result<(), String> {
        let current_epoch = self
            .blockchain
            .oracle_state
            .epoch_id(self.current_timestamp);
        self.blockchain
            .oracle_state
            .schedule_config_update(config, activate_at_epoch, current_epoch, None)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_creates_validators_in_committee() {
        let harness = OracleTestHarness::new(4);
        assert_eq!(harness.blockchain.oracle_state.committee.members().len(), 4);
        assert_eq!(harness.validators.len(), 4);
    }

    #[test]
    fn harness_produces_valid_attestation() {
        let harness = OracleTestHarness::new(4);
        let epoch = harness.current_epoch();

        let attestation = harness.produce_attestation(0, epoch, 100_000_000);
        assert_eq!(attestation.epoch_id, epoch);
        assert_eq!(attestation.sov_usd_price, 100_000_000);
        assert!(!attestation.signature.is_empty());
    }

    #[test]
    fn harness_advances_epoch() {
        let mut harness = OracleTestHarness::new(4);
        let initial_epoch = harness.current_epoch();

        harness.advance_oracle_epoch();

        assert!(harness.current_epoch() > initial_epoch);
    }

    #[test]
    fn harness_finalizes_epoch() {
        let mut harness = OracleTestHarness::new(4);
        let epoch = harness.current_epoch();

        let finalized = harness.finalize_epoch(epoch, 100_000_000);

        assert_eq!(finalized, Some(100_000_000));
        assert_eq!(harness.get_finalized_price(epoch), Some(100_000_000));
    }
}
