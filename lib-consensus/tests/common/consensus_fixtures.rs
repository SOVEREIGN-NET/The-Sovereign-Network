//! Shared consensus test fixtures for lib-consensus integration tests.
//!
//! Centralises identity construction, key generation, signature builders, and
//! config factories so every test file uses the same logic without duplication.

use std::sync::atomic::{AtomicU64, Ordering};

use lib_consensus::{ConsensusConfig, ConsensusProof, ConsensusProposal, ConsensusType, ConsensusVote, StakeProof, VoteType};
use lib_crypto::{hash_blake3, Hash, PostQuantumSignature, PublicKey, SignatureAlgorithm};
use lib_identity::IdentityId;

// Global counter for generating unique test identities across test files.
static UNIQUE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Deterministic identity derived from a human-readable name.
pub fn named_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

/// Unique identity guaranteed to not repeat within a process.
pub fn unique_identity() -> IdentityId {
    let id = UNIQUE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    Hash::from_bytes(&hash_blake3(format!("test-validator-{}", id).as_bytes()))
}

/// Returns (dilithium_pk, networking_key_bytes, rewards_key_bytes) for a given seed byte.
pub fn validator_keys(seed: u8) -> ([u8; 2592], Vec<u8>, Vec<u8>) {
    (
        [seed; 2592],
        vec![seed.wrapping_add(64); 32],
        vec![seed.wrapping_add(128); 32],
    )
}

/// Wall-clock timestamp as seconds since Unix epoch.
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A `PostQuantumSignature` with deterministic bytes derived from `timestamp`.
/// Not a real signature — for structural tests only.
pub fn test_signature(timestamp: u64) -> PostQuantumSignature {
    let mut sig_bytes = vec![timestamp as u8; 64];
    for i in 0..32 {
        sig_bytes[i] = sig_bytes[i].wrapping_add(i as u8);
    }
    PostQuantumSignature {
        signature: sig_bytes,
        public_key: PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [0u8; 32],
        },
        algorithm: SignatureAlgorithm::DEFAULT,
        timestamp,
    }
}

/// A `ConsensusConfig` tuned for BFT testing (fast timeouts, 10 validators max).
pub fn bft_test_config() -> ConsensusConfig {
    ConsensusConfig {
        consensus_type: ConsensusType::ByzantineFaultTolerance,
        min_stake: 1_000 * 1_000_000,
        min_storage: 100 * 1024 * 1024 * 1024,
        max_validators: 10,
        block_time: 1,
        epoch_length_blocks: 100,
        propose_timeout: 100,
        prevote_timeout: 50,
        precommit_timeout: 50,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: false,
    }
}

/// A basic `ConsensusConfig` for unit/integration tests (development_mode = true).
pub fn basic_test_config() -> ConsensusConfig {
    ConsensusConfig {
        consensus_type: ConsensusType::ByzantineFaultTolerance,
        min_stake: 1_000 * 1_000_000,
        min_storage: 100 * 1024 * 1024 * 1024,
        max_validators: 10,
        block_time: 1,
        epoch_length_blocks: 100,
        propose_timeout: 100,
        prevote_timeout: 50,
        precommit_timeout: 50,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: true,
    }
}

/// Build a `ConsensusProposal` for tests.
pub fn test_proposal(
    proposer: &IdentityId,
    height: u64,
    previous_hash: &Hash,
    block_data: Vec<u8>,
    timestamp: u64,
) -> ConsensusProposal {
    let proposal_id = Hash::from_bytes(&hash_blake3(
        format!("proposal-{}-{}-{}", height, timestamp, proposer).as_bytes(),
    ));
    ConsensusProposal {
        id: proposal_id,
        proposer: proposer.clone(),
        height,
        round: 0,
        protocol_version: 1,
        previous_hash: previous_hash.clone(),
        block_data,
        timestamp,
        signature: test_signature(timestamp),
        consensus_proof: ConsensusProof {
            consensus_type: ConsensusType::ByzantineFaultTolerance,
            stake_proof: Some(
                StakeProof::new(
                    proposer.clone(),
                    2_000 * 1_000_000,
                    Hash::from_bytes(&hash_blake3(
                        format!("stake-{}-{}", proposer, timestamp).as_bytes(),
                    )),
                    height.saturating_sub(1),
                    10_000,
                )
                .expect("valid stake proof"),
            ),
            storage_proof: None,
            work_proof: None,
            zk_did_proof: None,
            timestamp,
        },
    }
}

/// Build a `ConsensusVote` for tests.
pub fn test_vote(
    voter: &IdentityId,
    proposal_id: &Hash,
    vote_type: VoteType,
    height: u64,
    round: u32,
    timestamp: u64,
) -> ConsensusVote {
    let vote_id = Hash::from_bytes(&hash_blake3(
        format!("vote-{}-{}-{}-{}", voter, height, round, timestamp).as_bytes(),
    ));
    ConsensusVote {
        id: vote_id,
        voter: voter.clone(),
        proposal_id: proposal_id.clone(),
        vote_type,
        height,
        round,
        timestamp,
        signature: test_signature(timestamp),
    }
}
