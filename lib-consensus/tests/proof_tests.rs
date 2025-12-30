//! Tests for proof verification systems

use anyhow::Result;
use lib_consensus::{
    ComputeResult, NetworkState, ProofOfUsefulWork, StakeProof, StorageChallenge, StorageProof,
    WorkProof,
};
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

/// Helper function to create test network state
fn create_test_network_state() -> NetworkState {
    NetworkState {
        total_participants: 100,
        average_uptime: 95.5,
        total_bandwidth_shared: 1024 * 1024 * 1024, // 1 GB
        consensus_round: 1000,
    }
}

#[test]
fn test_stake_proof_creation_and_verification() -> Result<()> {
    let validator_id = create_test_identity("alice");
    let stake_amount = 2000 * 1_000_000; // 2000 ZHTP
    let stake_tx_hash = Hash::from_bytes(&hash_blake3(b"stake_transaction"));
    let block_height = 100;
    let lock_time = 86400; // 1 day

    let stake_proof = StakeProof::new(
        validator_id.clone(),
        stake_amount,
        stake_tx_hash.clone(),
        block_height,
        lock_time,
    )?;

    assert_eq!(stake_proof.validator, validator_id);
    assert_eq!(stake_proof.staked_amount, stake_amount);
    assert_eq!(stake_proof.stake_tx_hash, stake_tx_hash);
    assert_eq!(stake_proof.stake_height, block_height);
    assert_eq!(stake_proof.lock_time, lock_time);

    // Test verification
    let current_height = 200;
    assert!(stake_proof.verify(current_height)?);

    Ok(())
}

#[test]
fn test_stake_proof_insufficient_lock_time() -> Result<()> {
    let validator_id = create_test_identity("bob");
    let stake_amount = 1000 * 1_000_000;
    let stake_tx_hash = Hash::from_bytes(&hash_blake3(b"stake_transaction"));
    let block_height = 100;
    let lock_time = 3600; // 1 hour (too short)

    let stake_proof = StakeProof::new(
        validator_id,
        stake_amount,
        stake_tx_hash,
        block_height,
        lock_time,
    )?;

    // Test with a current height that would make the stake expired
    let current_height = block_height + lock_time + 1; // Expired
    let result = stake_proof.verify(current_height)?;
    assert!(!result); // Should return false for expired stake

    Ok(())
}

#[test]
fn test_stake_proof_verification_failure() -> Result<()> {
    let validator_id = create_test_identity("charlie");
    let stake_amount = 500 * 1_000_000; // Below minimum (1000 ZHTP)
    let stake_tx_hash = Hash::from_bytes(&hash_blake3(b"stake_transaction"));
    let block_height = 100;
    let lock_time = 86400;

    let stake_proof = StakeProof::new(
        validator_id,
        stake_amount,
        stake_tx_hash,
        block_height,
        lock_time,
    )?;

    let current_height = 200;
    let result = stake_proof.verify(current_height)?;
    assert!(!result); // Should return false for insufficient stake

    Ok(())
}

#[test]
fn test_storage_proof_creation_and_verification() -> Result<()> {
    let validator_hash = Hash::from_bytes(&hash_blake3(b"validator_alice"));
    let storage_capacity = 500 * 1024 * 1024 * 1024; // 500 GB
    let utilization = 75; // 75%

    // Create storage challenges
    let mut challenges = Vec::new();
    for i in 0..3 {
        let challenge = StorageChallenge {
            id: Hash::from_bytes(&hash_blake3(&format!("challenge_{}", i).as_bytes())),
            content_hash: Hash::from_bytes(&hash_blake3(&format!("content_{}", i).as_bytes())),
            challenge: vec![i as u8; 16],
            response: vec![(i * 2) as u8; 16],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() - (i as u64 * 3600),
        };
        challenges.push(challenge);
    }

    // Create merkle proof
    let merkle_proof = vec![
        Hash::from_bytes(&hash_blake3(b"merkle_root_1")),
        Hash::from_bytes(&hash_blake3(b"merkle_root_2")),
    ];

    let storage_proof = StorageProof::new(
        validator_hash,
        storage_capacity,
        utilization,
        challenges,
        merkle_proof,
    )?;

    assert_eq!(storage_proof.storage_capacity, storage_capacity);
    assert_eq!(storage_proof.utilization, utilization);
    assert_eq!(storage_proof.challenges_passed.len(), 3);
    assert_eq!(storage_proof.merkle_proof.len(), 2);

    // Test verification
    assert!(storage_proof.verify()?);

    Ok(())
}

#[test]
fn test_storage_proof_insufficient_capacity() -> Result<()> {
    let validator_hash = Hash::from_bytes(&hash_blake3(b"validator_bob"));
    let insufficient_capacity = 50 * 1024 * 1024 * 1024; // 50 GB (below minimum)
    let utilization = 75;
    let challenges = Vec::new();
    let merkle_proof = Vec::new();

    let storage_proof = StorageProof::new(
        validator_hash,
        insufficient_capacity,
        utilization,
        challenges,
        merkle_proof,
    )?;

    // Verification should fail due to insufficient capacity
    let result = storage_proof.verify()?;
    assert!(!result); // Should return false for insufficient storage

    Ok(())
}

#[test]
fn test_storage_proof_invalid_utilization() -> Result<()> {
    let validator_hash = Hash::from_bytes(&hash_blake3(b"validator_charlie"));
    let storage_capacity = 200 * 1024 * 1024 * 1024;
    let invalid_utilization = 105; // > 100%
    let challenges = Vec::new();
    let merkle_proof = Vec::new();

    let result = StorageProof::new(
        validator_hash,
        storage_capacity,
        invalid_utilization,
        challenges,
        merkle_proof,
    );

    // Construction should fail due to invalid utilization
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("utilization"));

    Ok(())
}

#[test]
fn test_work_proof_creation_and_verification() -> Result<()> {
    let routing_work = 1000;
    let storage_work = 2000;
    let compute_work = 1500;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let node_id = [42u8; 32];

    let work_proof = WorkProof::new(routing_work, storage_work, compute_work, timestamp, node_id)?;

    assert_eq!(work_proof.routing_work, routing_work);
    assert_eq!(work_proof.storage_work, storage_work);
    assert_eq!(work_proof.compute_work, compute_work);
    assert!(work_proof.quality_score > 0.0);
    assert!(work_proof.quality_score <= 1.0);

    // Test verification
    assert!(work_proof.verify()?);

    // Test total work calculation
    let total_work = work_proof.total_work();
    assert_eq!(total_work, routing_work + storage_work + compute_work);

    Ok(())
}

#[test]
fn test_work_proof_balanced_distribution() -> Result<()> {
    // Test perfectly balanced work distribution
    let balanced_work = 1000;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let node_id = [1u8; 32];

    let balanced_proof = WorkProof::new(
        balanced_work,
        balanced_work,
        balanced_work,
        timestamp,
        node_id,
    )?;

    // Test unbalanced work distribution
    let unbalanced_proof = WorkProof::new(
        3000, // All routing work
        0, 0, timestamp, [2u8; 32],
    )?;

    // Balanced work should have higher quality score
    assert!(balanced_proof.quality_score > unbalanced_proof.quality_score);

    Ok(())
}

#[test]
fn test_proof_of_useful_work_creation() -> Result<()> {
    let routing_work = 2000;
    let storage_work = 1500;
    let compute_work = 1000;
    let node_id = [99u8; 32];

    let proof = ProofOfUsefulWork::new(routing_work, storage_work, compute_work, node_id)?;

    assert_eq!(proof.routing_work, routing_work);
    assert_eq!(proof.storage_work, storage_work);
    assert_eq!(proof.compute_work, compute_work);
    assert_eq!(proof.node_id, node_id);
    assert!(proof.difficulty > 0);
    assert!(proof.timestamp > 0);

    Ok(())
}

#[test]
fn test_proof_of_useful_work_verification() -> Result<()> {
    let node_id = [55u8; 32];
    let network_state = create_test_network_state();

    // Get the actual work values from network state to match what verification expects
    let actual_routing_work = network_state.get_node_routing_work(&node_id)?;
    let storage_proofs = network_state.get_node_storage_proofs(&node_id)?;
    let total_storage_work: u64 = storage_proofs
        .iter()
        .map(|proof| proof.storage_capacity * proof.utilization / 100)
        .sum();
    let compute_results = network_state.get_node_compute_results(&node_id)?;
    let total_compute_work: u64 = compute_results
        .iter()
        .filter(|result| result.verify().unwrap_or(false))
        .map(|result| result.work_units)
        .sum();

    let proof = ProofOfUsefulWork::new(
        actual_routing_work,
        total_storage_work,
        total_compute_work,
        node_id,
    )?;

    let is_valid = proof.verify(&network_state)?;

    // Should be valid for test network state
    assert!(is_valid);

    Ok(())
}

#[test]
fn test_proof_difficulty_calculation() -> Result<()> {
    let high_work_proof = ProofOfUsefulWork::new(10000, 10000, 10000, [1u8; 32])?;

    let low_work_proof = ProofOfUsefulWork::new(100, 100, 100, [2u8; 32])?;

    // Higher work should result in lower difficulty requirement
    assert!(high_work_proof.difficulty < low_work_proof.difficulty);

    Ok(())
}

#[test]
fn test_work_score_calculation() -> Result<()> {
    let high_quality_proof = ProofOfUsefulWork::new(
        2000, // Balanced work
        2000, 2000, [1u8; 32],
    )?;

    let low_quality_proof = ProofOfUsefulWork::new(
        6000, // Unbalanced work (all routing)
        0, 0, [2u8; 32],
    )?;

    let high_score = high_quality_proof.get_work_score();
    let low_score = low_quality_proof.get_work_score();

    // Balanced work should get better score despite same total work
    assert!(high_score > low_score);

    Ok(())
}

#[test]
fn test_compute_result_verification() -> Result<()> {
    let compute_result = ComputeResult {
        node_id: [42u8; 32],
        work_units: 1000,
        computation_hash: hash_blake3(b"computation_data"),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        signature: vec![1, 2, 3, 4, 5],
    };

    assert!(compute_result.verify()?);

    Ok(())
}

#[test]
fn test_compute_result_verification_failure() -> Result<()> {
    let invalid_result = ComputeResult {
        node_id: [42u8; 32],
        work_units: 0, // Invalid: no work done
        computation_hash: [0u8; 32],
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        signature: Vec::new(), // Invalid: empty signature
    };

    assert!(!invalid_result.verify()?);

    Ok(())
}

#[test]
fn test_storage_challenge_creation() {
    let challenge = StorageChallenge {
        id: Hash::from_bytes(&hash_blake3(b"challenge_id")),
        content_hash: Hash::from_bytes(&hash_blake3(b"content")),
        challenge: vec![1, 2, 3, 4],
        response: vec![5, 6, 7, 8],
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    assert!(!challenge.challenge.is_empty());
    assert!(!challenge.response.is_empty());
    assert!(challenge.timestamp > 0);
}

#[test]
fn test_network_state_node_queries() -> Result<()> {
    let network_state = create_test_network_state();
    let node_id = [42u8; 32];

    // Test routing work query
    let routing_work = network_state.get_node_routing_work(&node_id)?;
    assert!(routing_work > 0);

    // Test storage proofs query
    let storage_proofs = network_state.get_node_storage_proofs(&node_id)?;
    assert!(!storage_proofs.is_empty());

    // Test compute results query
    let compute_results = network_state.get_node_compute_results(&node_id)?;
    assert!(!compute_results.is_empty());

    Ok(())
}

#[test]
fn test_proof_edge_cases() -> Result<()> {
    let node_id = [0u8; 32];

    // Test zero work proof
    let zero_work_proof = ProofOfUsefulWork::new(0, 0, 0, node_id)?;
    assert_eq!(zero_work_proof.difficulty, u32::MAX);

    // Test single type work
    let routing_only_proof = ProofOfUsefulWork::new(1000, 0, 0, node_id)?;
    assert!(routing_only_proof.work_proof.quality_score < 1.0);

    let storage_only_proof = ProofOfUsefulWork::new(0, 1000, 0, node_id)?;
    assert!(storage_only_proof.work_proof.quality_score < 1.0);

    let compute_only_proof = ProofOfUsefulWork::new(0, 0, 1000, node_id)?;
    assert!(compute_only_proof.work_proof.quality_score < 1.0);

    Ok(())
}
