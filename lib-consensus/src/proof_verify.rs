//! Network-state-coupled verification of consensus proofs.
//!
//! Per **CONS-104** / **AD-003**, the proof TYPES (`StakeProof`, `WorkProof`,
//! `ProofOfUsefulWork`) live in `lib_proofs::consensus`. The cross-validator
//! verification that compares a proof against actual node activity stays in
//! lib-consensus because it touches `NetworkState`, `ComputeResult`, and
//! `lib_storage::proofs::StorageCapacityAttestation` — none of which can be
//! pulled into lib-proofs without a dependency cycle.
//!
//! These free functions replace what used to be `impl ProofOfUsefulWork`
//! methods. Same logic, different home — the orphan rule blocks an inherent
//! impl on `ProofOfUsefulWork` from this crate.

use crate::types::{ComputeResult, NetworkState};
use anyhow::Result;
use lib_crypto::{hash_blake3, Hash};
use lib_proofs::consensus::ProofOfUsefulWork;
use lib_storage::proofs::{
    ChallengeResult, StorageCapacityAttestation, StorageChallenge, VerificationResult,
};

/// Full PoUW verification: hash integrity + difficulty + cross-validator
/// checks against `NetworkState` records for routing, storage, and compute work.
pub fn verify_pouw_against_network_state(
    proof: &ProofOfUsefulWork,
    network_state: &NetworkState,
) -> Result<bool> {
    // Self-contained checks first (cheap, no network state needed).
    if !proof.verify_self_contained()? {
        return Ok(false);
    }

    if !verify_routing_work(proof, network_state)? {
        return Ok(false);
    }
    if !verify_storage_work(proof, network_state)? {
        return Ok(false);
    }
    if !verify_compute_work(proof, network_state)? {
        return Ok(false);
    }
    Ok(true)
}

/// Routing-work check: claimed `routing_work` must match the network's
/// observation of this node's routing activity within ±10%.
fn verify_routing_work(proof: &ProofOfUsefulWork, network_state: &NetworkState) -> Result<bool> {
    let actual_routing_work = network_state.get_node_routing_work(&proof.node_id)?;
    let tolerance = actual_routing_work / 10;
    let min_work = actual_routing_work.saturating_sub(tolerance);
    let max_work = actual_routing_work.saturating_add(tolerance);
    Ok(proof.routing_work >= min_work && proof.routing_work <= max_work)
}

/// Storage-work check: claimed `storage_work` must match the sum of
/// (capacity × utilization / 100) across this node's storage attestations,
/// within ±10%.
fn verify_storage_work(proof: &ProofOfUsefulWork, network_state: &NetworkState) -> Result<bool> {
    let storage_proofs = network_state.get_node_storage_proofs(&proof.node_id)?;
    let total_storage_work: u64 = storage_proofs
        .iter()
        .map(|p| p.storage_capacity * p.utilization / 100)
        .sum();
    let tolerance = total_storage_work / 10;
    let min_work = total_storage_work.saturating_sub(tolerance);
    let max_work = total_storage_work.saturating_add(tolerance);
    Ok(proof.storage_work >= min_work && proof.storage_work <= max_work)
}

/// Compute-work check: claimed `compute_work` must match the sum of work
/// units across this node's verified compute results, within ±10%.
fn verify_compute_work(proof: &ProofOfUsefulWork, network_state: &NetworkState) -> Result<bool> {
    let compute_results = network_state.get_node_compute_results(&proof.node_id)?;
    let total_compute_work: u64 = compute_results
        .iter()
        .filter(|result| result.verify().unwrap_or(false))
        .map(|result| result.work_units)
        .sum();
    let tolerance = total_compute_work / 10;
    let min_work = total_compute_work.saturating_sub(tolerance);
    let max_work = total_compute_work.saturating_add(tolerance);
    Ok(proof.compute_work >= min_work && proof.compute_work <= max_work)
}

// =============================================================================
// NetworkState extensions: simulated network records.
//
// These methods MUST live in this crate because `NetworkState` is defined here
// (`lib-consensus/src/types/mod.rs`); the orphan rule prevents lib-proofs from
// adding inherent impls. Production would replace these simulators with reads
// against actual network telemetry.
// =============================================================================

impl NetworkState {
    /// Routing work performed by a node, derived from network bandwidth records.
    pub fn get_node_routing_work(&self, node_id: &[u8; 32]) -> Result<u64> {
        let base_routing = (self.total_bandwidth_shared / self.total_participants).max(1);
        let node_factor = (node_id[0] as u64 % 5) + 1; // 1-5 multiplier
        let routing_work = base_routing * node_factor;
        Ok(routing_work.min(10_000)) // Cap at reasonable maximum
    }

    /// Storage attestations a node has produced.
    pub fn get_node_storage_proofs(
        &self,
        node_id: &[u8; 32],
    ) -> Result<Vec<StorageCapacityAttestation>> {
        let num_proofs = ((node_id[1] as usize % 3) + 1).min(5);
        let mut proofs = Vec::new();

        for i in 0..num_proofs {
            let storage_capacity = 1024 * 1024 * 1024 * ((node_id[i % 32] as u64 % 10) + 1);
            let utilization = 50 + (node_id[(i + 1) % 32] % 40);

            let mut challenges = Vec::new();
            let num_challenges = (node_id[(i + 2) % 32] % 5) + 1;
            for j in 0..num_challenges {
                let content_hash = Hash::from_bytes(&hash_blake3(
                    &[b"content".to_vec(), vec![i as u8, j]].concat(),
                ));
                let challenge = StorageChallenge::new_storage_challenge(
                    content_hash.clone(),
                    (j as usize) % 3,
                    format!("validator-{}", i),
                    3600,
                );
                let proof = lib_storage::proofs::generate_storage_proof(
                    content_hash,
                    &vec![
                        hash_blake3(&[&node_id[..], &[i as u8, 0]].concat()).to_vec(),
                        hash_blake3(&[&node_id[..], &[i as u8, 1]].concat()).to_vec(),
                        hash_blake3(&[&node_id[..], &[i as u8, 2]].concat()).to_vec(),
                    ],
                    challenge.nonce,
                    challenge.block_index.unwrap_or(0),
                    format!("validator-{}", i),
                )?;
                let result = VerificationResult::Valid;
                challenges.push(ChallengeResult {
                    challenge,
                    proof,
                    result,
                });
            }

            let attestation = StorageCapacityAttestation::new(
                Hash::from_bytes(&hash_blake3(
                    &[b"validator", &node_id[..], &[i as u8]].concat(),
                )),
                storage_capacity,
                utilization as u64,
                challenges,
            );
            proofs.push(attestation);
        }
        Ok(proofs)
    }

    /// Compute results performed by a node.
    pub fn get_node_compute_results(&self, node_id: &[u8; 32]) -> Result<Vec<ComputeResult>> {
        let num_results = ((node_id[2] as usize % 4) + 1).min(8);
        let mut results = Vec::new();
        for i in 0..num_results {
            let work_units = 100 + (node_id[i % 32] as u64 * 10);
            let computation_hash =
                hash_blake3(&[&node_id[..], &work_units.to_le_bytes(), &[i as u8]].concat());
            let signature_data =
                [&node_id[..], &computation_hash, &work_units.to_le_bytes()].concat();
            let signature = hash_blake3(&signature_data).to_vec();
            results.push(ComputeResult {
                node_id: *node_id,
                work_units,
                computation_hash,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    - (i as u64 * 1800),
                signature,
            });
        }
        Ok(results)
    }
}
