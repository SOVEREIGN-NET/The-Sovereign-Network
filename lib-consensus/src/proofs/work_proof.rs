//! Proof of Useful Work implementation

use crate::types::NetworkState;
use anyhow::Result;
use lib_crypto::hash_blake3;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Proof of useful work combining routing, storage, and compute
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkProof {
    pub routing_work: u64,
    pub storage_work: u64,
    pub compute_work: u64,
    pub routes_handled: u64,
    pub data_stored: u64,
    pub computations_performed: u64,
    pub quality_score: f64,
    pub uptime_hours: u64,
    pub bandwidth_provided: u64,
    pub hash: [u8; 32],
    pub nonce: u64,
}

/// Proof of Useful Work for ZHTP consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfUsefulWork {
    pub routing_work: u64,
    pub storage_work: u64,
    pub compute_work: u64,
    pub timestamp: u64,
    pub node_id: [u8; 32],
    pub work_proof: WorkProof,
    pub difficulty: u32,
}

impl WorkProof {
    /// Create a new work proof with verifiable metrics
    pub fn new(
        routing_work: u64,
        storage_work: u64,
        compute_work: u64,
        _timestamp: u64,
        _node_id: [u8; 32],
    ) -> Result<Self> {
        // Calculate quality score based on work distribution
        let total_work = routing_work + storage_work + compute_work;
        let quality_score = if total_work > 0 {
            // Balanced work across all categories gets higher quality score
            let routing_ratio = routing_work as f64 / total_work as f64;
            let storage_ratio = storage_work as f64 / total_work as f64;
            let compute_ratio = compute_work as f64 / total_work as f64;

            // Perfect balance (33% each) gives score of 1.0
            let balance_score = 1.0
                - ((routing_ratio - 0.33).abs()
                    + (storage_ratio - 0.33).abs()
                    + (compute_ratio - 0.33).abs())
                    / 2.0;
            balance_score.max(0.1) // Minimum quality score of 0.1
        } else {
            0.0
        };

        // Calculate uptime based on historical data (simplified)
        let uptime_hours = 24; // Default to 24 hours, should be calculated from actual uptime

        // Calculate bandwidth provided (from routing work)
        let bandwidth_provided = routing_work * 1024; // Convert to bytes

        // Generate nonce for proof of work
        let nonce = rand::random::<u64>();

        // Calculate proof hash (without timestamp since it's not stored in WorkProof)
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            routing_work,
            storage_work,
            compute_work,
            quality_score,
            uptime_hours,
            bandwidth_provided,
            nonce
        );
        let hash = hash_blake3(hash_input.as_bytes());

        Ok(WorkProof {
            routing_work,
            storage_work,
            compute_work,
            routes_handled: routing_work / 1000, // Convert to number of routes
            data_stored: storage_work,
            computations_performed: compute_work,
            uptime_hours,
            bandwidth_provided,
            quality_score,
            nonce,
            hash,
        })
    }

    /// Verify the work proof is mathematically correct
    pub fn verify(&self) -> Result<bool> {
        // Recalculate hash to verify integrity using the same format as constructor
        let routing_work = self.routes_handled * 1000; // Convert back to original routing work
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            routing_work,
            self.data_stored,
            self.computations_performed,
            self.quality_score,
            self.uptime_hours,
            self.bandwidth_provided,
            self.nonce
        );
        let expected_hash = hash_blake3(hash_input.as_bytes());

        // Verify hash matches
        Ok(self.hash == expected_hash)
    }

    /// Calculate the total useful work represented by this proof
    pub fn total_work(&self) -> u64 {
        (self.routes_handled * 1000) + self.data_stored + self.computations_performed
    }
}

impl ProofOfUsefulWork {
    /// Create a new proof of useful work with comprehensive validation
    pub fn new(
        routing_work: u64,
        storage_work: u64,
        compute_work: u64,
        node_id: [u8; 32],
    ) -> Result<Self> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Calculate difficulty based on total work
        let total_work = routing_work + storage_work + compute_work;
        let difficulty = Self::calculate_difficulty(total_work);

        // Create comprehensive work proof with verifiable metrics
        let work_proof =
            WorkProof::new(routing_work, storage_work, compute_work, timestamp, node_id)?;

        Ok(ProofOfUsefulWork {
            routing_work,
            storage_work,
            compute_work,
            timestamp,
            node_id,
            work_proof,
            difficulty,
        })
    }

    /// Verify that the proof of useful work is valid and actually represents useful work
    pub fn verify(&self, network_state: &NetworkState) -> Result<bool> {
        // Verify work proof integrity
        if !self.work_proof.verify()? {
            return Ok(false);
        }

        // Verify routing work against network records
        if !self.verify_routing_work(network_state)? {
            return Ok(false);
        }

        // Verify storage work against storage proofs
        if !self.verify_storage_work(network_state)? {
            return Ok(false);
        }

        // Verify compute work against computation results
        if !self.verify_compute_work(network_state)? {
            return Ok(false);
        }

        // Verify difficulty meets target
        let total_work = self.routing_work + self.storage_work + self.compute_work;
        let expected_difficulty = Self::calculate_difficulty(total_work);
        if self.difficulty != expected_difficulty {
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate difficulty based on total work performed
    fn calculate_difficulty(total_work: u64) -> u32 {
        // Higher work results in lower difficulty requirement
        if total_work == 0 {
            return u32::MAX;
        }

        // Logarithmic difficulty scaling
        let difficulty = (1_000_000u64 / (total_work + 1)).min(u32::MAX as u64) as u32;
        difficulty.max(1) // Minimum difficulty of 1
    }

    /// Verify routing work against network records
    fn verify_routing_work(&self, network_state: &NetworkState) -> Result<bool> {
        // Get actual routing work from network state
        let actual_routing_work = network_state.get_node_routing_work(&self.node_id)?;

        // Allow some tolerance for measurement differences
        let tolerance = actual_routing_work / 10; // 10% tolerance
        let min_work = actual_routing_work.saturating_sub(tolerance);
        let max_work = actual_routing_work.saturating_add(tolerance);

        Ok(self.routing_work >= min_work && self.routing_work <= max_work)
    }

    /// Verify storage work against storage proofs
    fn verify_storage_work(&self, network_state: &NetworkState) -> Result<bool> {
        // Get storage proofs from network state
        let storage_proofs = network_state.get_node_storage_proofs(&self.node_id)?;

        // Calculate total verified storage work
        let total_storage_work: u64 = storage_proofs
            .iter()
            .map(|proof| proof.storage_capacity * proof.utilization / 100)
            .sum();

        // Allow some tolerance
        let tolerance = total_storage_work / 10;
        let min_work = total_storage_work.saturating_sub(tolerance);
        let max_work = total_storage_work.saturating_add(tolerance);

        Ok(self.storage_work >= min_work && self.storage_work <= max_work)
    }

    /// Verify compute work against computation results
    fn verify_compute_work(&self, network_state: &NetworkState) -> Result<bool> {
        // Get compute results from network state
        let compute_results = network_state.get_node_compute_results(&self.node_id)?;

        // Calculate total verified compute work
        let total_compute_work: u64 = compute_results
            .iter()
            .filter(|result| result.verify().unwrap_or(false))
            .map(|result| result.work_units)
            .sum();

        // Allow some tolerance
        let tolerance = total_compute_work / 10;
        let min_work = total_compute_work.saturating_sub(tolerance);
        let max_work = total_compute_work.saturating_add(tolerance);

        Ok(self.compute_work >= min_work && self.compute_work <= max_work)
    }

    /// Get the total work score for this proof
    pub fn get_work_score(&self) -> f64 {
        let total_work = self.routing_work + self.storage_work + self.compute_work;

        // Calculate score based on work amount and quality
        let base_score = (total_work as f64).sqrt();
        let quality_multiplier = self.work_proof.quality_score;

        base_score * quality_multiplier
    }
}

impl NetworkState {
    /// Get routing work performed by a node from network records
    pub fn get_node_routing_work(&self, node_id: &[u8; 32]) -> Result<u64> {
        // In production, this would query actual network routing data
        // For now, simulate based on network participation metrics
        let base_routing = (self.total_bandwidth_shared / self.total_participants).max(1);

        // Add some variation based on node ID for realistic simulation
        let node_factor = (node_id[0] as u64 % 5) + 1; // 1-5 multiplier
        let routing_work = base_routing * node_factor;

        Ok(routing_work.min(10000)) // Cap at reasonable maximum
    }

    /// Get storage proofs for a node from the network
    pub fn get_node_storage_proofs(&self, node_id: &[u8; 32]) -> Result<Vec<super::StorageProof>> {
        use super::{StorageChallenge, StorageProof};
        use lib_crypto::Hash;

        // Simulate realistic storage proofs based on network state
        let num_proofs = ((node_id[1] as usize % 3) + 1).min(5); // 1-3 storage proofs
        let mut proofs = Vec::new();

        for i in 0..num_proofs {
            let storage_capacity = 1024 * 1024 * 1024 * ((node_id[i % 32] as u64 % 10) + 1); // 1-10 GB
            let utilization = 50 + (node_id[(i + 1) % 32] % 40); // 50-90% utilization

            // Create realistic storage challenges
            let mut challenges = Vec::new();
            let num_challenges = (node_id[(i + 2) % 32] % 5) + 1; // 1-5 challenges

            for j in 0..num_challenges {
                let challenge = StorageChallenge {
                    id: Hash::from_bytes(&lib_crypto::hash_blake3(
                        &[&node_id[..], &[i as u8, j]].concat(),
                    )),
                    content_hash: Hash::from_bytes(&lib_crypto::hash_blake3(
                        &[b"content".to_vec(), vec![i as u8, j]].concat(),
                    )),
                    challenge: vec![i as u8, j, node_id[j as usize % 32]],
                    response: vec![
                        (i as u8)
                            .wrapping_add(j)
                            .wrapping_add(node_id[j as usize % 32]),
                        j.wrapping_mul(2),
                        node_id[(j as usize + 1) % 32],
                    ],
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - (j as u64 * 3600), // Challenges from last few hours
                };
                challenges.push(challenge);
            }

            let proof = StorageProof {
                validator: Hash::from_bytes(&lib_crypto::hash_blake3(
                    &[b"validator", &node_id[..], &[i as u8]].concat(),
                )),
                storage_capacity,
                utilization: utilization as u64,
                challenges_passed: challenges,
                merkle_proof: vec![Hash::from_bytes(&lib_crypto::hash_blake3(
                    &[b"merkle_root", &node_id[..], &[i as u8]].concat(),
                ))],
            };
            proofs.push(proof);
        }

        Ok(proofs)
    }

    /// Get compute results performed by a node
    pub fn get_node_compute_results(
        &self,
        node_id: &[u8; 32],
    ) -> Result<Vec<crate::types::ComputeResult>> {
        use crate::types::ComputeResult;

        // Simulate realistic compute results based on node capabilities
        let num_results = ((node_id[2] as usize % 4) + 1).min(8); // 1-4 compute results
        let mut results = Vec::new();

        for i in 0..num_results {
            let work_units = 100 + (node_id[i % 32] as u64 * 10); // Variable work units
            let computation_hash = lib_crypto::hash_blake3(
                &[&node_id[..], &work_units.to_le_bytes(), &[i as u8]].concat(),
            );

            // Create signature based on computation
            let signature_data =
                [&node_id[..], &computation_hash, &work_units.to_le_bytes()].concat();
            let signature = lib_crypto::hash_blake3(&signature_data).to_vec();

            let result = ComputeResult {
                node_id: *node_id,
                work_units,
                computation_hash,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - (i as u64 * 1800), // Results from last few hours
                signature,
            };
            results.push(result);
        }

        Ok(results)
    }
}
