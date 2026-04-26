//! Proof of Useful Work types and self-contained verification.
//!
//! Relocated from `lib-consensus/src/proofs/work_proof.rs` per **CONS-104**
//! (epic) and **AD-003** (decisions). Only the data definitions and the
//! self-contained verification (hash-integrity check, difficulty derivation,
//! score) live here. The `verify_against_network_state` chain that depends
//! on `lib_consensus::types::{NetworkState, ComputeResult}` and on
//! `lib_storage::proofs::StorageCapacityAttestation` stays in lib-consensus
//! to avoid pulling those crates into lib-proofs (lib-storage already depends
//! on lib-proofs — adding the reverse would create a cycle).

use anyhow::Result;
use lib_crypto::hash_blake3;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Proof of useful work combining routing, storage, and compute metrics.
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

/// Proof of Useful Work for ZHTP consensus.
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
    /// Create a new work proof with verifiable metrics.
    ///
    /// `node_start_time` is the Unix timestamp (seconds) when the node started.
    /// Uptime is derived from elapsed time since that timestamp, capped at 30 days.
    pub fn new(
        routing_work: u64,
        storage_work: u64,
        compute_work: u64,
        node_start_time: u64,
        _node_id: [u8; 32],
    ) -> Result<Self> {
        // Quality score rewards balanced work distribution across all categories.
        let total_work = routing_work + storage_work + compute_work;
        let quality_score = if total_work > 0 {
            let routing_ratio = routing_work as f64 / total_work as f64;
            let storage_ratio = storage_work as f64 / total_work as f64;
            let compute_ratio = compute_work as f64 / total_work as f64;
            let balance_score = 1.0
                - ((routing_ratio - 0.33).abs()
                    + (storage_ratio - 0.33).abs()
                    + (compute_ratio - 0.33).abs())
                    / 2.0;
            balance_score.max(0.1) // Minimum quality score of 0.1
        } else {
            0.0
        };

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let uptime_secs = now_secs.saturating_sub(node_start_time);
        const MAX_UPTIME_SECS: u64 = 30 * 24 * 3600;
        let uptime_hours = uptime_secs.min(MAX_UPTIME_SECS) / 3600;

        let bandwidth_provided = routing_work * 1024;
        let nonce = rand::random::<u64>();

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
            routes_handled: routing_work / 1000,
            data_stored: storage_work,
            computations_performed: compute_work,
            uptime_hours,
            bandwidth_provided,
            quality_score,
            nonce,
            hash,
        })
    }

    /// Verify the work proof's hash integrity. Self-contained — no network
    /// state lookup. The cross-validator check that compares the claimed work
    /// against actual node activity lives in `lib_consensus::proof_verify`.
    pub fn verify(&self) -> Result<bool> {
        let routing_work = self.routes_handled * 1000;
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
        Ok(self.hash == expected_hash)
    }

    /// Total useful work represented by this proof.
    pub fn total_work(&self) -> u64 {
        (self.routes_handled * 1000) + self.data_stored + self.computations_performed
    }
}

impl ProofOfUsefulWork {
    /// Create a new PoUW with comprehensive validation.
    pub fn new(
        routing_work: u64,
        storage_work: u64,
        compute_work: u64,
        node_id: [u8; 32],
    ) -> Result<Self> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let total_work = routing_work + storage_work + compute_work;
        let difficulty = Self::calculate_difficulty(total_work);
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

    /// Difficulty falls logarithmically with total work — more useful work
    /// = lower bar to clear. Floor of 1, ceiling of u32::MAX.
    pub fn calculate_difficulty(total_work: u64) -> u32 {
        if total_work == 0 {
            return u32::MAX;
        }
        let difficulty = (1_000_000u64 / (total_work + 1)).min(u32::MAX as u64) as u32;
        difficulty.max(1)
    }

    /// Combined work-amount and quality score, used by the reward calculator.
    pub fn get_work_score(&self) -> f64 {
        let total_work = self.routing_work + self.storage_work + self.compute_work;
        let base_score = (total_work as f64).sqrt();
        let quality_multiplier = self.work_proof.quality_score;
        base_score * quality_multiplier
    }

    /// Self-contained verification — checks the embedded `WorkProof` hash
    /// integrity and the difficulty derivation. The cross-validator check
    /// that compares against actual network activity lives in
    /// `lib_consensus::proof_verify::verify_pouw_against_network_state`.
    pub fn verify_self_contained(&self) -> Result<bool> {
        if !self.work_proof.verify()? {
            return Ok(false);
        }
        let total_work = self.routing_work + self.storage_work + self.compute_work;
        let expected_difficulty = Self::calculate_difficulty(total_work);
        Ok(self.difficulty == expected_difficulty)
    }
}
