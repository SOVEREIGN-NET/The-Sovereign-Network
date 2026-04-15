//! Fake/stub implementation of `ProofBackend` for testing and migration.
//!
//! This backend is **only** available when the `fake-proofs` feature is enabled.
//! All prove calls return empty proofs; all verify calls return `Ok(true)`.

use super::{BackendProof, ProofBackend};
use anyhow::Result;

/// Fake backend for tests and development.
pub struct FakeBackend;

impl FakeBackend {
    /// Create a new fake backend.
    pub fn new() -> Self {
        Self
    }

    fn empty_proof(proof_system: &str) -> BackendProof {
        BackendProof {
            proof_system: proof_system.to_string(),
            data: vec![],
        }
    }
}

impl ProofBackend for FakeBackend {
    fn name(&self) -> &str {
        "fake"
    }

    fn prove_transaction(
        &self,
        _sender_balance: u64,
        _amount: u64,
        _fee: u64,
        _sender_secret: u64,
        _nullifier_seed: u64,
        _merkle_root: [u64; 4],
        _leaf_index: u32,
        _merkle_siblings: &[[u64; 4]],
    ) -> Result<BackendProof> {
        Ok(Self::empty_proof("ZHTP-Optimized-Transaction"))
    }

    fn verify_transaction(&self, _proof: &BackendProof) -> Result<bool> {
        Ok(true)
    }

    fn prove_identity(
        &self,
        _identity_secret: u64,
        _age: u64,
        _jurisdiction_hash: u64,
        _credential_hash: u64,
        _min_age: u64,
        _required_jurisdiction: u64,
        _verification_level: u64,
    ) -> Result<BackendProof> {
        Ok(Self::empty_proof("ZHTP-Optimized-Identity"))
    }

    fn verify_identity(&self, _proof: &BackendProof) -> Result<bool> {
        Ok(true)
    }

    fn prove_range(
        &self,
        _value: u64,
        _blinding_factor: u64,
        _min_value: u64,
        _max_value: u64,
    ) -> Result<BackendProof> {
        Ok(Self::empty_proof("ZHTP-Optimized-Range"))
    }

    fn verify_range(&self, _proof: &BackendProof) -> Result<bool> {
        Ok(true)
    }

    fn prove_storage_access(
        &self,
        _access_key: u64,
        _requester_secret: u64,
        _data_hash: u64,
        _permission_level: u64,
        _required_permission: u64,
    ) -> Result<BackendProof> {
        Ok(Self::empty_proof("ZHTP-Optimized-StorageAccess"))
    }

    fn verify_storage_access(&self, _proof: &BackendProof) -> Result<bool> {
        Ok(true)
    }

    fn prove_merkle(
        &self,
        _leaf: [u8; 32],
        _path: &[[u8; 32]],
        _indices: &[bool],
        _root: [u8; 32],
    ) -> Result<BackendProof> {
        Ok(Self::empty_proof("ZHTP-Optimized-Merkle"))
    }

    fn verify_merkle(&self, _proof: &BackendProof, _root: [u8; 32]) -> Result<bool> {
        Ok(true)
    }
}
