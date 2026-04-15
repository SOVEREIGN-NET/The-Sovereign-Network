//! Backend-agnostic ZK proof abstraction layer.
//!
//! This module defines the `ProofBackend` trait and opaque `BackendProof` type
//! that decouple the rest of the workspace from Plonky2 (or any other concrete
//! ZK library) internals.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

mod plonky2_backend;

#[cfg(feature = "real-proofs")]
pub mod plonky2_spike;

#[cfg(any(test, feature = "fake-proofs"))]
mod fake_backend;

pub use plonky2_backend::Plonky2Backend;

#[cfg(any(test, feature = "fake-proofs"))]
pub use fake_backend::FakeBackend;

/// Opaque backend-specific proof data.
///
/// Downstream crates must not inspect `data`; they should treat it as an
/// opaque blob that only the active `ProofBackend` understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendProof {
    pub proof_system: String,
    pub data: Vec<u8>,
}

/// Unified ZK backend trait.
///
/// Each concrete backend (Plonky2, Halo2, fake/stub, etc.) implements this
/// interface.  The workspace interacts with proofs exclusively through this
/// trait or the high-level wrappers (`ZkTransactionProof`, `ZkIdentityProof`,
/// `ZkRangeProof`).
pub trait ProofBackend: Send + Sync {
    /// Human-readable backend name (e.g. "plonky2", "fake").
    fn name(&self) -> &str;

    /// Generate a transaction proof.
    fn prove_transaction(
        &self,
        sender_balance: u64,
        amount: u64,
        fee: u64,
        sender_secret: u64,
        nullifier_seed: u64,
    ) -> Result<BackendProof>;

    /// Verify a transaction proof.
    fn verify_transaction(&self, proof: &BackendProof) -> Result<bool>;

    /// Generate an identity proof.
    fn prove_identity(
        &self,
        identity_secret: u64,
        age: u64,
        jurisdiction_hash: u64,
        credential_hash: u64,
        min_age: u64,
        required_jurisdiction: u64,
        verification_level: u64,
    ) -> Result<BackendProof>;

    /// Verify an identity proof.
    fn verify_identity(&self, proof: &BackendProof) -> Result<bool>;

    /// Generate a range proof.
    fn prove_range(
        &self,
        value: u64,
        blinding_factor: u64,
        min_value: u64,
        max_value: u64,
    ) -> Result<BackendProof>;

    /// Verify a range proof.
    fn verify_range(&self, proof: &BackendProof) -> Result<bool>;

    /// Generate a storage-access proof.
    fn prove_storage_access(
        &self,
        access_key: u64,
        requester_secret: u64,
        data_hash: u64,
        permission_level: u64,
        required_permission: u64,
    ) -> Result<BackendProof>;

    /// Verify a storage-access proof.
    fn verify_storage_access(&self, proof: &BackendProof) -> Result<bool>;

    /// Generate a Merkle-inclusion proof.
    fn prove_merkle(
        &self,
        leaf: [u8; 32],
        path: &[[u8; 32]],
        indices: &[bool],
        root: [u8; 32],
    ) -> Result<BackendProof>;

    /// Verify a Merkle-inclusion proof.
    fn verify_merkle(&self, proof: &BackendProof, root: [u8; 32]) -> Result<bool>;
}

/// Global singleton returning the active backend.
///
/// Selection rules:
/// * `fake-proofs` feature enabled → `FakeBackend`
/// * otherwise → `Plonky2Backend`
pub fn get_backend() -> &'static dyn ProofBackend {
    static BACKEND: OnceLock<Box<dyn ProofBackend + Send + Sync>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            #[cfg(feature = "fake-proofs")]
            {
                Box::new(FakeBackend::new())
            }
            #[cfg(not(feature = "fake-proofs"))]
            {
                match Plonky2Backend::new() {
                    Ok(backend) => Box::new(backend),
                    Err(e) => {
                        // We panic here because a missing backend in production is
                        // a fatal configuration error.  In tests we can fall back to
                        // FakeBackend via the feature flag.
                        panic!("Failed to initialize Plonky2Backend: {}", e);
                    }
                }
            }
        })
        .as_ref()
}
