//! Proof systems for ZHTP consensus

pub mod stake_proof;
pub mod work_proof;

pub use lib_storage::proofs::{
    ChallengeResult, ProofVerifier, RetrievalProof, StorageCapacityAttestation, StorageChallenge,
    StorageProof, StorageProofProvider, StorageProofSummary, VerificationResult,
};
pub use stake_proof::*;
pub use work_proof::*;
