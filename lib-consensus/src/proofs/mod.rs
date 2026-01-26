//! Proof systems for ZHTP consensus

pub mod stake_proof;
pub mod work_proof;

pub use stake_proof::*;
pub use work_proof::*;
pub use lib_storage::proofs::{
    StorageCapacityAttestation,
    StorageChallenge,
    StorageProof,
    RetrievalProof,
    ProofVerifier,
    VerificationResult,
    StorageProofProvider,
    StorageProofSummary,
    ChallengeResult,
};
