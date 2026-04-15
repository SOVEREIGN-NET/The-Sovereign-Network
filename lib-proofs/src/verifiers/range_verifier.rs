// Range verifier implementation
use crate::range::ZkRangeProof;
use crate::types::VerificationResult;
use anyhow::Result;

/// Range verifier for verifying range proofs using the unified ZK backend.
pub struct RangeVerifier;

impl RangeVerifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_range(&self, proof: &ZkRangeProof) -> Result<VerificationResult> {
        crate::range::verification::verify_range_proof(proof)
    }
}
