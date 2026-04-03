// Range verifier implementation
use crate::range::{AggregatedBulletproof, BulletproofRangeProof};
use crate::types::VerificationResult;
use anyhow::Result;

/// Range verifier for verifying range proofs
pub struct RangeVerifier;

impl RangeVerifier {
    pub fn new() -> Self {
        Self
    }

    pub fn verify_range(&self, proof: &BulletproofRangeProof) -> Result<VerificationResult> {
        crate::range::verification::verify_bulletproof(proof)
    }

    pub fn verify_aggregated(&self, proof: &AggregatedBulletproof) -> Result<VerificationResult> {
        crate::range::verification::verify_aggregated_bulletproof(proof)
    }
}
