// Range prover implementation
use crate::range::BulletproofRangeProof;
use anyhow::Result;

/// Range prover for generating range proofs
pub struct RangeProver {
    pub bit_length: u8,
}

impl RangeProver {
    pub fn new(bit_length: u8) -> Self {
        Self { bit_length }
    }

    pub fn prove_range(&self, value: u64, blinding: [u8; 32]) -> Result<BulletproofRangeProof> {
        BulletproofRangeProof::generate(value, self.bit_length, blinding)
    }
}
