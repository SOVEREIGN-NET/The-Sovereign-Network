// Range prover implementation
use crate::range::ZkRangeProof;
use anyhow::Result;

/// Range prover for generating range proofs using the unified ZK backend.
pub struct RangeProver {
    pub bit_length: u8,
}

impl RangeProver {
    pub fn new(bit_length: u8) -> Self {
        Self { bit_length }
    }

    pub fn prove_range(&self, value: u64, blinding: [u8; 32]) -> Result<ZkRangeProof> {
        let max_value = if self.bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_length) - 1
        };
        ZkRangeProof::generate(value, 0, max_value, blinding)
    }
}
