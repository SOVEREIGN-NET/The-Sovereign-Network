//! Zero-knowledge range proof implementation using real Bulletproofs.
//!
//! Replaces the previous fake backend with cryptographic range proofs
//! from the `bulletproofs` crate over Ristretto255.

use crate::types::zk_proof::ZkProof;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Zero-knowledge range proof backed by Bulletproofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkRangeProof {
    /// Proof envelope carrying the Bulletproofs bytes.
    pub proof: ZkProof,
    /// 32-byte compressed Ristretto Pedersen commitment to the shifted value.
    pub commitment: [u8; 32],
    /// Minimum value in the range.
    pub min_value: u64,
    /// Maximum value in the range.
    pub max_value: u64,
}

impl ZkRangeProof {
    /// Generate a Bulletproofs range proof for `value ∈ [min_value, max_value]`.
    pub fn generate(
        value: u64,
        min_value: u64,
        max_value: u64,
        blinding: [u8; 32],
    ) -> Result<Self> {
        let (proof_bytes, commitment) =
            crate::range::bulletproofs::prove_range(value, min_value, max_value, blinding)?;

        let public_inputs = [
            &min_value.to_le_bytes()[..],
            &max_value.to_le_bytes()[..],
        ]
        .concat();

        let proof = ZkProof {
            proof_system: "Bulletproofs".to_string(),
            proof_data: proof_bytes.clone(),
            public_inputs,
            verification_key: vec![],
            backend_proof: None,
            proof: proof_bytes,
            circuit_id: "bulletproofs_range_v1".to_string(),
            circuit_version: 1,
            is_mock: false,
        };

        Ok(ZkRangeProof {
            proof,
            commitment,
            min_value,
            max_value,
        })
    }

    /// Generate a simple range proof with random blinding.
    pub fn generate_simple(value: u64, min_value: u64, max_value: u64) -> Result<Self> {
        use lib_crypto::random::SecureRng;
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();

        Self::generate(value, min_value, max_value, blinding)
    }

    /// Generate proof for positive value (value > 0).
    pub fn generate_positive(value: u64, blinding: [u8; 32]) -> Result<Self> {
        const MAX_POSITIVE: u64 = (1u64 << 63) - 1;
        Self::generate(value, 1, MAX_POSITIVE, blinding)
    }

    /// Generate proof for bounded value with power-of-2 range.
    pub fn generate_bounded_pow2(value: u64, max_bits: u8, blinding: [u8; 32]) -> Result<Self> {
        let max_value = (1u64 << max_bits) - 1;
        Self::generate(value, 0, max_value, blinding)
    }

    /// Verify the range proof using Bulletproofs.
    pub fn verify(&self) -> Result<bool> {
        crate::range::bulletproofs::verify_range(
            &self.proof.proof_data,
            &self.commitment,
            self.min_value,
            self.max_value,
        )
    }

    /// Get the range size.
    pub fn range_size(&self) -> u64 {
        self.max_value - self.min_value + 1
    }

    /// Check if the range is a power of 2.
    pub fn is_power_of_2_range(&self) -> bool {
        let size = self.range_size();
        size > 0 && (size & (size - 1)) == 0
    }

    /// Get the number of bits needed to represent this range.
    pub fn range_bits(&self) -> u32 {
        if self.range_size() == 0 {
            return 0;
        }
        let size = self.range_size();
        if size.is_power_of_two() {
            size.trailing_zeros()
        } else {
            (size - 1).next_power_of_two().trailing_zeros() + 1
        }
    }

    /// Get proof size in bytes.
    pub fn proof_size(&self) -> usize {
        self.proof.proof_data.len()
    }

    /// Check if this proof is using the unified system.
    pub fn is_unified_system(&self) -> bool {
        true
    }

    /// Check if this is a standard bulletproof.
    pub fn is_standard_bulletproof(&self) -> bool {
        true
    }
}

/// Range proof parameters for different bit lengths.
#[derive(Debug, Clone)]
pub struct RangeProofParams {
    pub bit_length: u8,
    pub max_value: u64,
    pub proof_size: usize,
}

impl RangeProofParams {
    /// Get parameters for common bit lengths.
    pub fn for_bits(bits: u8) -> Self {
        let max_value = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };

        // Standard Bulletproof sizes
        let proof_size = match bits {
            1..=8 => 320,
            9..=16 => 384,
            17..=32 => 512,
            33..=64 => 672,
            _ => 672,
        };

        Self {
            bit_length: bits,
            max_value,
            proof_size,
        }
    }

    /// Get parameters for common ranges.
    pub fn for_u8() -> Self {
        Self::for_bits(8)
    }

    pub fn for_u16() -> Self {
        Self::for_bits(16)
    }

    pub fn for_u32() -> Self {
        Self::for_bits(32)
    }

    pub fn for_u64() -> Self {
        Self::for_bits(64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::random::SecureRng;

    #[test]
    fn test_generate_valid_range_proof() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        let proof = ZkRangeProof::generate(100, 0, 1000, blinding).unwrap();
        assert!(proof.verify().unwrap());
        assert_eq!(proof.min_value, 0);
        assert_eq!(proof.max_value, 1000);
    }

    #[test]
    fn test_generate_simple_range_proof() {
        let proof = ZkRangeProof::generate_simple(50, 0, 100).unwrap();
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_generate_positive_proof() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        let proof = ZkRangeProof::generate_positive(500, blinding).unwrap();
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_invalid_range_rejected() {
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        assert!(ZkRangeProof::generate(1500, 0, 1000, blinding).is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let proof = ZkRangeProof::generate_simple(42, 18, 150).unwrap();
        let bytes = serde_json::to_vec(&proof).unwrap();
        let recovered: ZkRangeProof = serde_json::from_slice(&bytes).unwrap();
        assert!(recovered.verify().unwrap());
        assert_eq!(recovered.min_value, 18);
        assert_eq!(recovered.max_value, 150);
    }

    #[test]
    fn test_range_proof_params() {
        let params = RangeProofParams::for_bits(64);
        assert_eq!(params.bit_length, 64);
        assert_eq!(params.proof_size, 672);
    }
}
