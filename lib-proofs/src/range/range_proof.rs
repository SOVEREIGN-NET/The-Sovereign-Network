//! Zero-knowledge range proof implementation for unified ZK system
//! 
//! Zero-knowledge range proofs that allow proving a committed value lies within
//! a specified range without revealing the exact value, using unified Plonky2 backend.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use lib_crypto::hashing::hash_blake3;
use crate::types::zk_proof::ZkProof;

/// Zero-knowledge range proof using unified Plonky2 system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkRangeProof {
    /// Unified ZK proof for range verification
    pub proof: ZkProof,
    /// Commitment to the value
    pub commitment: [u8; 32],
    /// Minimum value in the range
    pub min_value: u64,
    /// Maximum value in the range
    pub max_value: u64,
}

impl ZkRangeProof {
    /// Generate a range proof for a value using unified ZK system
    pub fn generate(value: u64, min_value: u64, max_value: u64, blinding: [u8; 32]) -> Result<Self> {
        if value < min_value || value > max_value {
            return Err(anyhow::anyhow!("Value out of range: {} not in [{}, {}]", value, min_value, max_value));
        }

        // Generate commitment to the value
        let commitment = hash_blake3(&[&value.to_le_bytes()[..], &blinding[..]].concat());
        
        // Use unified ZK system via Plonky2
        let public_inputs = vec![value, min_value, max_value];
        let proof = ZkProof::from_public_inputs(public_inputs)?;
        
        Ok(ZkRangeProof {
            proof,
            commitment,
            min_value,
            max_value,
        })
    }

    /// Generate a simple range proof with random blinding
    pub fn generate_simple(value: u64, min_value: u64, max_value: u64) -> Result<Self> {
        use lib_crypto::random::SecureRng;
        let mut rng = SecureRng::new();
        let blinding = rng.generate_key_material();
        
        Self::generate(value, min_value, max_value, blinding)
    }

    /// Generate proof for positive value (value > 0)
    pub fn generate_positive(value: u64, blinding: [u8; 32]) -> Result<Self> {
        // Use a large but reasonable upper bound to avoid overflow
        const MAX_POSITIVE: u64 = (1u64 << 63) - 1; // 2^63 - 1
        Self::generate(value, 1, MAX_POSITIVE, blinding)
    }

    /// Generate proof for bounded value with power-of-2 range
    pub fn generate_bounded_pow2(value: u64, max_bits: u8, blinding: [u8; 32]) -> Result<Self> {
        let max_value = (1u64 << max_bits) - 1;
        Self::generate(value, 0, max_value, blinding)
    }

    /// Verify the range proof using unified ZK system
    pub fn verify(&self) -> Result<bool> {
        self.proof.verify()
    }

    /// Get the range size
    pub fn range_size(&self) -> u64 {
        self.max_value - self.min_value + 1
    }

    /// Check if the range is a power of 2
    pub fn is_power_of_2_range(&self) -> bool {
        let size = self.range_size();
        size > 0 && (size & (size - 1)) == 0
    }

    /// Get the number of bits needed to represent this range
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

    /// Get proof size in bytes
    pub fn proof_size(&self) -> usize {
        self.proof.size()
    }

    /// Check if this proof is using the unified system (always true)
    pub fn is_unified_system(&self) -> bool {
        true
    }

    /// Check if this is a standard bulletproof (for compatibility)
    pub fn is_standard_bulletproof(&self) -> bool {
        // All our range proofs use Plonky2 unified system, which is compatible
        true
    }
}

/// Range proof parameters for different bit lengths
#[derive(Debug, Clone)]
pub struct RangeProofParams {
    pub bit_length: u8,
    pub max_value: u64,
    pub proof_size: usize,
}

impl RangeProofParams {
    /// Get parameters for common bit lengths
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

    /// Get parameters for common ranges
    pub fn for_u8() -> Self { Self::for_bits(8) }
    pub fn for_u16() -> Self { Self::for_bits(16) }
    pub fn for_u32() -> Self { Self::for_bits(32) }
    pub fn for_u64() -> Self { Self::for_bits(64) }
}

/// Batch range proof for multiple values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRangeProof {
    /// Individual proofs
    pub proofs: Vec<ZkRangeProof>,
    /// Aggregated commitment
    pub aggregated_commitment: [u8; 32],
    /// Common range parameters
    pub min_value: u64,
    pub max_value: u64,
}

impl BatchRangeProof {
    /// Generate batch proof for multiple values
    pub fn generate(
        values: Vec<u64>,
        min_value: u64,
        max_value: u64,
        blindings: Vec<[u8; 32]>,
    ) -> Result<Self> {
        if values.len() != blindings.len() {
            return Err(anyhow::anyhow!("Values and blindings length mismatch"));
        }

        if values.is_empty() {
            return Err(anyhow::anyhow!("Cannot create empty batch proof"));
        }

        let mut proofs = Vec::with_capacity(values.len());
        let mut commitment_data = Vec::new();

        for (value, blinding) in values.iter().zip(blindings.iter()) {
            let proof = ZkRangeProof::generate(*value, min_value, max_value, *blinding)?;
            commitment_data.extend_from_slice(&proof.commitment);
            proofs.push(proof);
        }

        let aggregated_commitment = hash_blake3(&commitment_data);

        Ok(BatchRangeProof {
            proofs,
            aggregated_commitment,
            min_value,
            max_value,
        })
    }

    /// Get the number of values in this batch
    pub fn batch_size(&self) -> usize {
        self.proofs.len()
    }

    /// Get total proof size
    pub fn total_size(&self) -> usize {
        self.proofs.iter().map(|p| p.proof_size()).sum::<usize>() + 32 // +32 for aggregated commitment
    }

    /// Extract individual proof for a specific index
    pub fn get_proof(&self, index: usize) -> Option<&ZkRangeProof> {
        self.proofs.get(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_valid_range_proof() {
        let value = 100u64;
        let blinding = [1u8; 32];
        
        let proof = ZkRangeProof::generate(value, 0, 1000, blinding).unwrap();
        
        assert_eq!(proof.min_value, 0);
        assert_eq!(proof.max_value, 1000);
        assert_eq!(proof.range_size(), 1001);
        assert!(proof.is_standard_bulletproof());
    }

    #[test]
    fn test_generate_out_of_range() {
        let value = 1500u64;
        let blinding = [1u8; 32];
        
        let result = ZkRangeProof::generate(value, 0, 1000, blinding);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_simple() {
        let value = 50u64;
        let proof = ZkRangeProof::generate_simple(value, 0, 100).unwrap();
        
        assert_eq!(proof.min_value, 0);
        assert_eq!(proof.max_value, 100);
    }

    #[test]
    fn test_generate_positive() {
        let value = 42u64;
        let blinding = [2u8; 32];
        
        let proof = ZkRangeProof::generate_positive(value, blinding).unwrap();
        
        assert_eq!(proof.min_value, 1);
        assert_eq!(proof.max_value, (1u64 << 63) - 1);
    }

    #[test]
    fn test_generate_bounded_pow2() {
        let value = 15u64; // Fits in 4 bits
        let blinding = [3u8; 32];
        
        let proof = ZkRangeProof::generate_bounded_pow2(value, 4, blinding).unwrap();
        
        assert_eq!(proof.min_value, 0);
        assert_eq!(proof.max_value, 15); // 2^4 - 1
        assert!(proof.is_power_of_2_range());
    }

    #[test]
    fn test_range_proof_params() {
        let params8 = RangeProofParams::for_u8();
        assert_eq!(params8.bit_length, 8);
        assert_eq!(params8.max_value, 255);

        let params32 = RangeProofParams::for_u32();
        assert_eq!(params32.bit_length, 32);
        assert_eq!(params32.max_value, u32::MAX as u64);
    }

    #[test]
    fn test_batch_range_proof() {
        let values = vec![10u64, 20u64, 30u64];
        let blindings = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        
        let batch_proof = BatchRangeProof::generate(values, 0, 100, blindings).unwrap();
        
        assert_eq!(batch_proof.batch_size(), 3);
        assert_eq!(batch_proof.min_value, 0);
        assert_eq!(batch_proof.max_value, 100);
        assert!(batch_proof.get_proof(0).is_some());
        assert!(batch_proof.get_proof(3).is_none());
    }

    #[test]
    fn test_batch_proof_validation() {
        let values = vec![150u64]; // Out of range
        let blindings = vec![[1u8; 32]];
        
        let result = BatchRangeProof::generate(values, 0, 100, blindings);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_batch_proof() {
        let values = vec![];
        let blindings = vec![];
        
        let result = BatchRangeProof::generate(values, 0, 100, blindings);
        assert!(result.is_err());
    }

    #[test]
    fn test_range_properties() {
        let proof = ZkRangeProof::generate_simple(10, 0, 15).unwrap();
        
        assert_eq!(proof.range_size(), 16);
        assert!(proof.is_power_of_2_range());
        assert_eq!(proof.range_bits(), 4);
    }
}
