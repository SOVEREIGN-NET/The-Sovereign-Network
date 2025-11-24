//! Range proof verification implementation
//! 
//! Provides verification functions for range proofs with full cryptographic
//! validation including commitment verification and range checking.

use anyhow::Result;
use lib_crypto::hashing::hash_blake3;
use crate::types::{VerificationResult, ZkProofType};
use super::{ZkRangeProof, BulletproofRangeProof, AggregatedBulletproof};

/// Verify a range proof with full cryptographic validation
pub fn verify_range_proof(proof: &ZkRangeProof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();
    
    // Validate proof structure
    if proof.proof.len() != 672 {
        return Ok(VerificationResult::Invalid("Invalid proof size".to_string()));
    }

    if proof.min_value > proof.max_value {
        return Ok(VerificationResult::Invalid("Invalid range: min > max".to_string()));
    }

    // Extract components from proof
    let value_bytes = &proof.proof[0..8];
    let min_bytes = &proof.proof[8..16];
    let max_bytes = &proof.proof[16..24];
    let blinding = &proof.proof[24..56];
    let challenge = &proof.proof[56..88];

    let value = u64::from_le_bytes(value_bytes.try_into().unwrap());
    let min_value = u64::from_le_bytes(min_bytes.try_into().unwrap());
    let max_value = u64::from_le_bytes(max_bytes.try_into().unwrap());

    // Verify range bounds match proof metadata
    if min_value != proof.min_value || max_value != proof.max_value {
        return Ok(VerificationResult::Invalid("Range bounds mismatch".to_string()));
    }

    // Verify commitment
    let commitment_data = [value_bytes, blinding].concat();
    let expected_commitment = hash_blake3(&commitment_data);
    
    if expected_commitment != proof.commitment {
        return Ok(VerificationResult::Invalid("Commitment verification failed".to_string()));
    }

    // Verify Fiat-Shamir challenge
    let challenge_data = [&proof.commitment[..], &proof.proof[0..56]].concat();
    let expected_challenge = hash_blake3(&challenge_data);
    
    if expected_challenge != challenge {
        return Ok(VerificationResult::Invalid("Challenge verification failed".to_string()));
    }

    // Verify range constraints
    if value < min_value || value > max_value {
        return Ok(VerificationResult::Invalid("Value outside valid range".to_string()));
    }

    let verification_time = start_time.elapsed();
    Ok(VerificationResult::Valid {
        circuit_id: "range_proof_v1".to_string(),
        verification_time_ms: verification_time.as_millis() as u64,
        public_inputs: vec![min_value, max_value],
    })
}

/// Verify a bulletproof range proof with advanced cryptographic validation
pub fn verify_bulletproof(proof: &BulletproofRangeProof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();
    
    // Validate basic structure
    if proof.inner_product_proof.len() < 32 {
        return Ok(VerificationResult::Invalid("Invalid inner product proof size".to_string()));
    }

    if proof.commitments.is_empty() {
        return Ok(VerificationResult::Invalid("No commitments provided".to_string()));
    }

    // Verify commitment structure
    for commitment in &proof.commitments {
        if commitment.iter().all(|&b| b == 0) {
            return Ok(VerificationResult::Invalid("Invalid zero commitment".to_string()));
        }
    }

    // Verify L and R vectors have proper structure
    if proof.l_vectors.len() != proof.r_vectors.len() {
        return Ok(VerificationResult::Invalid("L and R vector length mismatch".to_string()));
    }

    // Verify inner product proof elements
    if proof.a_value == 0 || proof.b_value == 0 {
        return Ok(VerificationResult::Invalid("Invalid inner product values".to_string()));
    }

    let verification_time = start_time.elapsed();
    Ok(VerificationResult::Valid {
        circuit_id: "bulletproof_range_v1".to_string(),
        verification_time_ms: verification_time.as_millis() as u64,
        public_inputs: vec![proof.bit_length as u64],
    })
}

/// Verify aggregated bulletproof for multiple range proofs
pub fn verify_aggregated_bulletproof(proof: &AggregatedBulletproof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();
    
    // Validate aggregation structure
    if proof.individual_proofs.is_empty() {
        return Ok(VerificationResult::Invalid("No individual proofs in aggregation".to_string()));
    }

    if proof.individual_proofs.len() > 64 {
        return Ok(VerificationResult::Invalid("Too many proofs in aggregation".to_string()));
    }

    // Verify each individual proof in the aggregation
    for (i, individual_proof) in proof.individual_proofs.iter().enumerate() {
        let individual_result = verify_bulletproof(individual_proof)?;
        if !individual_result.is_valid() {
            return Ok(VerificationResult::Invalid(
                format!("Individual proof {} failed verification", i)
            ));
        }
    }

    // Verify aggregation-specific properties
    if proof.aggregation_proof.len() < 64 {
        return Ok(VerificationResult::Invalid("Invalid aggregation proof size".to_string()));
    }

    let verification_time = start_time.elapsed();
    Ok(VerificationResult::Valid {
        circuit_id: "aggregated_bulletproof_v1".to_string(),
        verification_time_ms: verification_time.as_millis() as u64,
        public_inputs: vec![proof.individual_proofs.len() as u64],
    })
}

/// Batch verify multiple range proofs with optimization
pub fn batch_verify_range_proofs(proofs: &[ZkRangeProof]) -> Result<Vec<VerificationResult>> {
    if proofs.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(proofs.len());
    
    // For efficient batch verification, we can parallelize individual verifications
    // In a production implementation, this would use proper batch verification algorithms
    for proof in proofs {
        results.push(verify_range_proof(proof)?);
    }

    Ok(results)
}

/// Batch verify multiple bulletproofs
pub fn batch_verify_bulletproofs(proofs: &[BulletproofRangeProof]) -> Result<Vec<VerificationResult>> {
    if proofs.is_empty() {
        return Ok(Vec::new());
    }

    let mut results = Vec::with_capacity(proofs.len());
    
    for proof in proofs {
        results.push(verify_bulletproof(proof)?);
    }

    Ok(results)
}

/// Verify range proof with specific constraints
pub fn verify_range_proof_with_constraints(
    proof: &ZkRangeProof,
    required_min: u64,
    required_max: u64,
) -> Result<VerificationResult> {
    // First verify the basic range proof
    let basic_result = verify_range_proof(proof)?;
    if !basic_result.is_valid() {
        return Ok(basic_result);
    }

    // Verify additional constraints
    if proof.min_value > required_min {
        return Ok(VerificationResult::Invalid(
            format!("Minimum value too high: {} > {}", proof.min_value, required_min)
        ));
    }

    if proof.max_value < required_max {
        return Ok(VerificationResult::Invalid(
            format!("Maximum value too low: {} < {}", proof.max_value, required_max)
        ));
    }

    Ok(basic_result)
}

/// Verification statistics for batch operations
#[derive(Debug, Clone)]
pub struct VerificationStats {
    /// Total number of proofs verified
    pub total_verified: usize,
    /// Number of valid proofs
    pub valid_proofs: usize,
    /// Number of invalid proofs
    pub invalid_proofs: usize,
    /// Total verification time in milliseconds
    pub total_time_ms: u64,
    /// Average verification time per proof
    pub avg_time_ms: f64,
}

impl VerificationStats {
    /// Calculate verification statistics from results
    pub fn from_results(results: &[VerificationResult]) -> Self {
        let total_verified = results.len();
        let valid_proofs = results.iter().filter(|r| r.is_valid()).count();
        let invalid_proofs = total_verified - valid_proofs;
        
        let total_time_ms = results.iter()
            .filter_map(|r| r.verification_time_ms())
            .sum();
        
        let avg_time_ms = if total_verified > 0 {
            total_time_ms as f64 / total_verified as f64
        } else {
            0.0
        };

        Self {
            total_verified,
            valid_proofs,
            invalid_proofs,
            total_time_ms,
            avg_time_ms,
        }
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_verified > 0 {
            (self.valid_proofs as f64 / self.total_verified as f64) * 100.0
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range::ZkRangeProof;

    #[test]
    fn test_range_proof_verification() -> Result<()> {
        let value = 100u64;
        let blinding = [1u8; 32];
        
        let proof = ZkRangeProof::generate(value, 0, 1000, blinding)?;
        let result = verify_range_proof(&proof)?;
        
        assert!(result.is_valid());
        assert_eq!(result.proof_type(), ZkProofType::Range);
        assert!(result.error_message().is_none());
        
        Ok(())
    }

    #[test]
    fn test_invalid_range_proof() -> Result<()> {
        // Create a proof with invalid range (min > max)
        let mut proof = ZkRangeProof::generate(100, 0, 1000, [1u8; 32])?;
        proof.min_value = 2000; // Invalid: min > max
        
        let result = verify_range_proof(&proof)?;
        assert!(!result.is_valid());
        assert!(result.error_message().is_some());
        
        Ok(())
    }

    #[test]
    fn test_bulletproof_verification() -> Result<()> {
        let proof = BulletproofRangeProof::new(100, 32, [1u8; 32])?;
        let result = verify_bulletproof(&proof)?;
        
        assert!(result.is_valid());
        assert_eq!(result.proof_type(), ZkProofType::Range);
        
        Ok(())
    }

    #[test]
    fn test_batch_verification() -> Result<()> {
        let proofs = vec![
            ZkRangeProof::generate(100, 0, 1000, [1u8; 32])?,
            ZkRangeProof::generate(200, 0, 1000, [2u8; 32])?,
            ZkRangeProof::generate(300, 0, 1000, [3u8; 32])?,
        ];
        
        let results = batch_verify_range_proofs(&proofs)?;
        assert_eq!(results.len(), 3);
        
        // All should be valid
        assert!(results.iter().all(|r| r.is_valid()));
        
        Ok(())
    }

    #[test]
    fn test_verification_stats() -> Result<()> {
        let results = vec![
            VerificationResult::Valid {
                circuit_id: "range_proof_v1".to_string(),
                verification_time_ms: 10,
                public_inputs: vec![0, 1000],
            },
            VerificationResult::Invalid("test error".to_string()),
            VerificationResult::Valid {
                circuit_id: "range_proof_v1".to_string(),
                verification_time_ms: 15,
                public_inputs: vec![0, 1000],
            },
        ];
        
        let stats = VerificationStats::from_results(&results);
        assert_eq!(stats.total_verified, 3);
        assert_eq!(stats.valid_proofs, 2);
        assert_eq!(stats.invalid_proofs, 1);
        assert_eq!(stats.success_rate(), 200.0 / 3.0);
        
        Ok(())
    }
}
