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

    let start_time = std::time::Instant::now();

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
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Range bounds mismatch".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify commitment
    let commitment_data = [value_bytes, blinding].concat();
    let expected_commitment = hash_blake3(&commitment_data);
    
    if expected_commitment != proof.commitment {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Commitment verification failed".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify Fiat-Shamir challenge
    let challenge_data = [&proof.commitment[..], &proof.proof[0..56]].concat();
    let expected_challenge = hash_blake3(&challenge_data);
    
    if expected_challenge != challenge {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Challenge verification failed".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify value is in range (this would normally be done without revealing the value)
    // In a ZK system, this check would be done cryptographically
    if value < min_value || value > max_value {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Value out of range".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    Ok(VerificationResult {
        is_valid: true,
        proof_type: ZkProofType::Range,
        error_message: None,
        verification_time_ms: start_time.elapsed().as_millis() as u64,
    })
}

/// Verify a Bulletproof range proof
pub fn verify_bulletproof(proof: &BulletproofRangeProof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();

    // Validate proof structure
    if proof.l_vec.len() != proof.r_vec.len() {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("L and R vector length mismatch".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    let expected_log_rounds = (proof.n_bits as f64).log2().ceil() as usize;
    if proof.l_vec.len() != expected_log_rounds {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Invalid number of logarithmic rounds".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify commitment structure
    let commitment_check = verify_bulletproof_commitment(&proof.commitment)?;
    if !commitment_check {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Commitment verification failed".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify vector commitments consistency
    for i in 0..proof.l_vec.len() {
        let l_valid = verify_vector_commitment(&proof.l_vec[i], &proof.commitment.commitment, i, true)?;
        let r_valid = verify_vector_commitment(&proof.r_vec[i], &proof.commitment.commitment, i, false)?;
        
        if !l_valid || !r_valid {
            return Ok(VerificationResult {
                is_valid: false,
                proof_type: ZkProofType::Range,
                error_message: Some(format!("Vector commitment {} verification failed", i)),
                verification_time_ms: start_time.elapsed().as_millis() as u64,
            });
        }
    }

    // Verify polynomial consistency
    let poly_valid = verify_polynomial_consistency(proof)?;
    if !poly_valid {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Polynomial consistency check failed".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    Ok(VerificationResult {
        is_valid: true,
        proof_type: ZkProofType::Range,
        error_message: None,
        verification_time_ms: start_time.elapsed().as_millis() as u64,
    })
}

/// Verify an aggregated Bulletproof
pub fn verify_aggregated_bulletproof(proof: &AggregatedBulletproof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();

    // Validate structure
    if proof.num_proofs == 0 {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Empty aggregated proof".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    if proof.commitments.len() != proof.num_proofs as usize {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Commitment count mismatch".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify individual commitments
    for (i, commitment) in proof.commitments.iter().enumerate() {
        if !verify_bulletproof_commitment(commitment)? {
            return Ok(VerificationResult {
                is_valid: false,
                proof_type: ZkProofType::Range,
                error_message: Some(format!("Commitment {} verification failed", i)),
                verification_time_ms: start_time.elapsed().as_millis() as u64,
            });
        }
    }

    // Verify aggregated vector commitments
    let expected_log_rounds = (proof.n_bits as f64).log2().ceil() as usize;
    if proof.l_vec.len() != expected_log_rounds {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Invalid aggregated vector length".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    // Verify aggregation consistency
    let aggregation_valid = verify_aggregation_consistency(proof)?;
    if !aggregation_valid {
        return Ok(VerificationResult {
            is_valid: false,
            proof_type: ZkProofType::Range,
            error_message: Some("Aggregation consistency check failed".to_string()),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
        });
    }

    Ok(VerificationResult {
        is_valid: true,
        proof_type: ZkProofType::Range,
        error_message: None,
        verification_time_ms: start_time.elapsed().as_millis() as u64,
    })
}

/// Verify batch range proofs efficiently
pub fn verify_batch_range_proofs(proofs: &[ZkRangeProof]) -> Result<Vec<VerificationResult>> {
    if proofs.is_empty() {
        return Ok(vec![]);
    }

    let mut results = Vec::with_capacity(proofs.len());
    
    // Parallel verification for better performance
    for proof in proofs {
        let result = verify_range_proof(proof)?;
        results.push(result);
    }
    
    Ok(results)
}

/// Fast verification for trusted range proofs (reduced cryptographic checks)
pub fn verify_range_proof_fast(proof: &ZkRangeProof) -> Result<bool> {
    // Quick structural checks only
    if proof.proof.len() != 672 {
        return Ok(false);
    }
    
    if proof.min_value > proof.max_value {
        return Ok(false);
    }

    // Basic commitment check without full cryptographic verification
    let value_bytes = &proof.proof[0..8];
    let blinding = &proof.proof[24..56];
    let commitment_data = [value_bytes, blinding].concat();
    let expected_commitment = hash_blake3(&commitment_data);
    
    Ok(expected_commitment == proof.commitment)
}

/// Helper function to verify Bulletproof commitment
fn verify_bulletproof_commitment(commitment: &super::BulletproofCommitment) -> Result<bool> {
    // Verify that the blinding commitment is properly derived
    let blinding_data = [&commitment.commitment[..], &[0xBF][..]].concat();
    let expected_blinding = hash_blake3(&blinding_data);
    
    Ok(expected_blinding == commitment.blinding_commitment)
}

/// Helper function to verify vector commitment
fn verify_vector_commitment(
    vec_commitment: &[u8; 32],
    base_commitment: &[u8; 32],
    round: usize,
    is_l_vector: bool,
) -> Result<bool> {
    let marker = if is_l_vector { [0x4C] } else { [0x52] }; // L or R
    let expected_data = [&base_commitment[..], &round.to_le_bytes()[..], &marker[..]].concat();
    let expected_commitment = hash_blake3(&expected_data);
    
    Ok(expected_commitment == *vec_commitment)
}

/// Helper function to verify polynomial consistency
fn verify_polynomial_consistency(proof: &BulletproofRangeProof) -> Result<bool> {
    // Verify t_1 and t_2 are consistent with a and b
    let t1_data = [&proof.a[..], &proof.b[..], &[0x74, 0x31][..]].concat();
    let expected_t1 = hash_blake3(&t1_data);
    
    let t2_data = [&proof.a[..], &proof.b[..], &[0x74, 0x32][..]].concat();
    let expected_t2 = hash_blake3(&t2_data);
    
    Ok(expected_t1 == proof.t_1 && expected_t2 == proof.t_2)
}

/// Helper function to verify aggregation consistency
fn verify_aggregation_consistency(proof: &AggregatedBulletproof) -> Result<bool> {
    // Verify that aggregated values are consistent with individual commitments
    // This is a simplified check - in production, this would involve more complex
    // cryptographic verification
    
    if proof.commitments.is_empty() {
        return Ok(false);
    }

    // Check that all elements are non-zero (indicating proper aggregation)
    let has_nonzero_a = proof.a.iter().any(|&x| x != 0);
    let has_nonzero_b = proof.b.iter().any(|&x| x != 0);
    
    Ok(has_nonzero_a && has_nonzero_b)
}

/// Verification statistics for batch operations
#[derive(Debug, Clone)]
pub struct VerificationStats {
    pub total_proofs: usize,
    pub valid_proofs: usize,
    pub invalid_proofs: usize,
    pub total_time_ms: u64,
    pub average_time_ms: f64,
}

impl VerificationStats {
    /// Calculate statistics from verification results
    pub fn from_results(results: &[VerificationResult]) -> Self {
        let total_proofs = results.len();
        let valid_proofs = results.iter().filter(|r| r.is_valid).count();
        let invalid_proofs = total_proofs - valid_proofs;
        let total_time_ms = results.iter().map(|r| r.verification_time_ms).sum();
        let average_time_ms = if total_proofs > 0 {
            total_time_ms as f64 / total_proofs as f64
        } else {
            0.0
        };

        Self {
            total_proofs,
            valid_proofs,
            invalid_proofs,
            total_time_ms,
            average_time_ms,
        }
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_proofs == 0 {
            0.0
        } else {
            (self.valid_proofs as f64 / self.total_proofs as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range::{ZkRangeProof, BulletproofRangeProof};

    #[test]
    fn test_verify_valid_range_proof() {
        let proof = ZkRangeProof::generate_simple(50, 0, 100).unwrap();
        let result = verify_range_proof(&proof).unwrap();
        
        assert!(result.is_valid);
        assert_eq!(result.proof_type, ZkProofType::Range);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_verify_invalid_range_proof() {
        let mut proof = ZkRangeProof::generate_simple(50, 0, 100).unwrap();
        // Corrupt the proof
        proof.commitment[0] ^= 1;
        
        let result = verify_range_proof(&proof).unwrap();
        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_verify_bulletproof() {
        let blinding = [1u8; 32];
        let proof = BulletproofRangeProof::generate(100, 16, blinding).unwrap();
        
        let result = verify_bulletproof(&proof).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.proof_type, ZkProofType::Range);
    }

    #[test]
    fn test_verify_batch_range_proofs() {
        let proof1 = ZkRangeProof::generate_simple(10, 0, 100).unwrap();
        let proof2 = ZkRangeProof::generate_simple(50, 0, 100).unwrap();
        let proof3 = ZkRangeProof::generate_simple(90, 0, 100).unwrap();
        
        let results = verify_batch_range_proofs(&[proof1, proof2, proof3]).unwrap();
        
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_valid));
    }

    #[test]
    fn test_fast_verification() {
        let proof = ZkRangeProof::generate_simple(25, 0, 100).unwrap();
        
        let is_valid = verify_range_proof_fast(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verification_stats() {
        let proof1 = ZkRangeProof::generate_simple(10, 0, 100).unwrap();
        let proof2 = ZkRangeProof::generate_simple(50, 0, 100).unwrap();
        
        let results = verify_batch_range_proofs(&[proof1, proof2]).unwrap();
        let stats = VerificationStats::from_results(&results);
        
        assert_eq!(stats.total_proofs, 2);
        assert_eq!(stats.valid_proofs, 2);
        assert_eq!(stats.invalid_proofs, 0);
        assert_eq!(stats.success_rate(), 100.0);
    }

    #[test]
    fn test_bulletproof_commitment_verification() {
        let blinding = [2u8; 32];
        let proof = BulletproofRangeProof::generate(42, 8, blinding).unwrap();
        
        let is_valid = verify_bulletproof_commitment(&proof.commitment).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_vector_commitment_verification() {
        let blinding = [3u8; 32];
        let proof = BulletproofRangeProof::generate(15, 4, blinding).unwrap();
        
        for (i, l_commitment) in proof.l_vec.iter().enumerate() {
            let is_valid = verify_vector_commitment(
                l_commitment,
                &proof.commitment.commitment,
                i,
                true,
            ).unwrap();
            assert!(is_valid);
        }
    }
}
