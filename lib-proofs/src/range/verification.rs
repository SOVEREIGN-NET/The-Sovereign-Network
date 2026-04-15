//! Range proof verification implementation
//!
//! Provides verification functions for range proofs with full cryptographic
//! validation including commitment verification and range checking.

use crate::types::VerificationResult;
use crate::ZkRangeProof;
use anyhow::Result;

/// Verify a range proof with full cryptographic validation
pub fn verify_range_proof(proof: &ZkRangeProof) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();

    // Use unified ZK proof verification
    match proof.verify() {
        Ok(is_valid) => {
            if is_valid {
                let verification_time = start_time.elapsed();
                Ok(VerificationResult::Valid {
                    circuit_id: "range_proof_unified".to_string(),
                    verification_time_ms: verification_time.as_millis() as u64,
                    public_inputs: vec![proof.min_value, proof.max_value],
                })
            } else {
                Ok(VerificationResult::Invalid(
                    "Unified ZK verification failed".to_string(),
                ))
            }
        }
        Err(e) => Ok(VerificationResult::Invalid(format!(
            "Verification error: {}",
            e
        ))),
    }
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
        return Ok(VerificationResult::Invalid(format!(
            "Minimum value too high: {} > {}",
            proof.min_value, required_min
        )));
    }

    if proof.max_value < required_max {
        return Ok(VerificationResult::Invalid(format!(
            "Maximum value too low: {} < {}",
            proof.max_value, required_max
        )));
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

        let total_time_ms = results
            .iter()
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
    use crate::types::ZkProofType;
    use crate::ZkRangeProof;

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
        // Test 1: Value out of range should fail during generation
        let result1 = ZkRangeProof::generate(1500, 0, 1000, [1u8; 32]);
        assert!(result1.is_err());

        // Test 2: Invalid range (min > max) should fail during generation
        let result2 = ZkRangeProof::generate(100, 2000, 1000, [1u8; 32]);
        assert!(result2.is_err());

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
        let expected_rate = 200.0 / 3.0;
        let actual_rate = stats.success_rate();
        assert!(
            (actual_rate - expected_rate).abs() < 0.001,
            "Expected rate ~{}, got {}",
            expected_rate,
            actual_rate
        );

        Ok(())
    }
}
