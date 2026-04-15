//! Transaction proof verification logic
//!
//! Provides PURE ZK verification functions for transaction proofs using
//! Plonky2 circuits only. NO FALLBACKS ALLOWED.

use crate::transaction::ZkTransactionProof;
use crate::types::VerificationResult;
use anyhow::Result;

/// Verify a transaction proof using the active backend.
pub fn verify_transaction(proof: &ZkTransactionProof) -> Result<bool> {
    proof.verify()
}

/// Verify transaction proof with detailed results
pub fn verify_transaction_detailed(proof: &ZkTransactionProof) -> VerificationResult {
    match verify_transaction(proof) {
        Ok(true) => VerificationResult::Valid {
            circuit_id: "transaction".to_string(),
            verification_time_ms: 0,
            public_inputs: vec![],
        },
        Ok(false) => VerificationResult::Invalid("Transaction constraints violated".to_string()),
        Err(e) => VerificationResult::Error(e.to_string()),
    }
}

/// REMOVED: Fallback verification - pure ZK only
/// This function is no longer used as we enforce ZK-only verification

/// Verify amount proof component using the active backend.
pub fn verify_amount_proof(proof: &ZkTransactionProof) -> Result<bool> {
    proof.amount_proof.verify()
}

/// Verify balance proof component using the active backend.
pub fn verify_balance_proof(proof: &ZkTransactionProof) -> Result<bool> {
    proof.balance_proof.verify()
}

/// Verify nullifier proof component using the active backend.
pub fn verify_nullifier_proof(proof: &ZkTransactionProof) -> Result<bool> {
    proof.nullifier_proof.verify()
}

/// Batch verify multiple transaction proofs
pub fn batch_verify_transactions(proofs: &[ZkTransactionProof]) -> Result<Vec<bool>> {
    let mut results = Vec::with_capacity(proofs.len());

    for proof in proofs {
        results.push(verify_transaction(proof)?);
    }

    Ok(results)
}

/// Check if a transaction proof meets minimum security requirements
pub fn meets_security_requirements(proof: &ZkTransactionProof) -> bool {
    // All proofs MUST use Plonky2 - no fallbacks allowed
    proof.is_plonky2() && !proof.has_empty_proofs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::ZkTransactionProver;
    use crate::types::ZkProof;

    #[test]
    fn test_verify_valid_transaction() {
        let sender_balance = 1000u64;
        let receiver_balance = 500u64;
        let amount = 100u64;
        let fee = 10u64;
        let sender_blinding = [1u8; 32];
        let receiver_blinding = [2u8; 32];
        let nullifier = [3u8; 32];

        let prover = ZkTransactionProver::new().unwrap();
        let proof = prover
            .prove_transaction(
                sender_balance,
                receiver_balance,
                amount,
                fee,
                sender_blinding,
                receiver_blinding,
                nullifier,
            )
            .unwrap();

        let is_valid = verify_transaction(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_transaction_detailed() {
        let proof = ZkTransactionProof::default();

        let result = verify_transaction_detailed(&proof);
        // Default proof should be invalid (empty proofs)
        assert!(result.is_invalid());
    }

    #[test]
    fn test_verify_individual_components() {
        let proof = ZkTransactionProof::default();

        // Components should fail for empty proof
        assert!(!verify_amount_proof(&proof).unwrap());
        assert!(!verify_balance_proof(&proof).unwrap());
        assert!(!verify_nullifier_proof(&proof).unwrap());
    }

    #[test]
    fn test_security_requirements() {
        let empty_proof = ZkTransactionProof::default();
        assert!(!meets_security_requirements(&empty_proof));

        // Create proofs with valid Plonky2 data
        use crate::plonky2::Plonky2Proof;

        let create_valid_plonky2_proof = |circuit_id: &str| -> ZkProof {
            let plonky2 = Plonky2Proof {
                proof: vec![1, 2, 3],
                public_inputs: vec![4, 5, 6],
                verification_key_hash: [7; 32],
                proof_system: "Plonky2".to_string(),
                generated_at: 1234567890,
                circuit_id: circuit_id.to_string(),
                private_input_commitment: [8; 32],
            };

            ZkProof::from_plonky2(plonky2)
        };

        let valid_proof = ZkTransactionProof::new(
            create_valid_plonky2_proof("amount"),
            create_valid_plonky2_proof("balance"),
            create_valid_plonky2_proof("nullifier"),
        );

        assert!(meets_security_requirements(&valid_proof));
    }

    #[test]
    fn test_batch_verification() {
        let prover = ZkTransactionProver::new().unwrap();
        let proof1 = prover.prove_simple_transaction(100, [1u8; 32]).unwrap();
        let proof2 = prover.prove_simple_transaction(200, [2u8; 32]).unwrap();

        let proofs = vec![proof1, proof2];
        let results = batch_verify_transactions(&proofs).unwrap();

        assert_eq!(results.len(), 2);
        // Both should be valid
        assert!(results.iter().all(|&r| r));
    }
}
