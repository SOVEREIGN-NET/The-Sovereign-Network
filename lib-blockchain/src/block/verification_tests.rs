//! BFT quorum proof verification tests
//!
//! These tests cover the security-critical quorum proof verification logic,
//! including validator set size validation and proposal consistency checks.

#[cfg(test)]
mod tests {
    use super::super::*;
    use lib_types::consensus::{BftQuorumProof, CommitAttestation};

    // ====================================================================
    // Test Helpers
    // ====================================================================

    fn create_test_validator_key(id: u8) -> ([u8; 32], [u8; 2592]) {
        let mut validator_id = [0u8; 32];
        validator_id[0] = id;
        
        let mut consensus_key = [0u8; 2592];
        consensus_key[0] = id;
        consensus_key[1] = 0xAA; // Mark as test key
        
        (validator_id, consensus_key)
    }

    fn create_test_attestation(
        validator_id: [u8; 32],
        proposal_id: [u8; 32],
        public_key: [u8; 2592],
    ) -> CommitAttestation {
        CommitAttestation {
            validator_id,
            vote_id: [0u8; 32],
            proposal_id,
            round: 0,
            signature: [0u8; 4595], // Note: invalid signature, tests will fail sig verification
            public_key,
        }
    }

    fn create_test_proof(
        height: u64,
        proposal_id: [u8; 32],
        total_validators: u32,
        attestations: Vec<CommitAttestation>,
    ) -> BftQuorumProof {
        BftQuorumProof {
            height,
            proposal_id,
            total_validators,
            attestations,
        }
    }

    // ====================================================================
    // extract_consistent_proposal_id Tests
    // ====================================================================

    #[test]
    fn test_extract_consistent_proposal_id_success() {
        let proposal_id = [0xABu8; 32];
        
        let att1 = create_test_attestation([0x01; 32], proposal_id, [0xAA; 2592]);
        let att2 = create_test_attestation([0x02; 32], proposal_id, [0xBB; 2592]);
        
        let proof = create_test_proof(100, proposal_id, 4, vec![att1, att2]);
        
        let result = extract_consistent_proposal_id(&proof);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), proposal_id);
    }

    #[test]
    fn test_extract_consistent_proposal_id_empty_attestations() {
        let proposal_id = [0xABu8; 32];
        let proof = create_test_proof(100, proposal_id, 4, vec![]);
        
        let result = extract_consistent_proposal_id(&proof);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no attestations"));
    }

    #[test]
    fn test_extract_consistent_proposal_id_mismatched_proposal() {
        let proposal_id_1 = [0xABu8; 32];
        let proposal_id_2 = [0xCDu8; 32];
        
        let att1 = create_test_attestation([0x01; 32], proposal_id_1, [0xAA; 2592]);
        let att2 = create_test_attestation([0x02; 32], proposal_id_2, [0xBB; 2592]); // Different proposal!
        
        let proof = create_test_proof(100, proposal_id_1, 4, vec![att1, att2]);
        
        let result = extract_consistent_proposal_id(&proof);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("mismatched proposal_id"));
        assert!(err.contains("attestation 1"));
    }

    // ====================================================================
    // verify_quorum_proof - Validator Set Size Tests (SECURITY)
    // ====================================================================

    #[test]
    fn test_verify_quorum_proof_empty_validator_set() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let proposal_id = [0xABu8; 32];
        
        let att = create_test_attestation(v1_id, proposal_id, v1_key);
        let proof = create_test_proof(100, proposal_id, 4, vec![att]);
        
        // Empty validator set should fail
        let validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("validator set is empty"));
    }

    #[test]
    fn test_verify_quorum_proof_size_mismatch_peer_claims_fewer() {
        // SECURITY: Peer claims 4 validators, local set has 7
        // This is the underreporting attack that was previously possible
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        // Local set has 7 validators (4 more not in the proof)
        let (v4_id, v4_key) = create_test_validator_key(4);
        let (v5_id, v5_key) = create_test_validator_key(5);
        let (v6_id, v6_key) = create_test_validator_key(6);
        let (v7_id, v7_key) = create_test_validator_key(7);
        validator_keys.insert(v4_id, v4_key);
        validator_keys.insert(v5_id, v5_key);
        validator_keys.insert(v6_id, v6_key);
        validator_keys.insert(v7_id, v7_key);
        
        let proposal_id = [0xABu8; 32];
        let att = create_test_attestation(v1_id, proposal_id, v1_key);
        
        // Peer claims only 3 validators (trying to lower threshold)
        let proof = create_test_proof(100, proposal_id, 3, vec![att]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("validator set size mismatch"));
        assert!(err.contains("proof claims 3 validators, local set has 7"));
    }

    #[test]
    fn test_verify_quorum_proof_size_mismatch_peer_claims_more() {
        // Peer claims more validators than local set knows about
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        
        let proposal_id = [0xABu8; 32];
        let att = create_test_attestation(v1_id, proposal_id, v1_key);
        
        // Peer claims 10 validators (more than local set)
        let proof = create_test_proof(100, proposal_id, 10, vec![att]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("validator set size mismatch"));
    }

    #[test]
    fn test_verify_quorum_proof_correct_size_matches() {
        // Proof's claimed total matches local set size
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        
        let proposal_id = [0xABu8; 32];
        
        // Need supermajority of 3 = 3 signatures (ceil(3*2/3) + 1 = 3)
        let att1 = create_test_attestation(v1_id, proposal_id, v1_key);
        let att2 = create_test_attestation(v2_id, proposal_id, v2_key);
        let att3 = create_test_attestation(v3_id, proposal_id, v3_key);
        
        // Note: Signatures are invalid, so this will fail signature verification
        // But it passes the size check
        let proof = create_test_proof(100, proposal_id, 3, vec![att1, att2, att3]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        // Should fail on signature verification, not size check
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.contains("size mismatch")); // Should NOT be size error
    }

    // ====================================================================
    // verify_quorum_proof - Attestation Validation Tests
    // ====================================================================

    #[test]
    fn test_verify_quorum_proof_unknown_validator() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        
        // Validator set only has v1, not v2
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        
        let proposal_id = [0xABu8; 32];
        // Attestation from unknown validator v2
        let att = create_test_attestation(v2_id, proposal_id, v2_key);
        
        let proof = create_test_proof(100, proposal_id, 1, vec![att]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown validator"));
    }

    #[test]
    fn test_verify_quorum_proof_public_key_mismatch() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (_v2_id, v2_key) = create_test_validator_key(2);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key); // v1 has key v1_key
        
        let proposal_id = [0xABu8; 32];
        // Attestation claims to be from v1 but uses v2's key
        let att = create_test_attestation(v1_id, proposal_id, v2_key);
        
        let proof = create_test_proof(100, proposal_id, 1, vec![att]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("public key mismatch"));
    }

    #[test]
    fn test_verify_quorum_proof_duplicate_attestation() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        
        let proposal_id = [0xABu8; 32];
        // Two attestations from same validator (v1)
        let att1 = create_test_attestation(v1_id, proposal_id, v1_key);
        let att2 = create_test_attestation(v1_id, proposal_id, v1_key); // Duplicate!
        let att3 = create_test_attestation(v2_id, proposal_id, v2_key);
        
        let proof = create_test_proof(100, proposal_id, 3, vec![att1, att2, att3]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate attestation"));
    }

    // ====================================================================
    // verify_quorum_proof_for_proposal Tests
    // ====================================================================

    #[test]
    fn test_verify_quorum_proof_for_proposal_mismatch() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        
        let proof_proposal_id = [0xABu8; 32];
        let expected_proposal_id = [0xCDu8; 32]; // Different!
        
        let att = create_test_attestation(v1_id, proof_proposal_id, v1_key);
        let proof = create_test_proof(100, proof_proposal_id, 3, vec![att]);
        
        let result = verify_quorum_proof_for_proposal(&proof, &expected_proposal_id, &validator_keys);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("proposal ID mismatch"));
        assert!(err.contains("replay attack"));
    }

    #[test]
    fn test_verify_quorum_proof_for_proposal_attestation_mismatch() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        
        let proof_proposal_id = [0xABu8; 32];
        let wrong_proposal_id = [0xEFu8; 32];
        
        // Proof claims proposal AB, but attestation is for proposal EF
        let att = create_test_attestation(v1_id, wrong_proposal_id, v1_key);
        let proof = create_test_proof(100, proof_proposal_id, 3, vec![att]);
        
        let result = verify_quorum_proof_for_proposal(&proof, &proof_proposal_id, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatched proposal_id"));
    }

    // ====================================================================
    // Supermajority Threshold Tests
    // ====================================================================

    #[test]
    fn test_supermajority_requirements() {
        use lib_types::consensus::threshold::has_supermajority;
        
        // Test various validator set sizes
        assert!(!has_supermajority(0, 3));  // 0/3 = 0%
        assert!(!has_supermajority(1, 3));  // 1/3 = 33%
        assert!(!has_supermajority(2, 3));  // 2/3 = 66.67% (needs > 66.67%)
        assert!(has_supermajority(3, 3));   // 3/3 = 100%
        
        assert!(!has_supermajority(2, 4));  // 2/4 = 50%
        assert!(has_supermajority(3, 4));   // 3/4 = 75%
        
        assert!(!has_supermajority(3, 5));  // 3/5 = 60%
        assert!(has_supermajority(4, 5));   // 4/5 = 80%
        
        assert!(!has_supermajority(4, 7));  // 4/7 = 57%
        assert!(!has_supermajority(5, 7));  // 5/7 = 71.4% (needs > 66.67%, so 5 is enough)
        // Actually 5/7 = 71.4% which is > 66.67%, so this should pass
        assert!(has_supermajority(5, 7));
        
        assert!(!has_supermajority(6, 10)); // 6/10 = 60%
        assert!(has_supermajority(7, 10));  // 7/10 = 70%
    }

    #[test]
    fn test_verify_quorum_proof_insufficient_attestations() {
        let (v1_id, v1_key) = create_test_validator_key(1);
        let (v2_id, v2_key) = create_test_validator_key(2);
        let (v3_id, v3_key) = create_test_validator_key(3);
        let (v4_id, v4_key) = create_test_validator_key(4);
        
        let mut validator_keys: HashMap<[u8; 32], [u8; 2592]> = HashMap::new();
        validator_keys.insert(v1_id, v1_key);
        validator_keys.insert(v2_id, v2_key);
        validator_keys.insert(v3_id, v3_key);
        validator_keys.insert(v4_id, v4_key);
        
        let proposal_id = [0xABu8; 32];
        // Only 2 attestations for 4 validators (need 3 for supermajority)
        let att1 = create_test_attestation(v1_id, proposal_id, v1_key);
        let att2 = create_test_attestation(v2_id, proposal_id, v2_key);
        
        let proof = create_test_proof(100, proposal_id, 4, vec![att1, att2]);
        
        let result = verify_quorum_proof(&proof, &validator_keys);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("insufficient attestations"));
    }
}
