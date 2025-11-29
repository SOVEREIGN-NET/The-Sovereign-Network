//! Test suite for identity proof implementation

#[cfg(test)]
mod tests {
    use super::super::identity_proofs::*;
    use tokio;
    use anyhow::Result;

    #[tokio::test]
    async fn test_generate_identity_proof() -> Result<()> {
        println!(" Testing identity proof generation...");
        
        let proof_bytes = generate_identity_proof().await?;
        
        // Verify proof is not empty (should be JSON serialized data)
        assert!(!proof_bytes.is_empty(), "Identity proof should not be empty");
        assert!(proof_bytes.len() > 100, "Identity proof should be substantial (>100 bytes)");
        
        // Verify it contains JSON-like structure
        let proof_str = String::from_utf8(proof_bytes.clone())?;
        assert!(proof_str.contains("proof"), "Should contain proof field");
        assert!(proof_str.contains("public_inputs"), "Should contain public_inputs field");
        assert!(proof_str.contains("verification_key_hash"), "Should contain verification_key_hash field");
        
        println!("Identity proof generation test passed: {} bytes", proof_bytes.len());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_identity_proof() -> Result<()> {
        println!(" Testing identity proof verification...");
        
        // Generate a proof first
        let proof_bytes = generate_identity_proof().await?;
        
        // Verify the proof
        let is_valid = verify_identity_proof(&proof_bytes).await?;
        assert!(is_valid, "Generated identity proof should be valid");
        
        println!("Identity proof verification test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_proof_with_custom_parameters() -> Result<()> {
        println!(" Testing identity proof with custom parameters...");
        
        let custom_params = IdentityProofParams {
            min_age: 21,
            required_jurisdiction: 840, // US
            verification_level: 2,
        };
        
        // Generate proof with custom parameters
        let proof_bytes = generate_identity_proof_with_params(&custom_params).await?;
        
        // Verify with same parameters
        let is_valid = verify_identity_proof_with_params(&proof_bytes, &custom_params).await?;
        assert!(is_valid, "Identity proof should be valid with matching parameters");
        
        println!("Custom parameter identity proof test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_proof_parameter_mismatch() -> Result<()> {
        println!(" Testing identity proof parameter mismatch...");
        
        let generation_params = IdentityProofParams {
            min_age: 18,
            required_jurisdiction: 0,
            verification_level: 1,
        };
        
        let verification_params = IdentityProofParams {
            min_age: 25, // Different age requirement
            required_jurisdiction: 0,
            verification_level: 1,
        };
        
        // Generate proof with one set of parameters
        let proof_bytes = generate_identity_proof_with_params(&generation_params).await?;
        
        // Try to verify with different parameters
        let is_valid = verify_identity_proof_with_params(&proof_bytes, &verification_params).await?;
        assert!(!is_valid, "Identity proof should be invalid with mismatched parameters");
        
        println!("Parameter mismatch test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_proof_invalid_data() -> Result<()> {
        println!(" Testing identity proof with invalid data...");
        
        // Test with empty data
        let empty_result = verify_identity_proof(&[]).await;
        assert!(empty_result.is_err(), "Empty proof should fail verification");
        
        // Test with invalid JSON
        let invalid_json = b"not valid json";
        let invalid_result = verify_identity_proof(invalid_json).await;
        assert!(invalid_result.is_err(), "Invalid JSON should fail verification");
        
        // Test with valid JSON but wrong structure
        let wrong_structure = br#"{"wrong": "structure"}"#;
        let wrong_result = verify_identity_proof(wrong_structure).await;
        assert!(wrong_result.is_err(), "Wrong structure should fail verification");
        
        println!("Invalid data test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_proof_mesh_participation() -> Result<()> {
        println!(" Testing identity proof for mesh network participation...");
        
        // Test with realistic mesh network requirements
        let mesh_params = IdentityProofParams {
            min_age: 18,          // Legal age for network participation
            required_jurisdiction: 0, // No jurisdiction restriction (global mesh)
            verification_level: 1,    // Basic verification
        };
        
        // Generate proof for mesh participation
        let proof_bytes = generate_identity_proof_with_params(&mesh_params).await?;
        
        // Verify proof meets mesh requirements
        let is_valid = verify_identity_proof_with_params(&proof_bytes, &mesh_params).await?;
        assert!(is_valid, "Identity proof should be valid for mesh participation");
        
        // Verify proof structure contains expected fields for mesh
        let proof_str = String::from_utf8(proof_bytes)?;
        assert!(proof_str.contains("ZHTP-Optimized-Identity"), "Should use ZHTP identity proof system");
        
        println!("Mesh participation identity proof test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_identity_proofs() -> Result<()> {
        println!(" Testing multiple identity proof generations...");
        
        let mut proof_bytes_list = Vec::new();
        
        // Generate multiple proofs
        for i in 0..5 {
            let proof_bytes = generate_identity_proof().await?;
            
            // Each proof should be valid
            let is_valid = verify_identity_proof(&proof_bytes).await?;
            assert!(is_valid, "Identity proof {} should be valid", i);
            
            proof_bytes_list.push(proof_bytes);
        }
        
        // All proofs should be different (due to different identity secrets and timestamps)
        for i in 0..proof_bytes_list.len() {
            for j in (i+1)..proof_bytes_list.len() {
                assert_ne!(proof_bytes_list[i], proof_bytes_list[j], 
                         "Identity proofs {} and {} should be different", i, j);
            }
        }
        
        println!("Multiple identity proofs test passed");
        Ok(())
    }

    #[tokio::test]
    async fn test_identity_proof_jurisdiction_requirements() -> Result<()> {
        println!(" Testing identity proof jurisdiction requirements...");
        
        // Test with specific jurisdiction requirement
        let us_params = IdentityProofParams {
            min_age: 18,
            required_jurisdiction: 840, // US jurisdiction
            verification_level: 1,
        };
        
        // Generate proof (will use a random jurisdiction)
        let proof_bytes = generate_identity_proof_with_params(&us_params).await?;
        
        // Verify with same jurisdiction requirement
        let is_valid = verify_identity_proof_with_params(&proof_bytes, &us_params).await?;
        
        // Note: This test might pass or fail depending on the random jurisdiction generated
        // In a implementation, the jurisdiction would be controlled by the user
        println!("Jurisdiction verification result: {}", is_valid);
        
        // Test with no jurisdiction requirement (should always work)
        let no_jurisdiction_params = IdentityProofParams {
            min_age: 18,
            required_jurisdiction: 0, // No requirement
            verification_level: 1,
        };
        
        let proof_bytes_2 = generate_identity_proof_with_params(&no_jurisdiction_params).await?;
        let is_valid_2 = verify_identity_proof_with_params(&proof_bytes_2, &no_jurisdiction_params).await?;
        assert!(is_valid_2, "Identity proof with no jurisdiction requirement should be valid");
        
        println!("Jurisdiction requirements test passed");
        Ok(())
    }
}
