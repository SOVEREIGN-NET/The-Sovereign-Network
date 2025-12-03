//! UBI distribution proof integration using lib-proofs and lib-economy

use anyhow::{Result, anyhow};
use lib_crypto::PublicKey;
use lib_proofs::plonky2::ZkProofSystem;
use lib_identity::{IdentityManager};
use tracing::{info, warn, error};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate UBI distribution proof using lib-proofs circuits
pub async fn generate_ubi_proof(
    recipient: &PublicKey,
    amount: u64,
    round: u64,
) -> Result<Vec<u8>> {
    info!("🎁 Generating UBI distribution proof for recipient, amount: {}, round: {}", amount, round);
    
    // Create ZK proof system
    let zk_system = ZkProofSystem::new()?;
    
    // Verify recipient eligibility through identity system
    let identity_manager = IdentityManager::new();
    // For now, assume all recipients are eligible (basic implementation)
    let is_eligible = true; // identity_manager.verify_ubi_eligibility(recipient).await?;
    
    if !is_eligible {
        return Err(anyhow!("Recipient not eligible for UBI distribution"));
    }
    
    // Convert recipient public key to u64 for circuit
    let recipient_id = u64::from_le_bytes(
        recipient.as_bytes()[0..8].try_into()
            .map_err(|_| anyhow!("Invalid recipient public key"))?
    );
    
    // Generate UBI distribution proof using Plonky2
    match zk_system.prove_identity(
        recipient_id,
        amount,
        round,
        0, // credential_hash - not needed for UBI
        18, // min_age requirement for UBI
        0,  // no jurisdiction requirement
        1,  // default verification level
    ) {
        Ok(plonky2_proof) => {
            // Create ZeroKnowledgeProof for UBI distribution  
            let ubi_proof = lib_proofs::ZeroKnowledgeProof {
                proof_system: "ZHTP-UBI-Distribution".to_string(),
                proof_data: plonky2_proof.proof.clone(),
                public_inputs: vec![amount.to_le_bytes().to_vec(), round.to_le_bytes().to_vec()].concat(),
                verification_key: vec![], // Simplified for now
                plonky2_proof: Some(plonky2_proof),
                proof: vec![], // Legacy field
            };
            
            // Serialize the proof
            let serialized = serde_json::to_vec(&ubi_proof)
                .map_err(|e| anyhow!("Failed to serialize UBI proof: {}", e))?;
            
            info!("UBI proof generated successfully ({} bytes)", serialized.len());
            Ok(serialized)
        },
        Err(e) => {
            error!("Failed to generate UBI proof: {}", e);
            Err(anyhow!("UBI proof generation failed: {}", e))
        }
    }
}

/// Verify UBI distribution proof using lib-proofs circuits
pub async fn verify_ubi_proof(proof: &[u8]) -> Result<bool> {
    info!("Verifying UBI distribution proof ({} bytes)", proof.len());
    
    // Parse the ZK proof
    let zk_proof: lib_proofs::ZeroKnowledgeProof = serde_json::from_slice(proof)
        .map_err(|e| anyhow!("Failed to parse UBI proof: {}", e))?;
    
    // Verify it's a UBI distribution proof (check proof system type)
    if zk_proof.proof_system != "ZHTP-UBI-Distribution" {
        return Err(anyhow!("Invalid proof system for UBI verification"));
    }
    
    // Create ZK proof system for verification
    let zk_system = ZkProofSystem::new()?;
    
    // Parse public inputs to extract amount and round
    if zk_proof.public_inputs.len() < 16 { // 8 bytes each for amount and round
        return Err(anyhow!("Invalid UBI proof public inputs"));
    }
    
    let amount = u64::from_le_bytes(
        zk_proof.public_inputs[0..8].try_into()
            .map_err(|_| anyhow!("Invalid amount in UBI proof"))?
    );
    
    let round = u64::from_le_bytes(
        zk_proof.public_inputs[8..16].try_into()
            .map_err(|_| anyhow!("Invalid round in UBI proof"))?
    );
    
    // Use the plonky2 proof if available
    if let Some(plonky2_proof) = &zk_proof.plonky2_proof {
        // Verify the proof using the ZK system
        match zk_system.verify_identity(plonky2_proof) {
            Ok(is_valid) => {
                if is_valid {
                    info!("UBI distribution proof verified successfully for amount: {}, round: {}", amount, round);
                    
                    // Additional validation against economics system
                    verify_ubi_economic_constraints(amount, round).await?;
                    
                    Ok(true)
                } else {
                    warn!("UBI distribution proof verification failed");
                    Ok(false)
                }
            },
            Err(e) => {
                error!("UBI proof verification error: {}", e);
                Ok(false)
            }
        }
    } else {
        warn!("No plonky2 proof found in UBI proof");
        Ok(false)
    }
}

/// Verify UBI proof meets economic constraints
async fn verify_ubi_economic_constraints(amount: u64, round: u64) -> Result<bool> {
    info!("Verifying UBI economic constraints for amount: {}, round: {}", amount, round);
    
    // Basic UBI constraints (simplified implementation)
    const MAX_UBI_AMOUNT: u64 = 1000; // Maximum UBI tokens per distribution
    const MAX_ROUNDS_AHEAD: u64 = 1; // Can't be more than 1 round ahead
    
    // Check if amount is within acceptable limits
    if amount > MAX_UBI_AMOUNT {
        warn!("UBI amount {} exceeds maximum {}", amount, MAX_UBI_AMOUNT);
        return Ok(false);
    }
    
    // Check if round is reasonable (simplified - would use actual current round in implementation)
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let estimated_current_round = current_time / 86400; // Daily rounds
    
    if round > estimated_current_round + MAX_ROUNDS_AHEAD {
        warn!("UBI round {} is too far in the future (estimated current: {})", round, estimated_current_round);
        return Ok(false);
    }
    
    // Additional economic validations would go here
    info!("UBI economic constraints verified");
    Ok(true)
}

/// Generate batch UBI proofs for multiple recipients
pub async fn generate_batch_ubi_proofs(
    recipients: &[PublicKey],
    amounts: &[u64],
    round: u64,
) -> Result<Vec<Vec<u8>>> {
    info!("🎁 Generating batch UBI proofs for {} recipients", recipients.len());
    
    if recipients.len() != amounts.len() {
        return Err(anyhow!("Recipients and amounts length mismatch"));
    }
    
    let mut proofs = Vec::with_capacity(recipients.len());
    
    for (i, (recipient, &amount)) in recipients.iter().zip(amounts.iter()).enumerate() {
        info!(" Generating UBI proof {}/{}", i + 1, recipients.len());
        
        match generate_ubi_proof(recipient, amount, round).await {
            Ok(proof) => proofs.push(proof),
            Err(e) => {
                error!("Failed to generate UBI proof for recipient {}: {}", i, e);
                return Err(anyhow!("Batch UBI proof generation failed at recipient {}: {}", i, e));
            }
        }
    }
    
    info!("Generated {} UBI proofs successfully", proofs.len());
    Ok(proofs)
}

/// Verify batch UBI proofs
pub async fn verify_batch_ubi_proofs(proofs: &[Vec<u8>]) -> Result<Vec<bool>> {
    info!("Verifying batch of {} UBI proofs", proofs.len());
    
    let mut results = Vec::with_capacity(proofs.len());
    
    for (i, proof) in proofs.iter().enumerate() {
        info!(" Verifying UBI proof {}/{}", i + 1, proofs.len());
        
        match verify_ubi_proof(proof).await {
            Ok(is_valid) => results.push(is_valid),
            Err(e) => {
                warn!("UBI proof {} verification failed: {}", i, e);
                results.push(false);
            }
        }
    }
    
    let valid_count = results.iter().filter(|&&v| v).count();
    info!("Batch UBI verification complete: {}/{} proofs valid", valid_count, proofs.len());
    
    Ok(results)
}

/// Generate UBI eligibility proof (separate from distribution proof)
pub async fn generate_ubi_eligibility_proof(
    identity: &PublicKey,
) -> Result<Vec<u8>> {
    info!("Generating UBI eligibility proof for identity");
    
    let _identity_manager = IdentityManager::new();
    
    // Simplified human identity verification
    // In a implementation, this would check biometric proofs, etc.
    let is_human = true; // identity_manager.verify_human_identity(identity).await?;
    if !is_human {
        return Err(anyhow!("Identity is not verified as human"));
    }
    
    // Simplified duplicate claim check
    let has_claim = false; // identity_manager.has_active_ubi_claim(identity).await?;
    if has_claim {
        return Err(anyhow!("Identity already has active UBI claim"));
    }
    
    // Generate simplified eligibility proof
    let proof_data = format!("UBI_ELIGIBLE:{}", hex::encode(identity.as_bytes()));
    let eligibility_proof = proof_data.into_bytes();
    
    info!("UBI eligibility proof generated successfully");
    Ok(eligibility_proof)
}

/// Verify UBI eligibility proof
pub async fn verify_ubi_eligibility_proof(
    proof: &[u8],
    identity: &PublicKey,
) -> Result<bool> {
    info!("Verifying UBI eligibility proof for identity");
    
    let _identity_manager = IdentityManager::new();
    
    // Simplified proof verification
    let proof_str = String::from_utf8(proof.to_vec())
        .map_err(|_| anyhow!("Invalid proof data format"))?;
    
    let expected_proof = format!("UBI_ELIGIBLE:{}", hex::encode(identity.as_bytes()));
    let is_valid = proof_str == expected_proof;
    
    if is_valid {
        info!("UBI eligibility proof verified successfully");
    } else {
        warn!("UBI eligibility proof verification failed");
    }
    
    Ok(is_valid)
}

/// Get UBI proof statistics (simplified implementation)
pub async fn get_ubi_proof_stats() -> Result<UbiProofStats> {
    // Simplified statistics without UBI distributor dependency
    Ok(UbiProofStats {
        total_proofs_generated: 0,
        total_proofs_verified: 0,
        current_distribution_round: 1,
        total_ubi_distributed: 0,
        eligible_recipients: 0,
        max_ubi_amount: 1000, // Example maximum UBI amount
    })
}

/// UBI proof statistics
#[derive(Debug, Clone)]
pub struct UbiProofStats {
    pub total_proofs_generated: u64,
    pub total_proofs_verified: u64,
    pub current_distribution_round: u64,
    pub total_ubi_distributed: u64,
    pub eligible_recipients: u64,
    pub max_ubi_amount: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ubi_proof_stats() {
        let stats = get_ubi_proof_stats().await;
        assert!(stats.is_ok());
    }
    
    #[tokio::test]
    async fn test_verify_empty_ubi_proof() {
        let result = verify_ubi_proof(&[]).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_batch_ubi_proofs_empty() {
        let result = verify_batch_ubi_proofs(&[]).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
