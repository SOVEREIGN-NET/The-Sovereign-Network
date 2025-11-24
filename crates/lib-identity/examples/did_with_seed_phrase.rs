//! Example: Creating and recovering DIDs with 20-word seed phrases
//! 
//! This example demonstrates the complete DID lifecycle with seed phrase support:
//! 1. Create a DID with a 20-word recovery seed phrase
//! 2. Backup the seed phrase securely
//! 3. Recover the DID from the seed phrase
//! 4. Transfer DID to a new device

use lib_identity::{
    create_secure_did, recover_did, transfer_did_to_device,
    IdentityManager, IdentityType, 
    DIDCreationRequest, create_did_with_seed_phrase
};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("DID Seed Phrase Example - ZHTP Identity Management");
    println!("════════════════════════════════════════════════════");
    
    // Step 1: Create a new identity
    println!("\n1️⃣ Creating new ZHTP identity...");
    let mut identity_manager = IdentityManager::new();
    let identity_id = identity_manager.create_identity(
        IdentityType::Human,
        Vec::new(), // No initial recovery options - we'll use seed phrase
    ).await?;
    
    println!("Identity created: {}", hex::encode(&identity_id.0[..8]));
    
    // Get the full identity object
    let identity = identity_manager.get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created identity"))?
        .clone();
    
    // Step 2: Create DID with 20-word seed phrase
    println!("\n2️⃣ Creating DID with 20-word recovery seed phrase...");
    let did_result = create_secure_did(
        identity.clone(),
        Some("https://did.zhtp.network".to_string()),
    ).await?;
    
    println!("DID created: {}", did_result.did_document.id);
    
    if let Some(seed_phrase) = &did_result.seed_phrase {
        println!("\n YOUR 20-WORD RECOVERY SEED PHRASE:");
        println!("┌─────────────────────────────────────────────────────────────┐");
        for (i, word) in seed_phrase.words.iter().enumerate() {
            if i % 4 == 0 { println!("│ "); }
            print!("{:2}. {:10} ", i + 1, word);
            if (i + 1) % 4 == 0 { println!("│"); }
        }
        println!("└─────────────────────────────────────────────────────────────┘");
        
        // Step 3: Show backup instructions
        println!("\n3️⃣ Seed Phrase Security Instructions:");
        println!("{}", did_result.recovery_instructions);
        
        // Step 4: Demonstrate recovery (simulation)
        println!("\n4️⃣ Testing DID recovery from seed phrase...");
        let recovery_result = recover_did(seed_phrase.words.clone()).await?;
        println!("Recovery test: {}", recovery_result);
        
        // Step 5: Demonstrate device transfer
        println!("\n5️⃣ Simulating DID transfer to new device...");
        let device_id = "mobile_device_12345";
        match transfer_did_to_device(&seed_phrase.words, device_id).await {
            Ok(verification_code) => {
                println!("Transfer initiated to device: {}", device_id);
                println!(" Verification code: {}", verification_code);
            }
            Err(e) => println!(" Transfer simulation: {}", e),
        }
    }
    
    // Step 6: Show DID document structure
    println!("\n6️⃣ DID Document Summary:");
    println!("   DID: {}", did_result.did_document.id);
    println!("   Verification Methods: {}", did_result.did_document.verification_method.len());
    println!("   Service Endpoints: {}", did_result.did_document.service.len());
    println!("   Created: {}", did_result.did_document.created);
    
    // Show service endpoints with seed commitment
    println!("\n   Service Endpoints:");
    for service in &did_result.did_document.service {
        if service.service_type == "SeedPhraseCommitment" {
            println!("   • {} (Seed Recovery): {}", service.service_type, &service.service_endpoint[..50]);
        } else {
            println!("   • {}: {}", service.service_type, service.service_endpoint);
        }
    }
    
    println!("\nDID with seed phrase example completed successfully!");
    println!("Your DID is now fully portable and recoverable using the 20-word seed phrase.");
    
    Ok(())
}

/// Example of advanced DID creation with custom options
pub async fn advanced_did_creation_example() -> Result<()> {
    println!("\nAdvanced DID Creation Example");
    println!("──────────────────────────────────");
    
    // Create identity
    let mut identity_manager = IdentityManager::new();
    let identity_id = identity_manager.create_identity(
        IdentityType::Human,
        Vec::new(),
    ).await?;
    
    let identity = identity_manager.get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve created identity"))?
        .clone();
    
    // Custom DID creation request with additional services
    let request = DIDCreationRequest {
        identity,
        generate_seed_phrase: true,
        word_count: Some(24), // Use 24 words for extra security
        language: Some("english".to_string()),
        base_url: Some("https://custom.zhtp.network".to_string()),
        additional_services: vec![
            // Custom service endpoints can be added here
        ],
    };
    
    let did_result = create_did_with_seed_phrase(request).await?;
    
    println!("Advanced DID created with 24-word seed phrase");
    println!("   DID: {}", did_result.did_document.id);
    
    if let Some(seed_phrase) = &did_result.seed_phrase {
        println!("   Seed words: {}", seed_phrase.word_count);
        println!("   Language: {}", seed_phrase.language);
        println!("   Checksum: {}", seed_phrase.checksum);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_did_seed_phrase_workflow() {
        // Test the basic DID creation with seed phrase
        let mut identity_manager = IdentityManager::new();
        let identity_id = identity_manager.create_identity(
            IdentityType::Human,
            Vec::new(),
        ).await.expect("Failed to create identity");
        
        let identity = identity_manager.get_identity(&identity_id)
            .expect("Failed to retrieve created identity")
            .clone();
        
        let did_result = create_secure_did(identity, None).await
            .expect("Failed to create DID with seed phrase");
        
        // Verify DID was created
        assert!(did_result.did_document.id.starts_with("did:zhtp:"));
        assert!(did_result.seed_phrase.is_some());
        
        // Verify seed phrase has 20 words
        if let Some(seed_phrase) = &did_result.seed_phrase {
            assert_eq!(seed_phrase.words.len(), 20);
            assert_eq!(seed_phrase.language, "english");
            assert!(!seed_phrase.checksum.is_empty());
        }
        
        // Verify seed commitment service is present
        let has_seed_commitment = did_result.did_document.service.iter()
            .any(|s| s.service_type == "SeedPhraseCommitment");
        assert!(has_seed_commitment, "DID should include seed commitment service");
    }
    
    #[tokio::test]
    async fn test_did_recovery_simulation() {
        // Create a sample 20-word seed phrase for testing
        let test_seed_words: Vec<String> = (1..=20)
            .map(|i| format!("word{:02}", i))
            .collect();
        
        // Test recovery (should handle the simulation gracefully)
        let recovery_result = recover_did(test_seed_words).await;
        
        // Recovery should either succeed or fail gracefully with a descriptive message
        match recovery_result {
            Ok(message) => {
                assert!(message.contains("successful") || message.contains("verified"));
            }
            Err(e) => {
                // Acceptable errors for simulation
                assert!(e.to_string().contains("No matching recovery phrase") 
                        || e.to_string().contains("20 seed phrase words required"));
            }
        }
    }
}
