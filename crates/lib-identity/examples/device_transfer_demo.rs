//! Device Transfer Demo - Shows how to transfer DID between devices
//! 
//! This example demonstrates the difference between:
//! - device_id: User-friendly device identifier (e.g., "laptop-2024")  
//! - zkDID: Zero-knowledge decentralized identifier (the actual DID)

use lib_identity::did::document_generation::{
    create_did_with_seed_phrase, transfer_did_to_device, DIDCreationRequest,
};
use lib_identity::identity::{ZhtpIdentity, IdentityType};
use lib_identity::recovery::PhraseGenerationOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" ZHTP Device Transfer Demo");
    println!("═══════════════════════════════");
    println!();

    // Step 1: Create identity and DID with seed phrase
    println!("1️⃣ Creating DID with seed phrase...");
    let identity = ZhtpIdentity::new("demo-user".to_string(), IdentityType::Individual)?;
    
    let request = DIDCreationRequest {
        identity,
        generate_seed_phrase: true,
        word_count: Some(12), // Shorter for demo
        language: Some("english".to_string()),
        base_url: Some("https://demo.zhtp.network".to_string()),
        additional_services: vec![],
    };
    
    let result = create_did_with_seed_phrase(request).await?;
    
    if let Some(seed_phrase) = &result.seed_phrase {
        println!("Created DID: {}", result.did_document.id);
        println!();
        
        // Step 2: Demonstrate device transfer
        println!("2️⃣ Transferring DID to different devices...");
        println!();
        
        // Example device IDs (not zkDIDs!)
        let devices = vec![
            "laptop-home",      // Home laptop
            "phone-main",       // Primary phone  
            "tablet-work",      // Work tablet
            "desktop-office",   // Office desktop
        ];
        
        for device_id in &devices {
            println!(" Transferring to device: {}", device_id);
            
            match transfer_did_to_device(&seed_phrase.words, device_id).await {
                Ok(verification_code) => {
                    println!("   Transfer code: {}", verification_code);
                    println!("   Enter this code on your {}", device_id);
                }
                Err(e) => {
                    println!("   Transfer failed: {}", e);
                }
            }
            println!();
        }
        
        // Step 3: Explain the concepts
        println!("3️⃣ Key Concepts:");
        println!("═══════════════");
        println!(" zkDID (Zero-Knowledge DID): {}", result.did_document.id);
        println!("   • This is your actual decentralized identifier");
        println!("   • Used for cryptographic operations and verification");
        println!("   • Format: did:zhtp:[hash]");
        println!();
        println!(" device_id: User-friendly device names");
        println!("   • Examples: 'laptop-home', 'phone-main', 'tablet-work'");
        println!("   • Used for device management and transfer verification");
        println!("   • You choose these names for easy identification");
        println!();
        println!(" Transfer Process:");
        println!("   1. Use your 12-20 word seed phrase");
        println!("   2. Specify target device_id (your device nickname)");
        println!("   3. Get verification code");
        println!("   4. Enter code on target device to complete transfer");
        println!();
        println!(" Security Note:");
        println!("   • Your zkDID remains the same across all devices");
        println!("   • device_id is just for convenience and organization");
        println!("   • Seed phrase gives you full control of your zkDID");
    }
    
    Ok(())
}
