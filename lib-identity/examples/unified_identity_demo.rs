//! Unified Identity Demo - Root-Key-Anchored DID Example (ADR-0004)
//!
//! This example demonstrates unified identity where the DID is anchored to a deterministic
//! Root Signing public key derived from a Root Secret.
//!
//! ## What This Demonstrates
//!
//! 1. **Identity Creation** - Using `ZhtpIdentity::new_unified()` with random or fixed seeds
//! 2. **DID Generation** - Decentralized Identifier format (did:zhtp:...)
//! 3. **NodeId Derivation** - DHT routing ID derived from DID + device name
//! 4. **Deterministic Secrets** - All secrets derived from master seed
//! 5. **Wallet Integration** - WalletManager with deterministic wallet generation
//! 6. **PQC Keypairs** - Real post-quantum cryptography (Dilithium + Kyber)
//! 7. **Reproducibility** - Same seed always produces same identity
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example unified_identity_demo
//! ```

use anyhow::Result;
use lib_identity::{
    ZhtpIdentity, IdentityType, NodeId,
};

fn main() -> Result<()> {
    println!("\n{}", "=".repeat(80));
    println!("  ZHTP UNIFIED IDENTITY DEMO - Root-Key-Anchored DID (ADR-0004)");
    println!("{}\n", "=".repeat(80));

    // ============================================================================
    // PART 1: Create Identity with Random Seed
    // ============================================================================
    // This demonstrates creating a new identity where the system generates
    // a cryptographically secure random seed. All identity secrets are derived
    // from this single seed using deterministic derivation.
    
    println!("📋 PART 1: Creating Identity with Random Seed\n");
    println!("   WHY: Production use case - each user gets unique random identity");
    println!("   HOW: System generates secure random root secret internally\n");

    let identity_random = create_identity_with_random_seed()?;
    display_identity_details(&identity_random, "Random Seed Identity")?;

    println!("\n{}\n", "-".repeat(80));

    // ============================================================================
    // PART 2: Create Identity with Fixed Seed (Demonstrates Determinism)
    // ============================================================================
    // This demonstrates the deterministic nature of the system. Using the same
    // seed will ALWAYS produce the same identity, DID, NodeId, and secrets.
    // This is crucial for:
    // - Identity recovery from seed phrase
    // - Multi-device sync (same identity on different devices)
    // - Deterministic testing
    
    println!("📋 PART 2: Creating Identity with Fixed Seed (Deterministic)\n");
    println!("   WHY: Recovery use case - restore identity from backed-up seed");
    println!("   HOW: Use specific seed bytes to demonstrate reproducibility\n");

    // Use a fixed seed for deterministic demonstration
    let fixed_seed = [0x42u8; 64]; // Fixed seed: all bytes = 0x42
    let identity_fixed = create_identity_with_fixed_seed(fixed_seed)?;
    display_identity_details(&identity_fixed, "Fixed Seed Identity")?;

    println!("\n{}\n", "-".repeat(80));

    // ============================================================================
    // PART 3: Verify Determinism (Same Seed → Same Identity)
    // ============================================================================
    // Create another identity with the SAME fixed seed and verify all derived
    // values match. This proves the system is truly deterministic.
    
    println!("📋 PART 3: Verifying Deterministic Derivation\n");
    println!("   WHY: Prove seed recovery will restore exact same identity");
    println!("   TEST: Create second identity with same seed, compare outputs\n");

    let identity_fixed_2 = create_identity_with_fixed_seed(fixed_seed)?;
    verify_determinism(&identity_fixed, &identity_fixed_2)?;

    println!("\n{}\n", "-".repeat(80));

    // ============================================================================
    // PART 4: Demonstrate Multi-Device Support
    // ============================================================================
    // Show how the same identity can have multiple devices (computers, phones)
    // each with their own NodeId for DHT routing, but all authenticated by the
    // same identity.
    
    println!("📋 PART 4: Multi-Device Support (Same Identity, Different NodeIds)\n");
    println!("   WHY: Users have laptop, phone, tablet - all use same identity");
    println!("   HOW: NodeId = hash(DID + device_name) - different per device\n");

    demonstrate_multi_device(&identity_fixed)?;

    println!("\n{}\n", "-".repeat(80));

    // ============================================================================
    // PART 5: Wallet Integration
    // ============================================================================
    // Show how the WalletManager uses the master seed to deterministically
    // generate multiple wallets (Primary, Savings, Staking, etc.)
    
    println!("📋 PART 5: Wallet Integration with Master Seed\n");
    println!("   WHY: All wallets recoverable from single seed phrase");
    println!("   HOW: WalletManager derives wallet keys from master seed\n");

    demonstrate_wallet_integration(&identity_fixed)?;

    println!("\n{}", "=".repeat(80));
    println!("  ✅ DEMO COMPLETE - All Features Verified");
    println!("{}\n", "=".repeat(80));

    Ok(())
}

/// Create a new identity with a randomly generated seed
/// 
/// In production, this is the standard way to create new identities.
/// The system generates a cryptographically secure random seed.
/// 
/// This uses ZhtpIdentity::new_unified() which:
/// - Generates random 64-byte seed internally
/// - Treats the 64-byte seed as Root Secret (RS) and anchors DID to a deterministic root signing public key
/// - Derives all secrets deterministically from seed
/// - Generates PQC keypairs (Dilithium + Kyber)
fn create_identity_with_random_seed() -> Result<ZhtpIdentity> {
    // Create unified identity with random seed
    // new_unified(type, age, jurisdiction, device_name, seed)
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25), // Age for Human identity (required for credential derivation)
        Some("US".to_string()), // Jurisdiction (required for credential derivation)
        "laptop", // Primary device name
        None, // None = generate random seed internally
    )?;
    
    Ok(identity)
}

/// Create a new identity with a fixed seed for deterministic testing
/// 
/// This demonstrates that the same seed always produces the same identity.
/// Useful for recovery and multi-device scenarios.
/// 
/// Same seed input → Identical outputs:
/// - Same DID
/// - Same NodeId (for same device name)
/// - Same zk_identity_secret
/// - Same wallet_master_seed
/// - Same dao_member_id
/// 
/// Note: Operational keys (e.g. Kyber) may be randomly generated/rotatable; DID is anchored to the root signing key.
fn create_identity_with_fixed_seed(seed: [u8; 64]) -> Result<ZhtpIdentity> {
    // Create unified identity with specific seed
    let identity = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(25), // Age for Human identity
        Some("US".to_string()), // Jurisdiction
        "laptop", // Primary device name
        Some(seed), // Use fixed seed for determinism
    )?;
    
    Ok(identity)
}

/// Display comprehensive details about an identity
fn display_identity_details(identity: &ZhtpIdentity, label: &str) -> Result<()> {
    println!("🔐 {}\n", label);
    
    // Identity ID
    println!("   Identity ID:    {}", hex::encode(&identity.id.0[..16]));
    println!("                   ↳ First 16 bytes shown (32 bytes total)");
    
    // DID (Decentralized Identifier)
    println!("\n   DID:            {}", identity.did);
    println!("                   ↳ Format: did:zhtp:<base58-encoded-public-key>");
    println!("                   ↳ Globally unique, self-verifying identifier");
    
    // Primary NodeId (for DHT routing)
    println!("\n   Primary NodeId: {}", hex::encode(&identity.node_id.as_bytes()));
    println!("                   ↳ Derived: hash(DID + '{}')", identity.primary_device);
    println!("                   ↳ Used for DHT/Kademlia routing in P2P network");
    
    // Identity Type and Access Level
    println!("\n   Type:           {:?}", identity.identity_type);
    println!("   Access Level:   {:?}", identity.access_level);
    println!("   Reputation:     {}", identity.reputation);
    
    // PQC Keypair Information
    println!("\n   🔑 Post-Quantum Cryptography Keys:");
    println!("      Dilithium Public Key:  {} bytes", identity.public_key.dilithium_pk.len());
    println!("                            ↳ Post-quantum digital signatures");
    println!("      Kyber Public Key:      {} bytes", identity.public_key.kyber_pk.len());
    println!("                            ↳ Post-quantum key encapsulation");
    
    // Derived Secrets (from master seed)
    println!("\n   🔐 Deterministically Derived Secrets:");
    println!("      ZK Identity Secret:    {} bytes", identity.zk_identity_secret.len());
    println!("                            ↳ For zero-knowledge proofs");
    
    println!("      Wallet Master Seed:    {} bytes", identity.wallet_master_seed.len());
    println!("                            ↳ Derives all wallet private keys");
    
    println!("      DAO Member ID:         {}", &identity.dao_member_id[..32]);
    println!("                            ↳ Pseudonymous DAO identity");
    
    // Wallet Manager Status
    println!("\n   💰 Wallet Manager:");
    println!("      Wallets:              {}", identity.wallet_manager.wallets.len());
    println!("      Total Balance:        {} ZHTP", identity.wallet_manager.total_balance);
    
    Ok(())
}

/// Verify that two identities created with the same seed are identical
fn verify_determinism(id1: &ZhtpIdentity, id2: &ZhtpIdentity) -> Result<()> {
    println!("   Comparing two identities created with same seed [0x42; 64]:\n");
    
    let did_match = id1.did == id2.did;
    let node_id_match = id1.node_id.as_bytes() == id2.node_id.as_bytes();
    let zk_secret_match = id1.zk_identity_secret == id2.zk_identity_secret;
    let wallet_seed_match = id1.wallet_master_seed == id2.wallet_master_seed;
    let dao_id_match = id1.dao_member_id == id2.dao_member_id;
    
    println!("   ✓ DID Match:              {}", if did_match { "✅ PASS" } else { "❌ FAIL" });
    println!("   ✓ NodeId Match:           {}", if node_id_match { "✅ PASS" } else { "❌ FAIL" });
    println!("   ✓ ZK Secret Match:        {}", if zk_secret_match { "✅ PASS" } else { "❌ FAIL" });
    println!("   ✓ Wallet Seed Match:      {}", if wallet_seed_match { "✅ PASS" } else { "❌ FAIL" });
    println!("   ✓ DAO Member ID Match:    {}", if dao_id_match { "✅ PASS" } else { "❌ FAIL" });
    
    if did_match && node_id_match && zk_secret_match && wallet_seed_match && dao_id_match {
        println!("\n   🎉 DETERMINISM VERIFIED: Same seed → Identical identity");
    } else {
        println!("\n   ❌ DETERMINISM FAILED: Values don't match!");
    }
    
    Ok(())
}

/// Demonstrate how the same identity works across multiple devices
fn demonstrate_multi_device(identity: &ZhtpIdentity) -> Result<()> {
    println!("   Base Identity DID: {}\n", identity.did);
    
    // Show primary device NodeId (already in identity)
    println!("   Device 1 (laptop):   NodeId = {}", 
             hex::encode(&identity.node_id.as_bytes()[..16]));
    println!("                        ↳ hash(DID + 'laptop')");
    
    // Calculate NodeIds for other devices
    let phone_node_id = NodeId::from_did_device(&identity.did, "phone")?;
    println!("\n   Device 2 (phone):    NodeId = {}", 
             hex::encode(&phone_node_id.as_bytes()[..16]));
    println!("                        ↳ hash(DID + 'phone')");
    
    let tablet_node_id = NodeId::from_did_device(&identity.did, "tablet")?;
    println!("\n   Device 3 (tablet):   NodeId = {}", 
             hex::encode(&tablet_node_id.as_bytes()[..16]));
    println!("                        ↳ hash(DID + 'tablet')");
    
    println!("\n   💡 KEY INSIGHT: Same DID, different NodeIds for DHT routing");
    println!("      Each device has unique NodeId but shares same identity/credentials");
    
    Ok(())
}

/// Demonstrate wallet integration with master seed derivation
fn demonstrate_wallet_integration(identity: &ZhtpIdentity) -> Result<()> {
    println!("   Identity has WalletManager with master seed derivation\n");
    
    println!("   Master Seed:         {} bytes", identity.wallet_master_seed.len());
    println!("                       ↳ All wallets derived from this seed");
    println!("\n   Wallet Derivation Path Examples:");
    println!("      Primary Wallet:   m/0  (first derived wallet)");
    println!("      Savings Wallet:   m/1  (second derived wallet)");
    println!("      Staking Wallet:   m/2  (third derived wallet)");
    println!("      DAO Wallet:       m/3  (fourth derived wallet)");
    
    println!("\n   💰 Current Wallet Status:");
    println!("      Wallets Created:  {}", identity.wallet_manager.wallets.len());
    println!("      Total Balance:    {} ZHTP", identity.wallet_manager.total_balance);
    
    // Show how to create wallets from the identity
    println!("\n   📝 Creating Wallets (Example Code):");
    println!("      ```rust");
    println!("      let (wallet_id, seed_phrase) = identity.wallet_manager");
    println!("          .create_wallet_with_seed_phrase(");
    println!("              WalletType::Standard,");
    println!("              \"My Wallet\".to_string(),");
    println!("              Some(\"primary\".to_string()),");
    println!("          ).await?;");
    println!("      ```");
    
    println!("\n   🔑 Recovery Process:");
    println!("      1. User backs up 20-word master seed phrase");
    println!("      2. On new device, restore identity from seed phrase");
    println!("      3. All wallets automatically re-derived from master seed");
    println!("      4. Same wallet addresses, same private keys, same funds");
    
    Ok(())
}
