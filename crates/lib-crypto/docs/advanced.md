# Advanced Signatures Module

Implementation of advanced cryptographic signature schemes: ring signatures for anonymity and multi-signatures for shared control. These provide privacy-preserving and collaborative signing capabilities.

## Overview

The advanced module provides:
- **Ring Signatures**: Anonymous signing within a group
- **Multi-Signatures**: Threshold signing requiring multiple parties
- **Privacy Protection**: Unlinkable and untraceable signatures
- **Collaborative Control**: Shared authority over resources

## Ring Signatures

### Algorithm Overview
- **Purpose**: Anonymous signing within a ring of possible signers
- **Properties**: Unlinkable, untraceable, non-repudiable
- **Security**: Computational anonymity, signature unforgeability
- **Applications**: Anonymous voting, whistleblowing, private transactions

### Core Structure

```rust
use lib_crypto::advanced::{RingSignature, RingContext};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingSignature {
    pub c: [u8; 32],              // Challenge hash
    pub responses: Vec<[u8; 32]>, // Responses for each ring member
    pub key_image: [u8; 32],      // Key image for double-spend prevention
}
```

### Usage Examples

**Basic Ring Signature:**
```rust
use lib_crypto::{KeyPair, advanced::{RingContext, verify_ring_signature}};

fn basic_ring_signature() -> Result<()> {
    // Create ring members
    let signer = KeyPair::generate()?;
    let member2 = KeyPair::generate()?;
    let member3 = KeyPair::generate()?;
    
    let ring = vec![
        signer.public_key.clone(),
        member2.public_key.clone(), 
        member3.public_key.clone(),
    ];
    
    let message = b"Anonymous message from within the ring";
    
    // Create ring context and sign with first member
    let mut context = RingContext::new(ring.clone(), message.to_vec());
    context.set_signer(0, signer.private_key.clone())?;
    
    // Generate ring signature
    let ring_signature = context.sign()?;
    
    // Verify (observer cannot determine which member signed)
    let is_valid = verify_ring_signature(&ring_signature, message, &ring)?;
    assert!(is_valid);
    
    println!("Ring signature verified - signer identity hidden");
    Ok(())
}
```

**Anonymous Voting:**
```rust
use lib_crypto::{KeyPair, advanced::RingContext};

fn anonymous_voting() -> Result<()> {
    // Eligible voters
    let voter1 = KeyPair::generate()?;
    let voter2 = KeyPair::generate()?; 
    let voter3 = KeyPair::generate()?;
    let voter4 = KeyPair::generate()?;
    
    let eligible_voters = vec![
        voter1.public_key.clone(),
        voter2.public_key.clone(),
        voter3.public_key.clone(),
        voter4.public_key.clone(),
    ];
    
    // Cast anonymous vote (voter2 votes "YES")
    let vote = b"YES - Proposal #123";
    let mut vote_context = RingContext::new(eligible_voters.clone(), vote.to_vec());
    vote_context.set_signer(1, voter2.private_key.clone())?; // voter2 at index 1
    
    let vote_signature = vote_context.sign()?;
    
    // Verify vote is from eligible voter (but don't know which one)
    let is_valid_vote = verify_ring_signature(&vote_signature, vote, &eligible_voters)?;
    assert!(is_valid_vote);
    
    // Key image prevents double voting
    let key_image = vote_signature.key_image;
    println!("Vote cast anonymously, key image: {:?}", key_image);
    
    // If same voter tries to vote again, same key image would be detected
    
    Ok(())
}
```

### Privacy Properties

**Unlinkability:**
```rust
use lib_crypto::{KeyPair, advanced::RingContext};

fn unlinkability_example() -> Result<()> {
    let signer = KeyPair::generate()?;
    let other1 = KeyPair::generate()?;
    let other2 = KeyPair::generate()?;
    
    let ring = vec![
        signer.public_key.clone(),
        other1.public_key.clone(),
        other2.public_key.clone(),
    ];
    
    // Same signer creates multiple ring signatures
    let message1 = b"First anonymous message";
    let message2 = b"Second anonymous message";
    
    // First signature
    let mut context1 = RingContext::new(ring.clone(), message1.to_vec());
    context1.set_signer(0, signer.private_key.clone())?;
    let sig1 = context1.sign()?;
    
    // Second signature 
    let mut context2 = RingContext::new(ring.clone(), message2.to_vec());
    context2.set_signer(0, signer.private_key.clone())?;
    let sig2 = context2.sign()?;
    
    // Signatures are unlinkable - observer cannot tell they're from same signer
    // (except by comparing key images for double-spend detection)
    assert_ne!(sig1.responses, sig2.responses); // Different random components
    
    println!("Two signatures from same signer are unlinkable");
    Ok(())
}
```

### Double-Spend Prevention

```rust
use lib_crypto::{KeyPair, advanced::RingContext};
use std::collections::HashSet;

fn double_spend_prevention() -> Result<()> {
    let signer = KeyPair::generate()?;
    let other = KeyPair::generate()?;
    
    let ring = vec![signer.public_key.clone(), other.public_key.clone()];
    
    // Track used key images to prevent double spending
    let mut used_key_images = HashSet::new();
    
    // First transaction
    let tx1 = b"Spend 10 coins to Alice";
    let mut context1 = RingContext::new(ring.clone(), tx1.to_vec());
    context1.set_signer(0, signer.private_key.clone())?;
    let sig1 = context1.sign()?;
    
    // Record key image
    used_key_images.insert(sig1.key_image);
    
    // Attempt second transaction with same key (double spend)
    let tx2 = b"Spend 10 coins to Bob";
    let mut context2 = RingContext::new(ring.clone(), tx2.to_vec());
    context2.set_signer(0, signer.private_key.clone())?;
    let sig2 = context2.sign()?;
    
    // Key images will be the same - double spend detected!
    assert_eq!(sig1.key_image, sig2.key_image);
    
    if used_key_images.contains(&sig2.key_image) {
        println!("Double spend detected - transaction rejected");
    } else {
        println!("New transaction accepted");
    }
    
    Ok(())
}
```

## Multi-Signatures

### Algorithm Overview
- **Purpose**: Require multiple parties to authorize an action
- **Properties**: Threshold signing, shared control, non-repudiation
- **Applications**: Corporate governance, multi-party contracts, secure wallets

### Core Structure

```rust
use lib_crypto::advanced::MultiSig;

pub struct MultiSig {
    pub public_keys: Vec<PublicKey>,
    pub threshold: usize,           // Minimum signatures required
}
```

### Usage Examples

**Basic Multi-Signature (2-of-3):**
```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn basic_multisig() -> Result<()> {
    // Three parties
    let party1 = KeyPair::generate()?;
    let party2 = KeyPair::generate()?;
    let party3 = KeyPair::generate()?;
    
    let public_keys = vec![
        party1.public_key.clone(),
        party2.public_key.clone(), 
        party3.public_key.clone(),
    ];
    
    // Create 2-of-3 multisig
    let multisig = MultiSig::new(public_keys, 2)?;
    
    let document = b"Transfer $1,000,000 to account XYZ";
    
    // Two parties sign (party1 and party3)
    let sig1 = party1.sign(document)?;
    let sig3 = party3.sign(document)?;
    
    let signatures = vec![sig1, sig3];
    
    // Verify multisig (2 signatures meet threshold of 2)
    let is_valid = multisig.verify(document, &signatures)?;
    assert!(is_valid);
    
    println!("2-of-3 multisig verification successful");
    Ok(())
}
```

**Corporate Governance:**
```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn corporate_governance() -> Result<()> {
    // Board of directors
    let ceo = KeyPair::generate()?;
    let cfo = KeyPair::generate()?;
    let cto = KeyPair::generate()?;
    let chairman = KeyPair::generate()?;
    let director = KeyPair::generate()?;
    
    let board = vec![
        ceo.public_key.clone(),
        cfo.public_key.clone(),
        cto.public_key.clone(), 
        chairman.public_key.clone(),
        director.public_key.clone(),
    ];
    
    // Major decisions require 3-of-5 approval
    let governance = MultiSig::new(board, 3)?;
    
    let resolution = b"Approve merger with Company ABC for $50M";
    
    // CEO, CFO, and Chairman approve
    let ceo_sig = ceo.sign(resolution)?;
    let cfo_sig = cfo.sign(resolution)?; 
    let chairman_sig = chairman.sign(resolution)?;
    
    let approvals = vec![ceo_sig, cfo_sig, chairman_sig];
    
    // Verify sufficient approval
    let is_approved = governance.verify(resolution, &approvals)?;
    assert!(is_approved);
    
    println!("Corporate resolution approved by board majority");
    Ok(())
}
```

**Cryptocurrency Wallet:**
```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn multisig_wallet() -> Result<()> {
    // Wallet owners
    let owner1 = KeyPair::generate()?; // Personal device
    let owner2 = KeyPair::generate()?; // Hardware wallet
    let owner3 = KeyPair::generate()?; // Recovery key
    
    let wallet_keys = vec![
        owner1.public_key.clone(),
        owner2.public_key.clone(),
        owner3.public_key.clone(),
    ];
    
    // Require 2-of-3 to spend (security + usability)
    let wallet = MultiSig::new(wallet_keys, 2)?;
    
    // Transaction to authorize
    let transaction = b"Send 5.0 BTC to address bc1q...";
    
    // Owner signs with personal device and hardware wallet
    let personal_sig = owner1.sign(transaction)?;
    let hardware_sig = owner2.sign(transaction)?;
    
    let authorizations = vec![personal_sig, hardware_sig];
    
    // Verify transaction is properly authorized
    let is_authorized = wallet.verify(transaction, &authorizations)?;
    assert!(is_authorized);
    
    println!("Multisig wallet transaction authorized");
    
    // If hardware wallet is lost, can use personal + recovery keys
    // If personal device compromised, need hardware + recovery
    
    Ok(())
}
```

### Threshold Variations

```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn threshold_examples() -> Result<()> {
    let keys: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate().unwrap()).collect();
    let public_keys: Vec<_> = keys.iter().map(|k| k.public_key.clone()).collect();
    
    let document = b"Threshold signature test";
    
    // 1-of-5: Any single signature is sufficient
    let multisig_1of5 = MultiSig::new(public_keys.clone(), 1)?;
    let sig1 = keys[0].sign(document)?;
    assert!(multisig_1of5.verify(document, &vec![sig1])?);
    
    // 3-of-5: Need majority approval  
    let multisig_3of5 = MultiSig::new(public_keys.clone(), 3)?;
    let sigs_3: Vec<_> = keys[0..3].iter()
        .map(|k| k.sign(document).unwrap())
        .collect();
    assert!(multisig_3of5.verify(document, &sigs_3)?);
    
    // 5-of-5: Unanimous approval required
    let multisig_5of5 = MultiSig::new(public_keys.clone(), 5)?;
    let sigs_5: Vec<_> = keys.iter()
        .map(|k| k.sign(document).unwrap())
        .collect();
    assert!(multisig_5of5.verify(document, &sigs_5)?);
    
    println!("All threshold variations verified successfully");
    Ok(())
}
```

## Security Considerations

### Ring Signature Security

```rust
use lib_crypto::{KeyPair, advanced::RingContext};

fn ring_security_analysis() -> Result<()> {
    // Security properties of ring signatures:
    
    // 1. Anonymity: Computational indistinguishability
    let ring_size = 100; // Larger rings provide stronger anonymity
    let ring: Vec<KeyPair> = (0..ring_size).map(|_| KeyPair::generate().unwrap()).collect();
    let public_keys: Vec<_> = ring.iter().map(|k| k.public_key.clone()).collect();
    
    let signer_index = 42; // Hidden among 100 members
    let message = b"Anonymous message with strong privacy";
    
    let mut context = RingContext::new(public_keys.clone(), message.to_vec());
    context.set_signer(signer_index, ring[signer_index].private_key.clone())?;
    
    let signature = context.sign()?;
    
    // 2. Unforgeability: Cannot create valid signature without private key
    let is_valid = verify_ring_signature(&signature, message, &public_keys)?;
    assert!(is_valid);
    
    // 3. Non-repudiation: Signer cannot deny creating signature
    // (but anonymity prevents identification)
    
    println!("Ring signature provides cryptographic anonymity among {} members", ring_size);
    Ok(())
}
```

### Multi-Signature Security

```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn multisig_security_analysis() -> Result<()> {
    let parties: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate().unwrap()).collect();
    let public_keys: Vec<_> = parties.iter().map(|k| k.public_key.clone()).collect();
    
    // Security analysis:
    
    // 1. Threshold enforcement: Insufficient signatures fail
    let multisig = MultiSig::new(public_keys.clone(), 3)?;
    let document = b"Security test document";
    
    // Only 2 signatures (below threshold of 3)
    let insufficient_sigs: Vec<_> = parties[0..2].iter()
        .map(|k| k.sign(document).unwrap())
        .collect();
    
    let result = multisig.verify(document, &insufficient_sigs)?;
    assert!(!result); // Should fail
    
    // 2. Signature authenticity: All signatures must be valid
    let sufficient_sigs: Vec<_> = parties[0..3].iter()
        .map(|k| k.sign(document).unwrap()) 
        .collect();
    
    let result = multisig.verify(document, &sufficient_sigs)?;
    assert!(result); // Should succeed
    
    // 3. Non-repudiation: Each signature is attributable
    for (i, sig) in sufficient_sigs.iter().enumerate() {
        let individual_valid = parties[i].verify(sig, document)?;
        assert!(individual_valid);
    }
    
    println!("Multisig enforces threshold and authenticity requirements");
    Ok(())
}
```

## Performance Considerations

### Ring Signature Performance

```rust
use std::time::Instant;
use lib_crypto::{KeyPair, advanced::RingContext};

fn ring_signature_benchmarks() -> Result<()> {
    let ring_sizes = vec![10, 50, 100, 500];
    
    for size in ring_sizes {
        let ring: Vec<KeyPair> = (0..size).map(|_| KeyPair::generate().unwrap()).collect();
        let public_keys: Vec<_> = ring.iter().map(|k| k.public_key.clone()).collect();
        
        let message = b"Ring signature benchmark";
        
        // Benchmark signing
        let mut context = RingContext::new(public_keys.clone(), message.to_vec());
        context.set_signer(0, ring[0].private_key.clone())?;
        
        let start = Instant::now();
        let signature = context.sign()?;
        let sign_time = start.elapsed();
        
        // Benchmark verification
        let start = Instant::now();
        let _valid = verify_ring_signature(&signature, message, &public_keys)?;
        let verify_time = start.elapsed();
        
        println!("Ring size {}: Sign {:?}, Verify {:?}", size, sign_time, verify_time);
    }
    
    Ok(())
}
```

### Multi-Signature Performance

```rust
use std::time::Instant;
use lib_crypto::{KeyPair, advanced::MultiSig};

fn multisig_benchmarks() -> Result<()> {
    let party_counts = vec![3, 5, 10, 20];
    
    for count in party_counts {
        let parties: Vec<KeyPair> = (0..count).map(|_| KeyPair::generate().unwrap()).collect();
        let public_keys: Vec<_> = parties.iter().map(|k| k.public_key.clone()).collect();
        
        let threshold = (count + 1) / 2; // Majority threshold
        let multisig = MultiSig::new(public_keys, threshold)?;
        
        let document = b"Multisig benchmark document";
        
        // Generate required signatures
        let signatures: Vec<_> = parties[0..threshold].iter()
            .map(|k| k.sign(document).unwrap())
            .collect();
        
        // Benchmark verification
        let start = Instant::now();
        let _valid = multisig.verify(document, &signatures)?;
        let verify_time = start.elapsed();
        
        println!("{}-of-{} multisig verification: {:?}", threshold, count, verify_time);
    }
    
    Ok(())
}
```

## Best Practices

### 1. Ring Signature Usage

```rust
// Choose appropriate ring size for anonymity vs performance
fn ring_best_practices() -> Result<()> {
    // Small rings (3-10): Fast, basic anonymity
    // Medium rings (50-100): Good anonymity, reasonable performance  
    // Large rings (500+): Strong anonymity, slower performance
    
    let anonymity_level = "high";
    let ring_size = match anonymity_level {
        "basic" => 10,
        "medium" => 50, 
        "high" => 100,
        "maximum" => 500,
        _ => 50,
    };
    
    println!("Using ring size {} for {} anonymity", ring_size, anonymity_level);
    Ok(())
}
```

### 2. Multi-Signature Configuration

```rust
use lib_crypto::{KeyPair, advanced::MultiSig};

fn multisig_best_practices() -> Result<()> {
    // Configure thresholds based on security requirements
    
    let parties = 5;
    let keys: Vec<KeyPair> = (0..parties).map(|_| KeyPair::generate().unwrap()).collect();
    let public_keys: Vec<_> = keys.iter().map(|k| k.public_key.clone()).collect();
    
    // Conservative: Require majority + 1
    let conservative = MultiSig::new(public_keys.clone(), 4)?; // 4-of-5
    
    // Balanced: Simple majority
    let balanced = MultiSig::new(public_keys.clone(), 3)?; // 3-of-5
    
    // Flexible: Allow minority (with controls)
    let flexible = MultiSig::new(public_keys.clone(), 2)?; // 2-of-5
    
    println!("Configured multisig policies for different risk profiles");
    Ok(())
}
```

### 3. Error Handling

```rust
use lib_crypto::{KeyPair, advanced::{MultiSig, RingContext}};
use anyhow::{Result, Context};

fn robust_advanced_operations() -> Result<()> {
    // Ring signature error handling
    let ring: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
    let public_keys: Vec<_> = ring.iter().map(|k| k.public_key.clone()).collect();
    
    let message = b"Test message";
    
    let mut context = RingContext::new(public_keys.clone(), message.to_vec());
    
    // Handle invalid signer index
    if let Err(e) = context.set_signer(10, ring[0].private_key.clone()) {
        println!("Expected error for invalid signer index: {}", e);
    }
    
    // Correct usage
    context.set_signer(0, ring[0].private_key.clone())
        .context("Failed to set ring signer")?;
    
    let signature = context.sign()
        .context("Failed to create ring signature")?;
    
    // Multisig error handling
    let parties: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate().unwrap()).collect();
    let party_keys: Vec<_> = parties.iter().map(|k| k.public_key.clone()).collect();
    
    // Handle invalid threshold
    if let Err(e) = MultiSig::new(party_keys.clone(), 0) {
        println!("Expected error for zero threshold: {}", e);
    }
    
    if let Err(e) = MultiSig::new(party_keys.clone(), 10) {
        println!("Expected error for excessive threshold: {}", e);
    }
    
    // Correct usage
    let multisig = MultiSig::new(party_keys, 2)
        .context("Failed to create multisig")?;
    
    Ok(())
}
```

The advanced signatures module provides powerful tools for privacy and collaborative security, enabling anonymous transactions and shared control over critical operations within the SOVEREIGN_NET ecosystem.
