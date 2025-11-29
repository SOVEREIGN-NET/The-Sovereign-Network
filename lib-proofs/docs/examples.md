# Examples and Tutorials

This document provides comprehensive examples and step-by-step tutorials for using lib-proofs in various scenarios.

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Financial Privacy Tutorial](#financial-privacy-tutorial)
3. [Identity Verification Tutorial](#identity-verification-tutorial)
4. [Decentralized Storage Tutorial](#decentralized-storage-tutorial)
5. [Network Routing Tutorial](#network-routing-tutorial)
6. [Advanced Patterns](#advanced-patterns)
7. [Real-World Integration](#real-world-integration)

## Basic Examples

### Simple Range Proof

```rust
use lib_proofs::{ZkRangeProof, ZkProofSystem};
use anyhow::Result;

fn basic_range_proof() -> Result<()> {
    println!("=== Basic Range Proof Example ===");
    
    // Create a range proof for a secret value
    let secret_value = 750;
    let min_range = 0;
    let max_range = 1000;
    
    println!("Proving that secret value is in range [{}, {}]", min_range, max_range);
    
    // Generate the proof
    let range_proof = ZkRangeProof::generate_simple(secret_value, min_range, max_range)?;
    println!("Proof generated successfully");
    
    // Verify the proof
    let is_valid = range_proof.verify()?;
    println!("Proof verification: {}", if is_valid { "PASSED" } else { "FAILED" });
    
    // Try with value outside range (should fail)
    println!("\nTesting with value outside range...");
    let invalid_proof = ZkRangeProof::generate_simple(1500, min_range, max_range);
    match invalid_proof {
        Ok(proof) => {
            let is_valid = proof.verify()?;
            println!("Invalid proof verification: {}", if is_valid { "PASSED" } else { "FAILED" });
        }
        Err(e) => {
            println!("Expected error for out-of-range value: {}", e);
        }
    }
    
    Ok(())
}
```

### Basic Transaction Proof

```rust
use lib_proofs::ZkProofSystem;
use anyhow::Result;

fn basic_transaction_proof() -> Result<()> {
    println!("=== Basic Transaction Proof Example ===");
    
    // Initialize the ZK proof system
    let zk_system = ZkProofSystem::new()?;
    
    // Transaction details (private)
    let sender_balance = 1000;
    let transfer_amount = 250;
    let transaction_fee = 5;
    let sender_secret = 12345;
    let nullifier_seed = 67890;
    
    println!("Creating transaction proof...");
    println!("- Balance check: {} >= {} + {} = {}", 
        sender_balance, transfer_amount, transaction_fee, 
        transfer_amount + transaction_fee);
    
    // Generate transaction proof
    let tx_proof = zk_system.prove_transaction(
        sender_balance,
        transfer_amount,
        transaction_fee,
        sender_secret,
        nullifier_seed,
    )?;
    
    println!("Transaction proof generated successfully");
    
    // Verify the proof
    let is_valid = zk_system.verify_transaction(&tx_proof)?;
    println!("Transaction proof verification: {}", 
        if is_valid { "PASSED" } else { "FAILED" });
    
    // Try with insufficient balance (should fail in implementation)
    println!("\nTesting with insufficient balance...");
    let insufficient_balance = 200; // Less than amount + fee
    
    match zk_system.prove_transaction(
        insufficient_balance,
        transfer_amount,
        transaction_fee,
        sender_secret,
        nullifier_seed,
    ) {
        Ok(proof) => {
            let is_valid = zk_system.verify_transaction(&proof)?;
            println!("Insufficient balance proof verification: {}", 
                if is_valid { "PASSED (unexpected)" } else { "FAILED (expected)" });
        }
        Err(e) => {
            println!("Expected error for insufficient balance: {}", e);
        }
    }
    
    Ok(())
}
```

## Financial Privacy Tutorial

### Tutorial: Building a Private Payment System

This tutorial demonstrates how to build a privacy-preserving payment system using lib-proofs.

#### Step 1: Setup and Initialization

```rust
use lib_proofs::{ZkProofSystem, zk_integration};
use lib_crypto::KeyPair;
use anyhow::Result;
use std::collections::HashMap;

// Account structure with encrypted balance
#[derive(Clone)]
struct PrivateAccount {
    keypair: KeyPair,
    encrypted_balance: u64,  // Encrypted or committed balance
    nonce: u64,             // To prevent replay attacks
}

// Payment system state
struct PrivatePaymentSystem {
    zk_system: ZkProofSystem,
    accounts: HashMap<String, PrivateAccount>,
    nullifier_set: std::collections::HashSet<u64>, // Prevent double spending
}

impl PrivatePaymentSystem {
    fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            accounts: HashMap::new(),
            nullifier_set: std::collections::HashSet::new(),
        })
    }
    
    fn create_account(&mut self, account_id: &str, initial_balance: u64) -> Result<()> {
        let keypair = KeyPair::generate()?;
        let account = PrivateAccount {
            keypair,
            encrypted_balance: initial_balance, // In system, this would be encrypted
            nonce: 0,
        };
        
        self.accounts.insert(account_id.to_string(), account);
        println!("Created account '{}' with balance {}", account_id, initial_balance);
        Ok(())
    }
}
```

#### Step 2: Private Transfer Implementation

```rust
impl PrivatePaymentSystem {
    fn create_private_transfer(
        &self,
        sender_id: &str,
        amount: u64,
        fee: u64,
    ) -> Result<PrivateTransferProof> {
        let sender = self.accounts.get(sender_id)
            .ok_or_else(|| anyhow::anyhow!("Sender account not found"))?;
        
        // Generate unique nullifier for this transaction
        let nullifier_seed = self.generate_nullifier_seed(&sender.keypair, sender.nonce);
        
        // Create zero-knowledge proof
        let proof = self.zk_system.prove_transaction(
            sender.encrypted_balance,
            amount,
            fee,
            self.derive_account_secret(&sender.keypair),
            nullifier_seed,
        )?;
        
        Ok(PrivateTransferProof {
            proof,
            nullifier: nullifier_seed,
            amount_commitment: self.commit_amount(amount)?,
            fee_commitment: self.commit_amount(fee)?,
        })
    }
    
    fn verify_and_execute_transfer(
        &mut self,
        transfer: PrivateTransferProof,
        sender_id: &str,
        receiver_id: &str,
    ) -> Result<bool> {
        // Check nullifier hasn't been used (prevent double spending)
        if self.nullifier_set.contains(&transfer.nullifier) {
            return Err(anyhow::anyhow!("Transaction already processed (double spend attempt)"));
        }
        
        // Verify the zero-knowledge proof
        let is_valid = self.zk_system.verify_transaction(&transfer.proof)?;
        if !is_valid {
            return Ok(false);
        }
        
        // Execute the transfer (update encrypted balances)
        self.execute_balance_updates(sender_id, receiver_id, &transfer)?;
        
        // Record nullifier to prevent reuse
        self.nullifier_set.insert(transfer.nullifier);
        
        println!("Private transfer completed successfully");
        Ok(true)
    }
    
    // Helper methods
    fn generate_nullifier_seed(&self, keypair: &KeyPair, nonce: u64) -> u64 {
        // In implementation, this would be a cryptographic hash
        // hash(keypair.private_key, nonce)
        12345 + nonce // Simplified for example
    }
    
    fn derive_account_secret(&self, keypair: &KeyPair) -> u64 {
        // Derive secret from private key
        54321 // Simplified for example
    }
    
    fn commit_amount(&self, amount: u64) -> Result<u64> {
        // Create commitment to amount with random blinding factor
        // commitment = hash(amount, randomness)
        Ok(amount * 999) // Simplified for example
    }
    
    fn execute_balance_updates(
        &mut self,
        sender_id: &str,
        receiver_id: &str,
        transfer: &PrivateTransferProof,
    ) -> Result<()> {
        // In a system, this would update encrypted/committed balances
        // For this example, we'll simulate the updates
        
        if let Some(sender) = self.accounts.get_mut(sender_id) {
            sender.nonce += 1;
            // Update encrypted balance (subtract amount + fee)
        }
        
        if let Some(receiver) = self.accounts.get_mut(receiver_id) {
            // Update encrypted balance (add amount)
        }
        
        Ok(())
    }
}

struct PrivateTransferProof {
    proof: lib_proofs::plonky2::Plonky2Proof,
    nullifier: u64,
    amount_commitment: u64,
    fee_commitment: u64,
}
```

#### Step 3: Running the Payment System

```rust
fn private_payment_tutorial() -> Result<()> {
    println!("=== Private Payment System Tutorial ===\n");
    
    let mut payment_system = PrivatePaymentSystem::new()?;
    
    // Step 1: Create accounts
    println!("Step 1: Creating accounts");
    payment_system.create_account("alice", 1000)?;
    payment_system.create_account("bob", 500)?;
    payment_system.create_account("charlie", 750)?;
    
    // Step 2: Create private transfer
    println!("\nStep 2: Alice sends 200 to Bob privately");
    let transfer = payment_system.create_private_transfer("alice", 200, 5)?;
    println!("Transfer proof created");
    
    // Step 3: Verify and execute transfer
    println!("\nStep 3: Verifying and executing transfer");
    let success = payment_system.verify_and_execute_transfer(transfer, "alice", "bob")?;
    println!("Transfer result: {}", if success { "SUCCESS" } else { "FAILED" });
    
    // Step 4: Attempt double spend (should fail)
    println!("\nStep 4: Testing double spend protection");
    let duplicate_transfer = payment_system.create_private_transfer("alice", 200, 5)?;
    match payment_system.verify_and_execute_transfer(duplicate_transfer, "alice", "bob") {
        Ok(_) => println!("ERROR: Double spend not detected!"),
        Err(e) => println!("Double spend correctly prevented: {}", e),
    }
    
    println!("\nPrivate payment system tutorial completed successfully!");
    Ok(())
}
```

## Identity Verification Tutorial

### Tutorial: Anonymous Age Verification System

This tutorial shows how to implement an age verification system that proves someone is old enough without revealing their exact age.

#### Step 1: Identity Setup

```rust
use lib_proofs::zk_integration;
use lib_crypto::KeyPair;

struct DigitalIdentity {
    keypair: KeyPair,
    age: u64,
    jurisdiction: u64,
    credential_hash: u64,
}

struct AgeVerificationSystem {
    trusted_authorities: Vec<String>,
    verification_requests: Vec<VerificationRequest>,
}

struct VerificationRequest {
    request_id: String,
    min_age_required: u64,
    jurisdiction_required: u64,
    service_name: String,
}

impl DigitalIdentity {
    fn new(age: u64, jurisdiction: u64) -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
            age,
            jurisdiction,
            credential_hash: 9999, // Simulated credential
        })
    }
    
    fn prove_age_eligibility(
        &self,
        min_age: u64,
        required_jurisdiction: u64,
    ) -> Result<AgeProof> {
        println!("Generating age proof...");
        println!("- Proving age >= {} without revealing actual age", min_age);
        if required_jurisdiction > 0 {
            println!("- Proving jurisdiction matches {}", required_jurisdiction);
        }
        
        let identity_proof = zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            self.credential_hash,
            min_age,
            required_jurisdiction,
        )?;
        
        Ok(AgeProof {
            identity_proof,
            public_key: self.keypair.public_key.clone(),
        })
    }
}

struct AgeProof {
    identity_proof: lib_proofs::types::ZkProof,
    public_key: lib_crypto::PublicKey,
}
```

#### Step 2: Verification Service

```rust
impl AgeVerificationSystem {
    fn new() -> Self {
        Self {
            trusted_authorities: vec![
                "Department of Motor Vehicles".to_string(),
                "Passport Office".to_string(),
                "University Registrar".to_string(),
            ],
            verification_requests: Vec::new(),
        }
    }
    
    fn create_verification_request(
        &mut self,
        service_name: &str,
        min_age: u64,
        jurisdiction: u64,
    ) -> String {
        let request_id = format!("req_{}", self.verification_requests.len() + 1);
        
        let request = VerificationRequest {
            request_id: request_id.clone(),
            min_age_required: min_age,
            jurisdiction_required: jurisdiction,
            service_name: service_name.to_string(),
        };
        
        self.verification_requests.push(request);
        println!("Created verification request: {}", request_id);
        println!("- Service: {}", service_name);
        println!("- Minimum age: {}", min_age);
        if jurisdiction > 0 {
            println!("- Required jurisdiction: {}", jurisdiction);
        }
        
        request_id
    }
    
    fn verify_age_proof(
        &self,
        request_id: &str,
        proof: &AgeProof,
    ) -> Result<VerificationResult> {
        let request = self.verification_requests
            .iter()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| anyhow::anyhow!("Verification request not found"))?;
        
        println!("Verifying age proof for request: {}", request_id);
        
        // Verify the zero-knowledge proof
        let is_valid = proof.identity_proof.verify()?;
        if !is_valid {
            return Ok(VerificationResult {
                approved: false,
                reason: "Invalid proof".to_string(),
                service: request.service_name.clone(),
            });
        }
        
        // In a system, you would also verify:
        // 1. The public key is associated with a trusted identity
        // 2. The credential hash corresponds to a valid credential
        // 3. The proof parameters match the request requirements
        
        println!("Age verification successful!");
        
        Ok(VerificationResult {
            approved: true,
            reason: "Age and jurisdiction requirements satisfied".to_string(),
            service: request.service_name.clone(),
        })
    }
}

struct VerificationResult {
    approved: bool,
    reason: String,
    service: String,
}
```

#### Step 3: Complete Age Verification Example

```rust
fn age_verification_tutorial() -> Result<()> {
    println!("=== Anonymous Age Verification Tutorial ===\n");
    
    // Step 1: Create digital identities
    println!("Step 1: Creating digital identities");
    let alice = DigitalIdentity::new(25, 840)?; // 25 years old, US jurisdiction (840)
    let bob = DigitalIdentity::new(17, 840)?;   // 17 years old, US jurisdiction
    let charlie = DigitalIdentity::new(30, 124)?; // 30 years old, Canada jurisdiction (124)
    
    println!("Created identities for Alice (25, US), Bob (17, US), Charlie (30, CA)");
    
    // Step 2: Create verification service
    println!("\nStep 2: Setting up age verification service");
    let mut verification_service = AgeVerificationSystem::new();
    
    // Step 3: Create verification requests
    println!("\nStep 3: Creating verification requests");
    let alcohol_request = verification_service.create_verification_request(
        "Liquor Store", 21, 840 // Must be 21+ and in US
    );
    
    let movie_request = verification_service.create_verification_request(
        "Movie Theater", 18, 0 // Must be 18+, any jurisdiction
    );
    
    // Step 4: Alice tries to buy alcohol (should succeed)
    println!("\nStep 4: Alice (25) attempts to buy alcohol (requires 21+, US)");
    let alice_proof = alice.prove_age_eligibility(21, 840)?;
    let alice_result = verification_service.verify_age_proof(&alcohol_request, &alice_proof)?;
    
    println!("Alice's verification: {} - {}", 
        if alice_result.approved { "APPROVED" } else { "DENIED" },
        alice_result.reason);
    
    // Step 5: Bob tries to buy alcohol (should fail - too young)
    println!("\nStep 5: Bob (17) attempts to buy alcohol (requires 21+, US)");
    match bob.prove_age_eligibility(21, 840) {
        Ok(bob_proof) => {
            let bob_result = verification_service.verify_age_proof(&alcohol_request, &bob_proof)?;
            println!("Bob's verification: {} - {}", 
                if bob_result.approved { "APPROVED" } else { "DENIED" },
                bob_result.reason);
        }
        Err(e) => {
            println!("Bob's proof generation failed (expected): {}", e);
        }
    }
    
    // Step 6: Charlie tries to see a movie (should succeed - age OK, jurisdiction not required)
    println!("\nStep 6: Charlie (30, CA) attempts to see R-rated movie (requires 18+, any jurisdiction)");
    let charlie_proof = charlie.prove_age_eligibility(18, 0)?;
    let charlie_result = verification_service.verify_age_proof(&movie_request, &charlie_proof)?;
    
    println!("Charlie's verification: {} - {}", 
        if charlie_result.approved { "APPROVED" } else { "DENIED" },
        charlie_result.reason);
    
    println!("\nAge verification tutorial completed successfully!");
    Ok(())
}
```

## Decentralized Storage Tutorial

### Tutorial: Proving Data Integrity Without Revealing Data

This tutorial demonstrates how to prove that data is stored correctly and can be accessed without revealing the actual data content.

#### Step 1: Storage System Setup

```rust
use lib_proofs::ZkProofSystem;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

struct DecentralizedStorageNode {
    node_id: u64,
    zk_system: ZkProofSystem,
    stored_data: HashMap<u64, StoredFile>,
    access_permissions: HashMap<u64, Vec<AccessPermission>>,
}

struct StoredFile {
    data_hash: u64,
    chunks: Vec<DataChunk>,
    total_size: u64,
    storage_secret: u64,
    timestamp: u64,
}

struct DataChunk {
    chunk_id: u64,
    chunk_hash: u64,
    size: u64,
}

struct AccessPermission {
    user_id: u64,
    permission_level: u64,
    granted_by: u64,
}

impl DecentralizedStorageNode {
    fn new(node_id: u64) -> Result<Self> {
        Ok(Self {
            node_id,
            zk_system: ZkProofSystem::new()?,
            stored_data: HashMap::new(),
            access_permissions: HashMap::new(),
        })
    }
}
```

#### Step 2: Data Storage with Integrity Proofs

```rust
impl DecentralizedStorageNode {
    fn store_file(
        &mut self,
        file_data: &[u8],
        owner_id: u64,
    ) -> Result<StorageProof> {
        println!("Storing file of {} bytes", file_data.len());
        
        // Generate unique file hash
        let mut hasher = Sha256::new();
        hasher.update(file_data);
        let hash_result = hasher.finalize();
        let data_hash = u64::from_be_bytes([
            hash_result[0], hash_result[1], hash_result[2], hash_result[3],
            hash_result[4], hash_result[5], hash_result[6], hash_result[7],
        ]);
        
        // Split into chunks for distributed storage
        let chunks = self.create_chunks(file_data)?;
        let chunk_count = chunks.len() as u64;
        let total_size = file_data.len() as u64;
        
        // Generate storage secret for this file
        let storage_secret = self.generate_storage_secret(data_hash, owner_id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create data integrity proof
        let integrity_proof = self.zk_system.prove_data_integrity(
            data_hash,
            chunk_count,
            total_size,
            self.compute_checksum(&chunks),
            storage_secret,
            timestamp,
            1000, // max_chunks
            10 * 1024 * 1024, // max_size (10MB)
        )?;
        
        // Store the file
        let stored_file = StoredFile {
            data_hash,
            chunks,
            total_size,
            storage_secret,
            timestamp,
        };
        
        self.stored_data.insert(data_hash, stored_file);
        
        // Grant full access to owner
        self.access_permissions.insert(data_hash, vec![
            AccessPermission {
                user_id: owner_id,
                permission_level: 100, // Full access
                granted_by: owner_id,
            }
        ]);
        
        println!("File stored with hash: {}", data_hash);
        
        Ok(StorageProof {
            data_hash,
            integrity_proof,
            node_id: self.node_id,
            timestamp,
        })
    }
    
    fn prove_access_capability(
        &self,
        data_hash: u64,
        user_id: u64,
        requested_permission: u64,
    ) -> Result<AccessProof> {
        println!("Generating access proof for user {} on file {}", user_id, data_hash);
        
        // Find user's permission level
        let permissions = self.access_permissions.get(&data_hash)
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;
        
        let user_permission = permissions.iter()
            .find(|p| p.user_id == user_id)
            .ok_or_else(|| anyhow::anyhow!("User has no access to this file"))?
            .permission_level;
        
        // Generate access key from user credentials
        let access_key = self.derive_access_key(user_id, data_hash);
        let user_secret = self.generate_user_secret(user_id);
        
        // Create storage access proof
        let access_proof = self.zk_system.prove_storage_access(
            access_key,
            user_secret,
            data_hash,
            user_permission,
            requested_permission,
        )?;
        
        Ok(AccessProof {
            data_hash,
            user_id,
            access_proof,
            node_id: self.node_id,
        })
    }
    
    fn verify_and_retrieve(
        &self,
        access_proof: &AccessProof,
    ) -> Result<Option<&StoredFile>> {
        println!("Verifying access proof and retrieving file");
        
        // Verify the access proof
        let is_valid = self.zk_system.verify_storage_access(&access_proof.access_proof)?;
        if !is_valid {
            println!("Access proof verification failed");
            return Ok(None);
        }
        
        // Retrieve the file if proof is valid
        let file = self.stored_data.get(&access_proof.data_hash);
        if file.is_some() {
            println!("Access granted - file retrieved");
        } else {
            println!("File not found on this node");
        }
        
        Ok(file)
    }
    
    // Helper methods
    fn create_chunks(&self, data: &[u8]) -> Result<Vec<DataChunk>> {
        const CHUNK_SIZE: usize = 1024; // 1KB chunks
        let mut chunks = Vec::new();
        
        for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(chunk_data);
            let hash_result = hasher.finalize();
            let chunk_hash = u64::from_be_bytes([
                hash_result[0], hash_result[1], hash_result[2], hash_result[3],
                hash_result[4], hash_result[5], hash_result[6], hash_result[7],
            ]);
            
            chunks.push(DataChunk {
                chunk_id: i as u64,
                chunk_hash,
                size: chunk_data.len() as u64,
            });
        }
        
        Ok(chunks)
    }
    
    fn compute_checksum(&self, chunks: &[DataChunk]) -> u64 {
        chunks.iter().map(|c| c.chunk_hash).sum()
    }
    
    fn generate_storage_secret(&self, data_hash: u64, owner_id: u64) -> u64 {
        // In implementation: hash(node_secret, data_hash, owner_id)
        self.node_id * 1000 + data_hash % 1000 + owner_id % 100
    }
    
    fn derive_access_key(&self, user_id: u64, data_hash: u64) -> u64 {
        // In implementation: hash(user_credentials, data_hash)
        user_id * 7919 + data_hash % 7919
    }
    
    fn generate_user_secret(&self, user_id: u64) -> u64 {
        // In implementation: derived from user's private key
        user_id * 991 + 12345
    }
}

struct StorageProof {
    data_hash: u64,
    integrity_proof: lib_proofs::plonky2::Plonky2Proof,
    node_id: u64,
    timestamp: u64,
}

struct AccessProof {
    data_hash: u64,
    user_id: u64,
    access_proof: lib_proofs::plonky2::Plonky2Proof,
    node_id: u64,
}
```

#### Step 3: Running the Storage System

```rust
fn decentralized_storage_tutorial() -> Result<()> {
    println!("=== Decentralized Storage Tutorial ===\n");
    
    // Step 1: Create storage nodes
    println!("Step 1: Creating storage nodes");
    let mut node1 = DecentralizedStorageNode::new(1001)?;
    let mut node2 = DecentralizedStorageNode::new(1002)?;
    
    // Step 2: Store a file
    println!("\nStep 2: Alice stores a document");
    let alice_id = 2001;
    let document_data = b"This is Alice's private document with sensitive information.";
    
    let storage_proof = node1.store_file(document_data, alice_id)?;
    println!("Document stored with integrity proof");
    
    // Step 3: Alice accesses her own file (should succeed)
    println!("\nStep 3: Alice accesses her own document");
    let alice_access_proof = node1.prove_access_capability(
        storage_proof.data_hash,
        alice_id,
        50, // Requesting read access (permission level 50)
    )?;
    
    let retrieved_file = node1.verify_and_retrieve(&alice_access_proof)?;
    match retrieved_file {
        Some(file) => {
            println!("Alice successfully retrieved her document");
            println!("- File size: {} bytes", file.total_size);
            println!("- Number of chunks: {}", file.chunks.len());
        }
        None => println!("Alice's access was denied"),
    }
    
    // Step 4: Bob tries to access Alice's file (should fail)
    println!("\nStep 4: Bob attempts to access Alice's document");
    let bob_id = 2002;
    
    match node1.prove_access_capability(storage_proof.data_hash, bob_id, 50) {
        Ok(bob_access_proof) => {
            let bob_retrieval = node1.verify_and_retrieve(&bob_access_proof)?;
            match bob_retrieval {
                Some(_) => println!("ERROR: Bob gained unauthorized access!"),
                None => println!("Bob's access correctly denied"),
            }
        }
        Err(e) => {
            println!("Bob's access attempt failed (expected): {}", e);
        }
    }
    
    // Step 5: Grant Bob read access
    println!("\nStep 5: Alice grants Bob read access");
    if let Some(permissions) = node1.access_permissions.get_mut(&storage_proof.data_hash) {
        permissions.push(AccessPermission {
            user_id: bob_id,
            permission_level: 25, // Read-only access
            granted_by: alice_id,
        });
        println!("Bob granted read access by Alice");
    }
    
    // Step 6: Bob accesses file with permission (should succeed)
    println!("\nStep 6: Bob accesses document with granted permission");
    let bob_access_proof = node1.prove_access_capability(
        storage_proof.data_hash,
        bob_id,
        25, // Requesting read access (has permission level 25)
    )?;
    
    let bob_retrieved_file = node1.verify_and_retrieve(&bob_access_proof)?;
    match bob_retrieved_file {
        Some(file) => {
            println!("Bob successfully retrieved the document with permission");
            println!("- File size: {} bytes", file.total_size);
        }
        None => println!("Bob's access was denied despite permission"),
    }
    
    // Step 7: Bob tries to request write access (should fail)
    println!("\nStep 7: Bob attempts to request write access");
    match node1.prove_access_capability(storage_proof.data_hash, bob_id, 75) {
        Ok(write_proof) => {
            let write_access = node1.verify_and_retrieve(&write_proof)?;
            if write_access.is_some() {
                println!("ERROR: Bob gained write access without permission!");
            } else {
                println!("Bob's write access correctly denied (insufficient permission level)");
            }
        }
        Err(e) => {
            println!("Bob's write access attempt failed (expected): {}", e);
        }
    }
    
    println!("\nDecentralized storage tutorial completed successfully!");
    Ok(())
}
```

## Network Routing Tutorial

### Tutorial: Anonymous Network Routing with Capability Proofs

This tutorial shows how nodes can prove their routing capabilities without revealing network topology.

#### Step 1: Network Setup

```rust
use lib_proofs::ZkProofSystem;
use std::collections::{HashMap, HashSet};

struct NetworkNode {
    node_id: u64,
    zk_system: ZkProofSystem,
    routing_table: HashMap<u64, RouteInfo>,
    network_secret: u64,
    bandwidth_capacity: u64,
}

struct RouteInfo {
    destination: u64,
    next_hop: u64,
    hop_count: u64,
    available_bandwidth: u64,
    latency: u64,
}

struct NetworkTopology {
    nodes: HashMap<u64, NetworkNode>,
    connections: HashMap<u64, HashSet<u64>>,
}

impl NetworkNode {
    fn new(node_id: u64, bandwidth_capacity: u64) -> Result<Self> {
        Ok(Self {
            node_id,
            zk_system: ZkProofSystem::new()?,
            routing_table: HashMap::new(),
            network_secret: node_id * 7919 + 12345, // Derived from node credentials
            bandwidth_capacity,
        })
    }
    
    fn add_route(&mut self, destination: u64, next_hop: u64, hop_count: u64, bandwidth: u64, latency: u64) {
        self.routing_table.insert(destination, RouteInfo {
            destination,
            next_hop,
            hop_count,
            available_bandwidth: bandwidth,
            latency,
        });
    }
}
```

#### Step 2: Routing Capability Proofs

```rust
impl NetworkNode {
    fn prove_routing_capability(
        &self,
        destination: u64,
        max_hops: u64,
        min_bandwidth: u64,
    ) -> Result<RoutingProof> {
        println!("Node {} generating routing proof for destination {}", self.node_id, destination);
        
        let route = self.routing_table.get(&destination)
            .ok_or_else(|| anyhow::anyhow!("No route to destination {}", destination))?;
        
        println!("Route found:");
        println!("- Hops: {} (max allowed: {})", route.hop_count, max_hops);
        println!("- Bandwidth: {} (min required: {})", route.available_bandwidth, min_bandwidth);
        println!("- Latency: {}ms", route.latency);
        
        // Verify we can meet the requirements
        if route.hop_count > max_hops {
            return Err(anyhow::anyhow!("Route exceeds maximum hop count"));
        }
        if route.available_bandwidth < min_bandwidth {
            return Err(anyhow::anyhow!("Insufficient bandwidth available"));
        }
        
        // Generate zero-knowledge proof of routing capability
        let routing_proof = self.zk_system.prove_routing(
            self.node_id,           // source
            destination,            // destination (public)
            route.hop_count,        // actual hop count (private)
            route.available_bandwidth, // actual bandwidth (private)
            route.latency,          // actual latency (private)
            self.network_secret,    // node's routing secret (private)
            max_hops,              // max hops constraint (public)
            min_bandwidth,         // min bandwidth constraint (public)
        )?;
        
        println!("Routing proof generated successfully");
        
        Ok(RoutingProof {
            source_node: self.node_id,
            destination,
            max_hops,
            min_bandwidth,
            proof: routing_proof,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }
    
    fn verify_routing_proof(&self, routing_proof: &RoutingProof) -> Result<bool> {
        println!("Verifying routing proof from node {}", routing_proof.source_node);
        
        // Verify the zero-knowledge proof
        let is_valid = self.zk_system.verify_routing(&routing_proof.proof)?;
        
        if is_valid {
            println!("Routing proof verification: PASSED");
            println!("- Node {} can route to {} within constraints", 
                routing_proof.source_node, routing_proof.destination);
        } else {
            println!("Routing proof verification: FAILED");
        }
        
        Ok(is_valid)
    }
    
    fn request_routing_service(
        &self,
        destination: u64,
        quality_requirements: QualityRequirements,
    ) -> Result<Vec<RoutingOffer>> {
        println!("Requesting routing service to destination {}", destination);
        println!("Requirements: max {} hops, min {} bandwidth", 
            quality_requirements.max_hops, quality_requirements.min_bandwidth);
        
        // In a network, this would broadcast the request
        // For this example, we'll simulate responses from other nodes
        Ok(Vec::new()) // Placeholder
    }
}

struct RoutingProof {
    source_node: u64,
    destination: u64,
    max_hops: u64,
    min_bandwidth: u64,
    proof: lib_proofs::plonky2::Plonky2Proof,
    timestamp: u64,
}

struct QualityRequirements {
    max_hops: u64,
    min_bandwidth: u64,
    max_latency: u64,
}

struct RoutingOffer {
    provider_node: u64,
    proof: RoutingProof,
    cost: u64,
}
```

#### Step 3: Network Routing Example

```rust
impl NetworkTopology {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            connections: HashMap::new(),
        }
    }
    
    fn add_node(&mut self, node: NetworkNode) {
        let node_id = node.node_id;
        self.nodes.insert(node_id, node);
        self.connections.insert(node_id, HashSet::new());
    }
    
    fn connect_nodes(&mut self, node1: u64, node2: u64) {
        self.connections.entry(node1).or_default().insert(node2);
        self.connections.entry(node2).or_default().insert(node1);
    }
    
    fn setup_routing_tables(&mut self) {
        // Simplified routing table setup
        // In practice, this would use a distributed routing protocol
        
        // Node 1001 can reach 1003 via 1002 (2 hops, 500 bandwidth, 20ms latency)
        if let Some(node) = self.nodes.get_mut(&1001) {
            node.add_route(1003, 1002, 2, 500, 20);
            node.add_route(1004, 1002, 3, 300, 35);
        }
        
        // Node 1002 can reach 1003 directly (1 hop, 800 bandwidth, 10ms latency)
        if let Some(node) = self.nodes.get_mut(&1002) {
            node.add_route(1003, 1003, 1, 800, 10);
            node.add_route(1004, 1004, 1, 600, 15);
        }
        
        // Node 1003 can reach 1001 via 1002 (2 hops, 450 bandwidth, 25ms latency)
        if let Some(node) = self.nodes.get_mut(&1003) {
            node.add_route(1001, 1002, 2, 450, 25);
        }
    }
}

fn network_routing_tutorial() -> Result<()> {
    println!("=== Anonymous Network Routing Tutorial ===\n");
    
    // Step 1: Create network topology
    println!("Step 1: Creating network topology");
    let mut network = NetworkTopology::new();
    
    // Add nodes with different capabilities
    network.add_node(NetworkNode::new(1001, 1000)?); // Node A
    network.add_node(NetworkNode::new(1002, 1200)?); // Node B (higher capacity)
    network.add_node(NetworkNode::new(1003, 800)?);  // Node C
    network.add_node(NetworkNode::new(1004, 600)?);  // Node D
    
    // Connect nodes
    network.connect_nodes(1001, 1002);
    network.connect_nodes(1002, 1003);
    network.connect_nodes(1002, 1004);
    network.connect_nodes(1003, 1004);
    
    // Setup routing tables
    network.setup_routing_tables();
    
    println!("Network created with 4 nodes and routing tables configured");
    
    // Step 2: Node 1001 proves it can route to 1003
    println!("\nStep 2: Node 1001 proves routing capability to 1003");
    let node1001 = network.nodes.get(&1001).unwrap();
    let routing_proof = node1001.prove_routing_capability(
        1003, // destination
        3,    // max 3 hops allowed
        400,  // minimum 400 bandwidth required
    )?;
    
    // Step 3: Another node verifies the routing proof
    println!("\nStep 3: Node 1002 verifies the routing proof");
    let node1002 = network.nodes.get(&1002).unwrap();
    let is_valid = node1002.verify_routing_proof(&routing_proof)?;
    
    println!("Proof validation result: {}", if is_valid { "VALID" } else { "INVALID" });
    
    // Step 4: Test with insufficient bandwidth requirement
    println!("\nStep 4: Node 1001 attempts to prove capability with high bandwidth requirement");
    match node1001.prove_routing_capability(1003, 3, 1000) {
        Ok(proof) => {
            println!("Proof generated unexpectedly");
            let verification = node1002.verify_routing_proof(&proof)?;
            println!("Verification result: {}", if verification { "VALID" } else { "INVALID" });
        }
        Err(e) => {
            println!("Proof generation failed as expected: {}", e);
        }
    }
    
    // Step 5: Test with excessive hop count requirement
    println!("\nStep 5: Node 1001 attempts to prove capability with strict hop limit");
    match node1001.prove_routing_capability(1003, 1, 300) {
        Ok(proof) => {
            println!("Proof generated unexpectedly");
            let verification = node1002.verify_routing_proof(&proof)?;
            println!("Verification result: {}", if verification { "VALID" } else { "INVALID" });
        }
        Err(e) => {
            println!("Proof generation failed as expected: {}", e);
        }
    }
    
    // Step 6: Demonstrate privacy preservation
    println!("\nStep 6: Privacy Analysis");
    println!("The routing proof reveals:");
    println!("- Source node: {}", routing_proof.source_node);
    println!("- Destination node: {}", routing_proof.destination);
    println!("- Maximum hops allowed: {}", routing_proof.max_hops);
    println!("- Minimum bandwidth required: {}", routing_proof.min_bandwidth);
    println!("\nThe routing proof DOES NOT reveal:");
    println!("- Exact hop count of the route");
    println!("- Actual available bandwidth");
    println!("- Specific path taken (intermediate nodes)");
    println!("- Network topology details");
    println!("- Node's routing table contents");
    
    println!("\nNetwork routing tutorial completed successfully!");
    Ok(())
}
```

## Advanced Patterns

### Recursive Proof Composition

```rust
use lib_proofs::{ZkProofSystem, verifiers::RecursiveProofAggregator};

fn recursive_proof_example() -> Result<()> {
    println!("=== Recursive Proof Composition Example ===\n");
    
    let zk_system = ZkProofSystem::new()?;
    let aggregator = RecursiveProofAggregator::new()?;
    
    // Generate multiple base proofs
    println!("Step 1: Generating base proofs");
    let mut base_proofs = Vec::new();
    
    for i in 0..5 {
        let proof = zk_system.prove_range(
            100 + i * 100, // values: 100, 200, 300, 400, 500
            12345 + i,     // different secrets
            0,             // min
            1000,          // max
        )?;
        base_proofs.push(proof);
        println!("Generated proof {} for value in range [0, 1000]", i + 1);
    }
    
    // Aggregate proofs recursively
    println!("\nStep 2: Aggregating proofs recursively");
    // Note: This would require implementing recursive aggregation
    // For now, we demonstrate the concept
    
    println!("All {} proofs can be aggregated into a single proof", base_proofs.len());
    println!("The aggregated proof would verify that all 5 values are in range [0, 1000]");
    println!("Verification time would be constant regardless of the number of base proofs");
    
    Ok(())
}
```

### Batch Verification

```rust
fn batch_verification_example() -> Result<()> {
    println!("=== Batch Verification Example ===\n");
    
    let zk_system = ZkProofSystem::new()?;
    
    // Generate a batch of transaction proofs
    println!("Step 1: Generating batch of transaction proofs");
    let mut tx_proofs = Vec::new();
    let batch_size = 10;
    
    for i in 0..batch_size {
        let proof = zk_system.prove_transaction(
            1000 + i * 100,  // varying balances
            50 + i * 10,     // varying amounts
            5,               // fixed fee
            12345 + i,       // varying secrets
            67890 + i,       // varying nullifiers
        )?;
        tx_proofs.push(proof);
    }
    
    println!("Generated {} transaction proofs", batch_size);
    
    // Individual verification
    println!("\nStep 2: Individual verification");
    let start = std::time::Instant::now();
    let mut all_valid = true;
    
    for (i, proof) in tx_proofs.iter().enumerate() {
        let is_valid = zk_system.verify_transaction(proof)?;
        if !is_valid {
            println!("Proof {} failed verification", i);
            all_valid = false;
        }
    }
    
    let individual_time = start.elapsed();
    println!("Individual verification: {:?} for {} proofs", individual_time, batch_size);
    println!("All proofs valid: {}", all_valid);
    
    // Batch verification (simulated - would be more efficient in practice)
    println!("\nStep 3: Batch verification");
    let start = std::time::Instant::now();
    
    // In a implementation, batch verification would be significantly faster
    let batch_valid = tx_proofs.iter().all(|proof| {
        zk_system.verify_transaction(proof).unwrap_or(false)
    });
    
    let batch_time = start.elapsed();
    println!("Batch verification: {:?} for {} proofs", batch_time, batch_size);
    println!("Batch valid: {}", batch_valid);
    
    if individual_time > batch_time {
        let speedup = individual_time.as_secs_f64() / batch_time.as_secs_f64();
        println!("Batch verification speedup: {:.2}x", speedup);
    }
    
    Ok(())
}
```

## Real-World Integration

### Complete Application Example

```rust
// This example ties together all the tutorials into a complete application
fn complete_application_example() -> Result<()> {
    println!("=== Complete Privacy-Preserving Application ===\n");
    
    // Initialize all systems
    let mut payment_system = PrivatePaymentSystem::new()?;
    let mut verification_system = AgeVerificationSystem::new();
    let mut storage_node = DecentralizedStorageNode::new(3001)?;
    let mut network = NetworkTopology::new();
    
    // Setup network
    network.add_node(NetworkNode::new(3001, 1000)?);
    network.add_node(NetworkNode::new(3002, 1200)?);
    network.setup_routing_tables();
    
    // Create users
    println!("Creating user accounts and identities...");
    payment_system.create_account("alice", 2000)?;
    payment_system.create_account("bob", 1500)?;
    
    let alice_identity = DigitalIdentity::new(25, 840)?;
    let bob_identity = DigitalIdentity::new(19, 840)?;
    
    // Scenario 1: Age verification for service access
    println!("\n--- Scenario 1: Age-Gated Service Access ---");
    let age_verification_req = verification_system.create_verification_request(
        "Premium Content Platform", 21, 840
    );
    
    // Alice can access (25 >= 21)
    let alice_age_proof = alice_identity.prove_age_eligibility(21, 840)?;
    let alice_age_result = verification_system.verify_age_proof(&age_verification_req, &alice_age_proof)?;
    println!("Alice's access: {}", if alice_age_result.approved { "GRANTED" } else { "DENIED" });
    
    // Bob cannot access (19 < 21)
    match bob_identity.prove_age_eligibility(21, 840) {
        Ok(bob_age_proof) => {
            let bob_age_result = verification_system.verify_age_proof(&age_verification_req, &bob_age_proof)?;
            println!("Bob's access: {}", if bob_age_result.approved { "GRANTED" } else { "DENIED" });
        }
        Err(_) => println!("Bob's access: DENIED (age verification failed)"),
    }
    
    // Scenario 2: Private payment for service
    println!("\n--- Scenario 2: Private Payment ---");
    if alice_age_result.approved {
        println!("Alice makes private payment for premium service...");
        let payment_proof = payment_system.create_private_transfer("alice", 100, 5)?;
        let payment_success = payment_system.verify_and_execute_transfer(
            payment_proof, "alice", "service_provider"
        )?;
        println!("Payment result: {}", if payment_success { "SUCCESS" } else { "FAILED" });
    }
    
    // Scenario 3: Private document storage
    println!("\n--- Scenario 3: Private Document Storage ---");
    let alice_document = b"Alice's private medical records - confidential";
    let storage_proof = storage_node.store_file(alice_document, 2001)?;
    
    // Alice accesses her document
    let alice_access_proof = storage_node.prove_access_capability(
        storage_proof.data_hash, 2001, 50
    )?;
    let alice_file = storage_node.verify_and_retrieve(&alice_access_proof)?;
    println!("Alice document retrieval: {}", 
        if alice_file.is_some() { "SUCCESS" } else { "FAILED" });
    
    // Scenario 4: Network routing for data transfer
    println!("\n--- Scenario 4: Anonymous Data Routing ---");
    if let Some(routing_node) = network.nodes.get(&3001) {
        match routing_node.prove_routing_capability(3002, 2, 500) {
            Ok(routing_proof) => {
                if let Some(verifier_node) = network.nodes.get(&3002) {
                    let routing_valid = verifier_node.verify_routing_proof(&routing_proof)?;
                    println!("Routing capability: {}", 
                        if routing_valid { "VERIFIED" } else { "FAILED" });
                }
            }
            Err(_) => println!("Routing capability: NOT AVAILABLE"),
        }
    }
    
    println!("\n=== Application Scenarios Completed ===");
    println!("Demonstrated:");
    println!("✓ Anonymous age verification");
    println!("✓ Private financial transactions");
    println!("✓ Confidential data storage with access control");
    println!("✓ Anonymous network routing capabilities");
    println!("All while preserving user privacy through zero-knowledge proofs!");
    
    Ok(())
}
```

## Running the Examples

To run all examples and tutorials:

```rust
fn main() -> Result<()> {
    println!("lib-proofs Examples and Tutorials\n");
    println!("==================================\n");
    
    // Basic examples
    basic_range_proof()?;
    println!("\n");
    basic_transaction_proof()?;
    println!("\n");
    
    // Tutorials
    private_payment_tutorial()?;
    println!("\n");
    age_verification_tutorial()?;
    println!("\n");
    decentralized_storage_tutorial()?;
    println!("\n");
    network_routing_tutorial()?;
    println!("\n");
    
    // Advanced patterns
    recursive_proof_example()?;
    println!("\n");
    batch_verification_example()?;
    println!("\n");
    
    // Complete application
    complete_application_example()?;
    
    println!("\n All examples and tutorials completed successfully!");
    Ok(())
}
```

# Examples and Tutorials

This document provides comprehensive examples and step-by-step tutorials for using lib-proofs in various scenarios.

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Financial Privacy Tutorial](#financial-privacy-tutorial)
3. [Identity Verification Tutorial](#identity-verification-tutorial)
4. [Decentralized Storage Tutorial](#decentralized-storage-tutorial)
5. [Network Routing Tutorial](#network-routing-tutorial)
6. [Advanced Patterns](#advanced-patterns)
7. [Real-World Integration](#real-world-integration)

## Basic Examples

### Simple Range Proof

```rust
use lib_proofs::{ZkRangeProof, ZkProofSystem};
use anyhow::Result;

fn basic_range_proof() -> Result<()> {
    println!("=== Basic Range Proof Example ===");
    
    // Create a range proof for a secret value
    let secret_value = 750;
    let min_range = 0;
    let max_range = 1000;
    
    println!("Proving that secret value is in range [{}, {}]", min_range, max_range);
    
    // Generate the proof
    let range_proof = ZkRangeProof::generate_simple(secret_value, min_range, max_range)?;
    println!("Proof generated successfully");
    
    // Verify the proof
    let is_valid = range_proof.verify()?;
    println!("Proof verification: {}", if is_valid { "PASSED" } else { "FAILED" });
    
    // Try with value outside range (should fail)
    println!("\nTesting with value outside range...");
    let invalid_proof = ZkRangeProof::generate_simple(1500, min_range, max_range);
    match invalid_proof {
        Ok(proof) => {
            let is_valid = proof.verify()?;
            println!("Invalid proof verification: {}", if is_valid { "PASSED" } else { "FAILED" });
        }
        Err(e) => {
            println!("Expected error for out-of-range value: {}", e);
        }
    }
    
    Ok(())
}
```

### Basic Transaction Proof

```rust
use lib_proofs::ZkProofSystem;
use anyhow::Result;

fn basic_transaction_proof() -> Result<()> {
    println!("=== Basic Transaction Proof Example ===");
    
    // Initialize the ZK proof system
    let zk_system = ZkProofSystem::new()?;
    
    // Transaction details (private)
    let sender_balance = 1000;
    let transfer_amount = 250;
    let transaction_fee = 5;
    let sender_secret = 12345;
    let nullifier_seed = 67890;
    
    println!("Creating transaction proof...");
    println!("- Balance check: {} >= {} + {} = {}", 
        sender_balance, transfer_amount, transaction_fee, 
        transfer_amount + transaction_fee);
    
    // Generate transaction proof
    let tx_proof = zk_system.prove_transaction(
        sender_balance,
        transfer_amount,
        transaction_fee,
        sender_secret,
        nullifier_seed,
    )?;
    
    println!("Transaction proof generated successfully");
    
    // Verify the proof
    let is_valid = zk_system.verify_transaction(&tx_proof)?;
    println!("Transaction proof verification: {}", 
        if is_valid { "PASSED" } else { "FAILED" });
    
    // Try with insufficient balance (should fail in real implementation)
    println!("\nTesting with insufficient balance...");
    let insufficient_balance = 200; // Less than amount + fee
    
    match zk_system.prove_transaction(
        insufficient_balance,
        transfer_amount,
        transaction_fee,
        sender_secret,
        nullifier_seed,
    ) {
        Ok(proof) => {
            let is_valid = zk_system.verify_transaction(&proof)?;
            println!("Insufficient balance proof verification: {}", 
                if is_valid { "PASSED (unexpected)" } else { "FAILED (expected)" });
        }
        Err(e) => {
            println!("Expected error for insufficient balance: {}", e);
        }
    }
    
    Ok(())
}
```

## Financial Privacy Tutorial

### Tutorial: Building a Private Payment System

This tutorial demonstrates how to build a privacy-preserving payment system using lib-proofs.

#### Step 1: Setup and Initialization

```rust
use lib_proofs::{ZkProofSystem, zk_integration};
use lib_crypto::KeyPair;
use anyhow::Result;
use std::collections::HashMap;

// Account structure with encrypted balance
#[derive(Clone)]
struct PrivateAccount {
    keypair: KeyPair,
    encrypted_balance: u64,  // Encrypted or committed balance
    nonce: u64,             // To prevent replay attacks
}

// Payment system state
struct PrivatePaymentSystem {
    zk_system: ZkProofSystem,
    accounts: HashMap<String, PrivateAccount>,
    nullifier_set: std::collections::HashSet<u64>, // Prevent double spending
}

impl PrivatePaymentSystem {
    fn new() -> Result<Self> {
        Ok(Self {
            zk_system: ZkProofSystem::new()?,
            accounts: HashMap::new(),
            nullifier_set: std::collections::HashSet::new(),
        })
    }
    
    fn create_account(&mut self, account_id: &str, initial_balance: u64) -> Result<()> {
        let keypair = KeyPair::generate()?;
        let account = PrivateAccount {
            keypair,
            encrypted_balance: initial_balance, // In real system, this would be encrypted
            nonce: 0,
        };
        
        self.accounts.insert(account_id.to_string(), account);
        println!("Created account '{}' with balance {}", account_id, initial_balance);
        Ok(())
    }
}
```

#### Step 2: Private Transfer Implementation

```rust
impl PrivatePaymentSystem {
    fn create_private_transfer(
        &self,
        sender_id: &str,
        amount: u64,
        fee: u64,
    ) -> Result<PrivateTransferProof> {
        let sender = self.accounts.get(sender_id)
            .ok_or_else(|| anyhow::anyhow!("Sender account not found"))?;
        
        // Generate unique nullifier for this transaction
        let nullifier_seed = self.generate_nullifier_seed(&sender.keypair, sender.nonce);
        
        // Create zero-knowledge proof
        let proof = self.zk_system.prove_transaction(
            sender.encrypted_balance,
            amount,
            fee,
            self.derive_account_secret(&sender.keypair),
            nullifier_seed,
        )?;
        
        Ok(PrivateTransferProof {
            proof,
            nullifier: nullifier_seed,
            amount_commitment: self.commit_amount(amount)?,
            fee_commitment: self.commit_amount(fee)?,
        })
    }
    
    fn verify_and_execute_transfer(
        &mut self,
        transfer: PrivateTransferProof,
        sender_id: &str,
        receiver_id: &str,
    ) -> Result<bool> {
        // Check nullifier hasn't been used (prevent double spending)
        if self.nullifier_set.contains(&transfer.nullifier) {
            return Err(anyhow::anyhow!("Transaction already processed (double spend attempt)"));
        }
        
        // Verify the zero-knowledge proof
        let is_valid = self.zk_system.verify_transaction(&transfer.proof)?;
        if !is_valid {
            return Ok(false);
        }
        
        // Execute the transfer (update encrypted balances)
        self.execute_balance_updates(sender_id, receiver_id, &transfer)?;
        
        // Record nullifier to prevent reuse
        self.nullifier_set.insert(transfer.nullifier);
        
        println!("Private transfer completed successfully");
        Ok(true)
    }
    
    // Helper methods
    fn generate_nullifier_seed(&self, keypair: &KeyPair, nonce: u64) -> u64 {
        // In real implementation, this would be a cryptographic hash
        // hash(keypair.private_key, nonce)
        12345 + nonce // Simplified for example
    }
    
    fn derive_account_secret(&self, keypair: &KeyPair) -> u64 {
        // Derive secret from private key
        54321 // Simplified for example
    }
    
    fn commit_amount(&self, amount: u64) -> Result<u64> {
        // Create commitment to amount with random blinding factor
        // commitment = hash(amount, randomness)
        Ok(amount * 999) // Simplified for example
    }
    
    fn execute_balance_updates(
        &mut self,
        sender_id: &str,
        receiver_id: &str,
        transfer: &PrivateTransferProof,
    ) -> Result<()> {
        // In a real system, this would update encrypted/committed balances
        // For this example, we'll simulate the updates
        
        if let Some(sender) = self.accounts.get_mut(sender_id) {
            sender.nonce += 1;
            // Update encrypted balance (subtract amount + fee)
        }
        
        if let Some(receiver) = self.accounts.get_mut(receiver_id) {
            // Update encrypted balance (add amount)
        }
        
        Ok(())
    }
}

struct PrivateTransferProof {
    proof: lib_proofs::plonky2::Plonky2Proof,
    nullifier: u64,
    amount_commitment: u64,
    fee_commitment: u64,
}
```

#### Step 3: Running the Payment System

```rust
fn private_payment_tutorial() -> Result<()> {
    println!("=== Private Payment System Tutorial ===\n");
    
    let mut payment_system = PrivatePaymentSystem::new()?;
    
    // Step 1: Create accounts
    println!("Step 1: Creating accounts");
    payment_system.create_account("alice", 1000)?;
    payment_system.create_account("bob", 500)?;
    payment_system.create_account("charlie", 750)?;
    
    // Step 2: Create private transfer
    println!("\nStep 2: Alice sends 200 to Bob privately");
    let transfer = payment_system.create_private_transfer("alice", 200, 5)?;
    println!("Transfer proof created");
    
    // Step 3: Verify and execute transfer
    println!("\nStep 3: Verifying and executing transfer");
    let success = payment_system.verify_and_execute_transfer(transfer, "alice", "bob")?;
    println!("Transfer result: {}", if success { "SUCCESS" } else { "FAILED" });
    
    // Step 4: Attempt double spend (should fail)
    println!("\nStep 4: Testing double spend protection");
    let duplicate_transfer = payment_system.create_private_transfer("alice", 200, 5)?;
    match payment_system.verify_and_execute_transfer(duplicate_transfer, "alice", "bob") {
        Ok(_) => println!("ERROR: Double spend not detected!"),
        Err(e) => println!("Double spend correctly prevented: {}", e),
    }
    
    println!("\nPrivate payment system tutorial completed successfully!");
    Ok(())
}
```

## Identity Verification Tutorial

### Tutorial: Anonymous Age Verification System

This tutorial shows how to implement an age verification system that proves someone is old enough without revealing their exact age.

#### Step 1: Identity Setup

```rust
use lib_proofs::zk_integration;
use lib_crypto::KeyPair;

struct DigitalIdentity {
    keypair: KeyPair,
    age: u64,
    jurisdiction: u64,
    credential_hash: u64,
}

struct AgeVerificationSystem {
    trusted_authorities: Vec<String>,
    verification_requests: Vec<VerificationRequest>,
}

struct VerificationRequest {
    request_id: String,
    min_age_required: u64,
    jurisdiction_required: u64,
    service_name: String,
}

impl DigitalIdentity {
    fn new(age: u64, jurisdiction: u64) -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
            age,
            jurisdiction,
            credential_hash: 9999, // Simulated credential
        })
    }
    
    fn prove_age_eligibility(
        &self,
        min_age: u64,
        required_jurisdiction: u64,
    ) -> Result<AgeProof> {
        println!("Generating age proof...");
        println!("- Proving age >= {} without revealing actual age", min_age);
        if required_jurisdiction > 0 {
            println!("- Proving jurisdiction matches {}", required_jurisdiction);
        }
        
        let identity_proof = zk_integration::prove_identity(
            &self.keypair.private_key,
            self.age,
            self.jurisdiction,
            self.credential_hash,
            min_age,
            required_jurisdiction,
        )?;
        
        Ok(AgeProof {
            identity_proof,
            public_key: self.keypair.public_key.clone(),
        })
    }
}

struct AgeProof {
    identity_proof: lib_proofs::types::ZkProof,
    public_key: lib_crypto::PublicKey,
}
```

#### Step 2: Verification Service

```rust
impl AgeVerificationSystem {
    fn new() -> Self {
        Self {
            trusted_authorities: vec![
                "Department of Motor Vehicles".to_string(),
                "Passport Office".to_string(),
                "University Registrar".to_string(),
            ],
            verification_requests: Vec::new(),
        }
    }
    
    fn create_verification_request(
        &mut self,
        service_name: &str,
        min_age: u64,
        jurisdiction: u64,
    ) -> String {
        let request_id = format!("req_{}", self.verification_requests.len() + 1);
        
        let request = VerificationRequest {
            request_id: request_id.clone(),
            min_age_required: min_age,
            jurisdiction_required: jurisdiction,
            service_name: service_name.to_string(),
        };
        
        self.verification_requests.push(request);
        println!("Created verification request: {}", request_id);
        println!("- Service: {}", service_name);
        println!("- Minimum age: {}", min_age);
        if jurisdiction > 0 {
            println!("- Required jurisdiction: {}", jurisdiction);
        }
        
        request_id
    }
    
    fn verify_age_proof(
        &self,
        request_id: &str,
        proof: &AgeProof,
    ) -> Result<VerificationResult> {
        let request = self.verification_requests
            .iter()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| anyhow::anyhow!("Verification request not found"))?;
        
        println!("Verifying age proof for request: {}", request_id);
        
        // Verify the zero-knowledge proof
        let is_valid = proof.identity_proof.verify()?;
        if !is_valid {
            return Ok(VerificationResult {
                approved: false,
                reason: "Invalid proof".to_string(),
                service: request.service_name.clone(),
            });
        }
        
        // In a real system, you would also verify:
        // 1. The public key is associated with a trusted identity
        // 2. The credential hash corresponds to a valid credential
        // 3. The proof parameters match the request requirements
        
        println!("Age verification successful!");
        
        Ok(VerificationResult {
            approved: true,
            reason: "Age and jurisdiction requirements satisfied".to_string(),
            service: request.service_name.clone(),
        })
    }
}

struct VerificationResult {
    approved: bool,
    reason: String,
    service: String,
}
```

#### Step 3: Complete Age Verification Example

```rust
fn age_verification_tutorial() -> Result<()> {
    println!("=== Anonymous Age Verification Tutorial ===\n");
    
    // Step 1: Create digital identities
    println!("Step 1: Creating digital identities");
    let alice = DigitalIdentity::new(25, 840)?; // 25 years old, US jurisdiction (840)
    let bob = DigitalIdentity::new(17, 840)?;   // 17 years old, US jurisdiction
    let charlie = DigitalIdentity::new(30, 124)?; // 30 years old, Canada jurisdiction (124)
    
    println!("Created identities for Alice (25, US), Bob (17, US), Charlie (30, CA)");
    
    // Step 2: Create verification service
    println!("\nStep 2: Setting up age verification service");
    let mut verification_service = AgeVerificationSystem::new();
    
    // Step 3: Create verification requests
    println!("\nStep 3: Creating verification requests");
    let alcohol_request = verification_service.create_verification_request(
        "Liquor Store", 21, 840 // Must be 21+ and in US
    );
    
    let movie_request = verification_service.create_verification_request(
        "Movie Theater", 18, 0 // Must be 18+, any jurisdiction
    );
    
    // Step 4: Alice tries to buy alcohol (should succeed)
    println!("\nStep 4: Alice (25) attempts to buy alcohol (requires 21+, US)");
    let alice_proof = alice.prove_age_eligibility(21, 840)?;
    let alice_result = verification_service.verify_age_proof(&alcohol_request, &alice_proof)?;
    
    println!("Alice's verification: {} - {}", 
        if alice_result.approved { "APPROVED" } else { "DENIED" },
        alice_result.reason);
    
    // Step 5: Bob tries to buy alcohol (should fail - too young)
    println!("\nStep 5: Bob (17) attempts to buy alcohol (requires 21+, US)");
    match bob.prove_age_eligibility(21, 840) {
        Ok(bob_proof) => {
            let bob_result = verification_service.verify_age_proof(&alcohol_request, &bob_proof)?;
            println!("Bob's verification: {} - {}", 
                if bob_result.approved { "APPROVED" } else { "DENIED" },
                bob_result.reason);
        }
        Err(e) => {
            println!("Bob's proof generation failed (expected): {}", e);
        }
    }
    
    // Step 6: Charlie tries to see a movie (should succeed - age OK, jurisdiction not required)
    println!("\nStep 6: Charlie (30, CA) attempts to see R-rated movie (requires 18+, any jurisdiction)");
    let charlie_proof = charlie.prove_age_eligibility(18, 0)?;
    let charlie_result = verification_service.verify_age_proof(&movie_request, &charlie_proof)?;
    
    println!("Charlie's verification: {} - {}", 
        if charlie_result.approved { "APPROVED" } else { "DENIED" },
        charlie_result.reason);
    
    println!("\nAge verification tutorial completed successfully!");
    Ok(())
}
```

## Decentralized Storage Tutorial

### Tutorial: Proving Data Integrity Without Revealing Data

This tutorial demonstrates how to prove that data is stored correctly and can be accessed without revealing the actual data content.

#### Step 1: Storage System Setup

```rust
use lib_proofs::ZkProofSystem;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

struct DecentralizedStorageNode {
    node_id: u64,
    zk_system: ZkProofSystem,
    stored_data: HashMap<u64, StoredFile>,
    access_permissions: HashMap<u64, Vec<AccessPermission>>,
}

struct StoredFile {
    data_hash: u64,
    chunks: Vec<DataChunk>,
    total_size: u64,
    storage_secret: u64,
    timestamp: u64,
}

struct DataChunk {
    chunk_id: u64,
    chunk_hash: u64,
    size: u64,
}

struct AccessPermission {
    user_id: u64,
    permission_level: u64,
    granted_by: u64,
}

impl DecentralizedStorageNode {
    fn new(node_id: u64) -> Result<Self> {
        Ok(Self {
            node_id,
            zk_system: ZkProofSystem::new()?,
            stored_data: HashMap::new(),
            access_permissions: HashMap::new(),
        })
    }
}
```

#### Step 2: Data Storage with Integrity Proofs

```rust
impl DecentralizedStorageNode {
    fn store_file(
        &mut self,
        file_data: &[u8],
        owner_id: u64,
    ) -> Result<StorageProof> {
        println!("Storing file of {} bytes", file_data.len());
        
        // Generate unique file hash
        let mut hasher = Sha256::new();
        hasher.update(file_data);
        let hash_result = hasher.finalize();
        let data_hash = u64::from_be_bytes([
            hash_result[0], hash_result[1], hash_result[2], hash_result[3],
            hash_result[4], hash_result[5], hash_result[6], hash_result[7],
        ]);
        
        // Split into chunks for distributed storage
        let chunks = self.create_chunks(file_data)?;
        let chunk_count = chunks.len() as u64;
        let total_size = file_data.len() as u64;
        
        // Generate storage secret for this file
        let storage_secret = self.generate_storage_secret(data_hash, owner_id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Create data integrity proof
        let integrity_proof = self.zk_system.prove_data_integrity(
            data_hash,
            chunk_count,
            total_size,
            self.compute_checksum(&chunks),
            storage_secret,
            timestamp,
            1000, // max_chunks
            10 * 1024 * 1024, // max_size (10MB)
        )?;
        
        // Store the file
        let stored_file = StoredFile {
            data_hash,
            chunks,
            total_size,
            storage_secret,
            timestamp,
        };
        
        self.stored_data.insert(data_hash, stored_file);
        
        // Grant full access to owner
        self.access_permissions.insert(data_hash, vec![
            AccessPermission {
                user_id: owner_id,
                permission_level: 100, // Full access
                granted_by: owner_id,
            }
        ]);
        
        println!("File stored with hash: {}", data_hash);
        
        Ok(StorageProof {
            data_hash,
            integrity_proof,
            node_id: self.node_id,
            timestamp,
        })
    }
    
    fn prove_access_capability(
        &self,
        data_hash: u64,
        user_id: u64,
        requested_permission: u64,
    ) -> Result<AccessProof> {
        println!("Generating access proof for user {} on file {}", user_id, data_hash);
        
        // Find user's permission level
        let permissions = self.access_permissions.get(&data_hash)
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;
        
        let user_permission = permissions.iter()
            .find(|p| p.user_id == user_id)
            .ok_or_else(|| anyhow::anyhow!("User has no access to this file"))?
            .permission_level;
        
        // Generate access key from user credentials
        let access_key = self.derive_access_key(user_id, data_hash);
        let user_secret = self.generate_user_secret(user_id);
        
        // Create storage access proof
        let access_proof = self.zk_system.prove_storage_access(
            access_key,
            user_secret,
            data_hash,
            user_permission,
            requested_permission,
        )?;
        
        Ok(AccessProof {
            data_hash,
            user_id,
            access_proof,
            node_id: self.node_id,
        })
    }
    
    fn verify_and_retrieve(
        &self,
        access_proof: &AccessProof,
    ) -> Result<Option<&StoredFile>> {
        println!("Verifying access proof and retrieving file");
        
        // Verify the access proof
        let is_valid = self.zk_system.verify_storage_access(&access_proof.access_proof)?;
        if !is_valid {
            println!("Access proof verification failed");
            return Ok(None);
        }
        
        // Retrieve the file if proof is valid
        let file = self.stored_data.get(&access_proof.data_hash);
        if file.is_some() {
            println!("Access granted - file retrieved");
        } else {
            println!("File not found on this node");
        }
        
        Ok(file)
    }
    
    // Helper methods
    fn create_chunks(&self, data: &[u8]) -> Result<Vec<DataChunk>> {
        const CHUNK_SIZE: usize = 1024; // 1KB chunks
        let mut chunks = Vec::new();
        
        for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(chunk_data);
            let hash_result = hasher.finalize();
            let chunk_hash = u64::from_be_bytes([
                hash_result[0], hash_result[1], hash_result[2], hash_result[3],
                hash_result[4], hash_result[5], hash_result[6], hash_result[7],
            ]);
            
            chunks.push(DataChunk {
                chunk_id: i as u64,
                chunk_hash,
                size: chunk_data.len() as u64,
            });
        }
        
        Ok(chunks)
    }
    
    fn compute_checksum(&self, chunks: &[DataChunk]) -> u64 {
        chunks.iter().map(|c| c.chunk_hash).sum()
    }
    
    fn generate_storage_secret(&self, data_hash: u64, owner_id: u64) -> u64 {
        // In real implementation: hash(node_secret, data_hash, owner_id)
        self.node_id * 1000 + data_hash % 1000 + owner_id % 100
    }
    
    fn derive_access_key(&self, user_id: u64, data_hash: u64) -> u64 {
        // In real implementation: hash(user_credentials, data_hash)
        user_id * 7919 + data_hash % 7919
    }
    
    fn generate_user_secret(&self, user_id: u64) -> u64 {
        // In real implementation: derived from user's private key
        user_id * 991 + 12345
    }
}

struct StorageProof {
    data_hash: u64,
    integrity_proof: lib_proofs::plonky2::Plonky2Proof,
    node_id: u64,
    timestamp: u64,
}

struct AccessProof {
    data_hash: u64,
    user_id: u64,
    access_proof: lib_proofs::plonky2::Plonky2Proof,
    node_id: u64,
}
```

#### Step 3: Running the Storage System

```rust
fn decentralized_storage_tutorial() -> Result<()> {
    println!("=== Decentralized Storage Tutorial ===\n");
    
    // Step 1: Create storage nodes
    println!("Step 1: Creating storage nodes");
    let mut node1 = DecentralizedStorageNode::new(1001)?;
    let mut node2 = DecentralizedStorageNode::new(1002)?;
    
    // Step 2: Store a file
    println!("\nStep 2: Alice stores a document");
    let alice_id = 2001;
    let document_data = b"This is Alice's private document with sensitive information.";
    
    let storage_proof = node1.store_file(document_data, alice_id)?;
    println!("Document stored with integrity proof");
    
    // Step 3: Alice accesses her own file (should succeed)
    println!("\nStep 3: Alice accesses her own document");
    let alice_access_proof = node1.prove_access_capability(
        storage_proof.data_hash,
        alice_id,
        50, // Requesting read access (permission level 50)
    )?;
    
    let retrieved_file = node1.verify_and_retrieve(&alice_access_proof)?;
    match retrieved_file {
        Some(file) => {
            println!("Alice successfully retrieved her document");
            println!("- File size: {} bytes", file.total_size);
            println!("- Number of chunks: {}", file.chunks.len());
        }
        None => println!("Alice's access was denied"),
    }
    
    // Step 4: Bob tries to access Alice's file (should fail)
    println!("\nStep 4: Bob attempts to access Alice's document");
    let bob_id = 2002;
    
    match node1.prove_access_capability(storage_proof.data_hash, bob_id, 50) {
        Ok(bob_access_proof) => {
            let bob_retrieval = node1.verify_and_retrieve(&bob_access_proof)?;
            match bob_retrieval {
                Some(_) => println!("ERROR: Bob gained unauthorized access!"),
                None => println!("Bob's access correctly denied"),
            }
        }
        Err(e) => {
            println!("Bob's access attempt failed (expected): {}", e);
        }
    }
    
    // Step 5: Grant Bob read access
    println!("\nStep 5: Alice grants Bob read access");
    if let Some(permissions) = node1.access_permissions.get_mut(&storage_proof.data_hash) {
        permissions.push(AccessPermission {
            user_id: bob_id,
            permission_level: 25, // Read-only access
            granted_by: alice_id,
        });
        println!("Bob granted read access by Alice");
    }
    
    // Step 6: Bob accesses file with permission (should succeed)
    println!("\nStep 6: Bob accesses document with granted permission");
    let bob_access_proof = node1.prove_access_capability(
        storage_proof.data_hash,
        bob_id,
        25, // Requesting read access (has permission level 25)
    )?;
    
    let bob_retrieved_file = node1.verify_and_retrieve(&bob_access_proof)?;
    match bob_retrieved_file {
        Some(file) => {
            println!("Bob successfully retrieved the document with permission");
            println!("- File size: {} bytes", file.total_size);
        }
        None => println!("Bob's access was denied despite permission"),
    }
    
    // Step 7: Bob tries to request write access (should fail)
    println!("\nStep 7: Bob attempts to request write access");
    match node1.prove_access_capability(storage_proof.data_hash, bob_id, 75) {
        Ok(write_proof) => {
            let write_access = node1.verify_and_retrieve(&write_proof)?;
            if write_access.is_some() {
                println!("ERROR: Bob gained write access without permission!");
            } else {
                println!("Bob's write access correctly denied (insufficient permission level)");
            }
        }
        Err(e) => {
            println!("Bob's write access attempt failed (expected): {}", e);
        }
    }
    
    println!("\nDecentralized storage tutorial completed successfully!");
    Ok(())
}
```

## Network Routing Tutorial

### Tutorial: Anonymous Network Routing with Capability Proofs

This tutorial shows how nodes can prove their routing capabilities without revealing network topology.

#### Step 1: Network Setup

```rust
use lib_proofs::ZkProofSystem;
use std::collections::{HashMap, HashSet};

struct NetworkNode {
    node_id: u64,
    zk_system: ZkProofSystem,
    routing_table: HashMap<u64, RouteInfo>,
    network_secret: u64,
    bandwidth_capacity: u64,
}

struct RouteInfo {
    destination: u64,
    next_hop: u64,
    hop_count: u64,
    available_bandwidth: u64,
    latency: u64,
}

struct NetworkTopology {
    nodes: HashMap<u64, NetworkNode>,
    connections: HashMap<u64, HashSet<u64>>,
}

impl NetworkNode {
    fn new(node_id: u64, bandwidth_capacity: u64) -> Result<Self> {
        Ok(Self {
            node_id,
            zk_system: ZkProofSystem::new()?,
            routing_table: HashMap::new(),
            network_secret: node_id * 7919 + 12345, // Derived from node credentials
            bandwidth_capacity,
        })
    }
    
    fn add_route(&mut self, destination: u64, next_hop: u64, hop_count: u64, bandwidth: u64, latency: u64) {
        self.routing_table.insert(destination, RouteInfo {
            destination,
            next_hop,
            hop_count,
            available_bandwidth: bandwidth,
            latency,
        });
    }
}
```

#### Step 2: Routing Capability Proofs

```rust
impl NetworkNode {
    fn prove_routing_capability(
        &self,
        destination: u64,
        max_hops: u64,
        min_bandwidth: u64,
    ) -> Result<RoutingProof> {
        println!("Node {} generating routing proof for destination {}", self.node_id, destination);
        
        let route = self.routing_table.get(&destination)
            .ok_or_else(|| anyhow::anyhow!("No route to destination {}", destination))?;
        
        println!("Route found:");
        println!("- Hops: {} (max allowed: {})", route.hop_count, max_hops);
        println!("- Bandwidth: {} (min required: {})", route.available_bandwidth, min_bandwidth);
        println!("- Latency: {}ms", route.latency);
        
        // Verify we can meet the requirements
        if route.hop_count > max_hops {
            return Err(anyhow::anyhow!("Route exceeds maximum hop count"));
        }
        if route.available_bandwidth < min_bandwidth {
            return Err(anyhow::anyhow!("Insufficient bandwidth available"));
        }
        
        // Generate zero-knowledge proof of routing capability
        let routing_proof = self.zk_system.prove_routing(
            self.node_id,           // source
            destination,            // destination (public)
            route.hop_count,        // actual hop count (private)
            route.available_bandwidth, // actual bandwidth (private)
            route.latency,          // actual latency (private)
            self.network_secret,    // node's routing secret (private)
            max_hops,              // max hops constraint (public)
            min_bandwidth,         // min bandwidth constraint (public)
        )?;
        
        println!("Routing proof generated successfully");
        
        Ok(RoutingProof {
            source_node: self.node_id,
            destination,
            max_hops,
            min_bandwidth,
            proof: routing_proof,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }
    
    fn verify_routing_proof(&self, routing_proof: &RoutingProof) -> Result<bool> {
        println!("Verifying routing proof from node {}", routing_proof.source_node);
        
        // Verify the zero-knowledge proof
        let is_valid = self.zk_system.verify_routing(&routing_proof.proof)?;
        
        if is_valid {
            println!("Routing proof verification: PASSED");
            println!("- Node {} can route to {} within constraints", 
                routing_proof.source_node, routing_proof.destination);
        } else {
            println!("Routing proof verification: FAILED");
        }
        
        Ok(is_valid)
    }
    
    fn request_routing_service(
        &self,
        destination: u64,
        quality_requirements: QualityRequirements,
    ) -> Result<Vec<RoutingOffer>> {
        println!("Requesting routing service to destination {}", destination);
        println!("Requirements: max {} hops, min {} bandwidth", 
            quality_requirements.max_hops, quality_requirements.min_bandwidth);
        
        // In a real network, this would broadcast the request
        // For this example, we'll simulate responses from other nodes
        Ok(Vec::new()) // Placeholder
    }
}

struct RoutingProof {
    source_node: u64,
    destination: u64,
    max_hops: u64,
    min_bandwidth: u64,
    proof: lib_proofs::plonky2::Plonky2Proof,
    timestamp: u64,
}

struct QualityRequirements {
    max_hops: u64,
    min_bandwidth: u64,
    max_latency: u64,
}

struct RoutingOffer {
    provider_node: u64,
    proof: RoutingProof,
    cost: u64,
}
```

#### Step 3: Network Routing Example

```rust
impl NetworkTopology {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            connections: HashMap::new(),
        }
    }
    
    fn add_node(&mut self, node: NetworkNode) {
        let node_id = node.node_id;
        self.nodes.insert(node_id, node);
        self.connections.insert(node_id, HashSet::new());
    }
    
    fn connect_nodes(&mut self, node1: u64, node2: u64) {
        self.connections.entry(node1).or_default().insert(node2);
        self.connections.entry(node2).or_default().insert(node1);
    }
    
    fn setup_routing_tables(&mut self) {
        // Simplified routing table setup
        // In practice, this would use a distributed routing protocol
        
        // Node 1001 can reach 1003 via 1002 (2 hops, 500 bandwidth, 20ms latency)
        if let Some(node) = self.nodes.get_mut(&1001) {
            node.add_route(1003, 1002, 2, 500, 20);
            node.add_route(1004, 1002, 3, 300, 35);
        }
        
        // Node 1002 can reach 1003 directly (1 hop, 800 bandwidth, 10ms latency)
        if let Some(node) = self.nodes.get_mut(&1002) {
            node.add_route(1003, 1003, 1, 800, 10);
            node.add_route(1004, 1004, 1, 600, 15);
        }
        
        // Node 1003 can reach 1001 via 1002 (2 hops, 450 bandwidth, 25ms latency)
        if let Some(node) = self.nodes.get_mut(&1003) {
            node.add_route(1001, 1002, 2, 450, 25);
        }
    }
}

fn network_routing_tutorial() -> Result<()> {
    println!("=== Anonymous Network Routing Tutorial ===\n");
    
    // Step 1: Create network topology
    println!("Step 1: Creating network topology");
    let mut network = NetworkTopology::new();
    
    // Add nodes with different capabilities
    network.add_node(NetworkNode::new(1001, 1000)?); // Node A
    network.add_node(NetworkNode::new(1002, 1200)?); // Node B (higher capacity)
    network.add_node(NetworkNode::new(1003, 800)?);  // Node C
    network.add_node(NetworkNode::new(1004, 600)?);  // Node D
    
    // Connect nodes
    network.connect_nodes(1001, 1002);
    network.connect_nodes(1002, 1003);
    network.connect_nodes(1002, 1004);
    network.connect_nodes(1003, 1004);
    
    // Setup routing tables
    network.setup_routing_tables();
    
    println!("Network created with 4 nodes and routing tables configured");
    
    // Step 2: Node 1001 proves it can route to 1003
    println!("\nStep 2: Node 1001 proves routing capability to 1003");
    let node1001 = network.nodes.get(&1001).unwrap();
    let routing_proof = node1001.prove_routing_capability(
        1003, // destination
        3,    // max 3 hops allowed
        400,  // minimum 400 bandwidth required
    )?;
    
    // Step 3: Another node verifies the routing proof
    println!("\nStep 3: Node 1002 verifies the routing proof");
    let node1002 = network.nodes.get(&1002).unwrap();
    let is_valid = node1002.verify_routing_proof(&routing_proof)?;
    
    println!("Proof validation result: {}", if is_valid { "VALID" } else { "INVALID" });
    
    // Step 4: Test with insufficient bandwidth requirement
    println!("\nStep 4: Node 1001 attempts to prove capability with high bandwidth requirement");
    match node1001.prove_routing_capability(1003, 3, 1000) {
        Ok(proof) => {
            println!("Proof generated unexpectedly");
            let verification = node1002.verify_routing_proof(&proof)?;
            println!("Verification result: {}", if verification { "VALID" } else { "INVALID" });
        }
        Err(e) => {
            println!("Proof generation failed as expected: {}", e);
        }
    }
    
    // Step 5: Test with excessive hop count requirement
    println!("\nStep 5: Node 1001 attempts to prove capability with strict hop limit");
    match node1001.prove_routing_capability(1003, 1, 300) {
        Ok(proof) => {
            println!("Proof generated unexpectedly");
            let verification = node1002.verify_routing_proof(&proof)?;
            println!("Verification result: {}", if verification { "VALID" } else { "INVALID" });
        }
        Err(e) => {
            println!("Proof generation failed as expected: {}", e);
        }
    }
    
    // Step 6: Demonstrate privacy preservation
    println!("\nStep 6: Privacy Analysis");
    println!("The routing proof reveals:");
    println!("- Source node: {}", routing_proof.source_node);
    println!("- Destination node: {}", routing_proof.destination);
    println!("- Maximum hops allowed: {}", routing_proof.max_hops);
    println!("- Minimum bandwidth required: {}", routing_proof.min_bandwidth);
    println!("\nThe routing proof DOES NOT reveal:");
    println!("- Exact hop count of the route");
    println!("- Actual available bandwidth");
    println!("- Specific path taken (intermediate nodes)");
    println!("- Network topology details");
    println!("- Node's routing table contents");
    
    println!("\nNetwork routing tutorial completed successfully!");
    Ok(())
}
```

## Advanced Patterns

### Recursive Proof Composition

```rust
use lib_proofs::{ZkProofSystem, verifiers::RecursiveProofAggregator};

fn recursive_proof_example() -> Result<()> {
    println!("=== Recursive Proof Composition Example ===\n");
    
    let zk_system = ZkProofSystem::new()?;
    let aggregator = RecursiveProofAggregator::new()?;
    
    // Generate multiple base proofs
    println!("Step 1: Generating base proofs");
    let mut base_proofs = Vec::new();
    
    for i in 0..5 {
        let proof = zk_system.prove_range(
            100 + i * 100, // values: 100, 200, 300, 400, 500
            12345 + i,     // different secrets
            0,             // min
            1000,          // max
        )?;
        base_proofs.push(proof);
        println!("Generated proof {} for value in range [0, 1000]", i + 1);
    }
    
    // Aggregate proofs recursively
    println!("\nStep 2: Aggregating proofs recursively");
    // Note: This would require implementing recursive aggregation
    // For now, we demonstrate the concept
    
    println!("All {} proofs can be aggregated into a single proof", base_proofs.len());
    println!("The aggregated proof would verify that all 5 values are in range [0, 1000]");
    println!("Verification time would be constant regardless of the number of base proofs");
    
    Ok(())
}
```

### Batch Verification

```rust
fn batch_verification_example() -> Result<()> {
    println!("=== Batch Verification Example ===\n");
    
    let zk_system = ZkProofSystem::new()?;
    
    // Generate a batch of transaction proofs
    println!("Step 1: Generating batch of transaction proofs");
    let mut tx_proofs = Vec::new();
    let batch_size = 10;
    
    for i in 0..batch_size {
        let proof = zk_system.prove_transaction(
            1000 + i * 100,  // varying balances
            50 + i * 10,     // varying amounts
            5,               // fixed fee
            12345 + i,       // varying secrets
            67890 + i,       // varying nullifiers
        )?;
        tx_proofs.push(proof);
    }
    
    println!("Generated {} transaction proofs", batch_size);
    
    // Individual verification
    println!("\nStep 2: Individual verification");
    let start = std::time::Instant::now();
    let mut all_valid = true;
    
    for (i, proof) in tx_proofs.iter().enumerate() {
        let is_valid = zk_system.verify_transaction(proof)?;
        if !is_valid {
            println!("Proof {} failed verification", i);
            all_valid = false;
        }
    }
    
    let individual_time = start.elapsed();
    println!("Individual verification: {:?} for {} proofs", individual_time, batch_size);
    println!("All proofs valid: {}", all_valid);
    
    // Batch verification (simulated - would be more efficient in practice)
    println!("\nStep 3: Batch verification");
    let start = std::time::Instant::now();
    
    // In a real implementation, batch verification would be significantly faster
    let batch_valid = tx_proofs.iter().all(|proof| {
        zk_system.verify_transaction(proof).unwrap_or(false)
    });
    
    let batch_time = start.elapsed();
    println!("Batch verification: {:?} for {} proofs", batch_time, batch_size);
    println!("Batch valid: {}", batch_valid);
    
    if individual_time > batch_time {
        let speedup = individual_time.as_secs_f64() / batch_time.as_secs_f64();
        println!("Batch verification speedup: {:.2}x", speedup);
    }
    
    Ok(())
}
```

## Real-World Integration

### Complete Application Example

```rust
// This example ties together all the tutorials into a complete application
fn complete_application_example() -> Result<()> {
    println!("=== Complete Privacy-Preserving Application ===\n");
    
    // Initialize all systems
    let mut payment_system = PrivatePaymentSystem::new()?;
    let mut verification_system = AgeVerificationSystem::new();
    let mut storage_node = DecentralizedStorageNode::new(3001)?;
    let mut network = NetworkTopology::new();
    
    // Setup network
    network.add_node(NetworkNode::new(3001, 1000)?);
    network.add_node(NetworkNode::new(3002, 1200)?);
    network.setup_routing_tables();
    
    // Create users
    println!("Creating user accounts and identities...");
    payment_system.create_account("alice", 2000)?;
    payment_system.create_account("bob", 1500)?;
    
    let alice_identity = DigitalIdentity::new(25, 840)?;
    let bob_identity = DigitalIdentity::new(19, 840)?;
    
    // Scenario 1: Age verification for service access
    println!("\n--- Scenario 1: Age-Gated Service Access ---");
    let age_verification_req = verification_system.create_verification_request(
        "Premium Content Platform", 21, 840
    );
    
    // Alice can access (25 >= 21)
    let alice_age_proof = alice_identity.prove_age_eligibility(21, 840)?;
    let alice_age_result = verification_system.verify_age_proof(&age_verification_req, &alice_age_proof)?;
    println!("Alice's access: {}", if alice_age_result.approved { "GRANTED" } else { "DENIED" });
    
    // Bob cannot access (19 < 21)
    match bob_identity.prove_age_eligibility(21, 840) {
        Ok(bob_age_proof) => {
            let bob_age_result = verification_system.verify_age_proof(&age_verification_req, &bob_age_proof)?;
            println!("Bob's access: {}", if bob_age_result.approved { "GRANTED" } else { "DENIED" });
        }
        Err(_) => println!("Bob's access: DENIED (age verification failed)"),
    }
    
    // Scenario 2: Private payment for service
    println!("\n--- Scenario 2: Private Payment ---");
    if alice_age_result.approved {
        println!("Alice makes private payment for premium service...");
        let payment_proof = payment_system.create_private_transfer("alice", 100, 5)?;
        let payment_success = payment_system.verify_and_execute_transfer(
            payment_proof, "alice", "service_provider"
        )?;
        println!("Payment result: {}", if payment_success { "SUCCESS" } else { "FAILED" });
    }
    
    // Scenario 3: Private document storage
    println!("\n--- Scenario 3: Private Document Storage ---");
    let alice_document = b"Alice's private medical records - confidential";
    let storage_proof = storage_node.store_file(alice_document, 2001)?;
    
    // Alice accesses her document
    let alice_access_proof = storage_node.prove_access_capability(
        storage_proof.data_hash, 2001, 50
    )?;
    let alice_file = storage_node.verify_and_retrieve(&alice_access_proof)?;
    println!("Alice document retrieval: {}", 
        if alice_file.is_some() { "SUCCESS" } else { "FAILED" });
    
    // Scenario 4: Network routing for data transfer
    println!("\n--- Scenario 4: Anonymous Data Routing ---");
    if let Some(routing_node) = network.nodes.get(&3001) {
        match routing_node.prove_routing_capability(3002, 2, 500) {
            Ok(routing_proof) => {
                if let Some(verifier_node) = network.nodes.get(&3002) {
                    let routing_valid = verifier_node.verify_routing_proof(&routing_proof)?;
                    println!("Routing capability: {}", 
                        if routing_valid { "VERIFIED" } else { "FAILED" });
                }
            }
            Err(_) => println!("Routing capability: NOT AVAILABLE"),
        }
    }
    
    println!("\n=== Application Scenarios Completed ===");
    println!("Demonstrated:");
    println!("✓ Anonymous age verification");
    println!("✓ Private financial transactions");
    println!("✓ Confidential data storage with access control");
    println!("✓ Anonymous network routing capabilities");
    println!("All while preserving user privacy through zero-knowledge proofs!");
    
    Ok(())
}
```

## Running the Examples

To run all examples and tutorials:

```rust
fn main() -> Result<()> {
    println!("lib-proofs Examples and Tutorials\n");
    println!("==================================\n");
    
    // Basic examples
    basic_range_proof()?;
    println!("\n");
    basic_transaction_proof()?;
    println!("\n");
    
    // Tutorials
    private_payment_tutorial()?;
    println!("\n");
    age_verification_tutorial()?;
    println!("\n");
    decentralized_storage_tutorial()?;
    println!("\n");
    network_routing_tutorial()?;
    println!("\n");
    
    // Advanced patterns
    recursive_proof_example()?;
    println!("\n");
    batch_verification_example()?;
    println!("\n");
    
    // Complete application
    complete_application_example()?;
    
    println!("\n All examples and tutorials completed successfully!");
    Ok(())
}
```

This comprehensive examples guide demonstrates the practical applications of lib-proofs across various privacy-preserving scenarios. Each tutorial builds upon the previous concepts and shows how zero-knowledge proofs can be used to create systems that preserve privacy while maintaining functionality and security.