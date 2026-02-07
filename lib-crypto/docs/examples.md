<<<<<<< HEAD
# Examples

Comprehensive examples demonstrating real-world usage patterns of lib-crypto in the SOVEREIGN_NET ecosystem. From basic operations to advanced cryptographic protocols and complete application scenarios.

## Basic Examples

### Hello Crypto World

```rust
use lib_crypto::*;

fn hello_crypto_world() -> Result<()> {
    println!(" Welcome to SOVEREIGN_NET Cryptography!");
    
    // Generate a keypair
    let keypair = KeyPair::generate()?;
    println!("Generated keypair with public key: {}", 
             hex::encode(keypair.public_key().as_bytes()));
    
    // Sign and verify a message
    let message = b"Hello, cryptographic world!";
    let signature = keypair.sign(message)?;
    let is_valid = keypair.verify(&signature, message)?;
    
    println!("Message: {}", String::from_utf8_lossy(message));
    println!("Signature valid: {}", is_valid);
    
    // Encrypt and decrypt data
    let secret_data = b"This is confidential information";
    let metadata = b"example_encryption";
    
    let encrypted = keypair.encrypt(secret_data, metadata)?;
    let decrypted = keypair.decrypt(&encrypted, metadata)?;
    
    println!("Original: {}", String::from_utf8_lossy(secret_data));
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
```

### Key Generation and Management

```rust
use lib_crypto::*;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
struct SecureKeyManager {
    master_seed: [u8; 32],
    operational_keys: Vec<KeyPair>,
}

impl SecureKeyManager {
    fn new() -> Result<Self> {
        let master_seed = random::secure_random_bytes::<32>()?;
        
        Ok(Self {
            master_seed,
            operational_keys: Vec::new(),
        })
    }
    
    fn new_operational_keypair(&mut self, purpose: &str, index: u32) -> Result<KeyPair> {
        // Derive a deterministic key identifier for tracking and purpose separation.
        //
        // NOTE: This does NOT deterministically generate PQ key material. PQ keypairs are generated
        // randomly; only the `key_id` is deterministic. Use identity-layer derivation
        // (`lib-identity-core`) for deterministic identity anchors.
        let purpose_data = format!("{}:{}", purpose, index);
        let derived_key_id = hashing::derive_key_blake3(
            &format!("ZHTP_OP_KEY_ID_V1:{}", purpose_data),
            &self.master_seed,
        );
        
        let mut keypair = KeyPair::generate()?;
        keypair.public_key.key_id = derived_key_id;
        self.operational_keys.push(keypair.clone());
        
        println!("Derived key for '{}' #{}: {}", 
                 purpose, index, hex::encode(keypair.public_key.key_id));
        
        Ok(keypair)
    }
    
    fn get_signing_key(&mut self) -> Result<KeyPair> {
        self.new_operational_keypair("signing", 0)
    }
    
    fn get_encryption_key(&mut self) -> Result<KeyPair> {
        self.new_operational_keypair("encryption", 0)
    }
    
    fn get_identity_key(&mut self, identity_id: u32) -> Result<KeyPair> {
        self.new_operational_keypair("identity", identity_id)
    }
}

fn key_management_example() -> Result<()> {
    let mut key_manager = SecureKeyManager::new()?;
    
    // Derive different keys for different purposes
    let signing_key = key_manager.get_signing_key()?;
    let encryption_key = key_manager.get_encryption_key()?;
    let alice_identity = key_manager.get_identity_key(1001)?;
    let bob_identity = key_manager.get_identity_key(1002)?;
    
    // Use keys for their intended purposes
    let document = b"Important contract to sign";
    let signature = signing_key.sign(document)?;
    println!("Document signed with signing key");
    
    let confidential_data = b"Confidential business data";
    let encrypted = encryption_key.encrypt(confidential_data, b"business_data")?;
    println!("Data encrypted with encryption key");
    
    // Identity-based messaging
    let message_to_bob = b"Hello Bob, this is Alice";
    let alice_signed = alice_identity.sign(message_to_bob)?;
    println!("Alice sent authenticated message to Bob");
    
    Ok(())
}
```

## Real-World Application Examples

### Secure Messaging System

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
struct SecureMessage {
    from: String,
    to: String,
    encrypted_content: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    nonce: [u8; 12],
}

struct MessagingSystem {
    users: HashMap<String, KeyPair>,
    message_history: Vec<SecureMessage>,
}

impl MessagingSystem {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            message_history: Vec::new(),
        }
    }
    
    fn register_user(&mut self, username: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.users.insert(username.to_string(), keypair);
        println!("User '{}' registered with public key: {}", username, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn send_message(&mut self, from: &str, to: &str, content: &str) -> Result<()> {
        let sender_keypair = self.users.get(from)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", from))?;
        
        let recipient_keypair = self.users.get(to)
            .ok_or_else(|| anyhow::anyhow!("Recipient not found: {}", to))?;
        
        // Encrypt content for recipient
        let content_bytes = content.as_bytes();
        let metadata = format!("from:{}|to:{}|timestamp:{}", 
                              from, to, 
                              std::time::SystemTime::now()
                                  .duration_since(std::time::UNIX_EPOCH)?
                                  .as_secs());
        
        let encrypted_content = recipient_keypair.encrypt(content_bytes, metadata.as_bytes())?;
        
        // Sign message with sender's key
        let message_data = format!("{}|{}|{}", from, to, hex::encode(&encrypted_content));
        let signature = sender_keypair.sign(message_data.as_bytes())?;
        
        let secure_message = SecureMessage {
            from: from.to_string(),
            to: to.to_string(),
            encrypted_content,
            signature: signature.as_bytes().to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            nonce: random::secure_random_bytes::<12>()?,
        };
        
        self.message_history.push(secure_message);
        println!("Message sent from {} to {}", from, to);
        
        Ok(())
    }
    
    fn read_messages(&self, username: &str) -> Result<Vec<String>> {
        let user_keypair = self.users.get(username)
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", username))?;
        
        let mut decrypted_messages = Vec::new();
        
        for message in &self.message_history {
            if message.to == username {
                // Verify sender's signature
                let sender_keypair = self.users.get(&message.from)
                    .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", message.from))?;
                
                let message_data = format!("{}|{}|{}", 
                                          message.from, message.to, 
                                          hex::encode(&message.encrypted_content));
                let signature = Signature::from_bytes(&message.signature)?;
                
                if sender_keypair.verify(&signature, message_data.as_bytes())? {
                    // Decrypt message
                    let metadata = format!("from:{}|to:{}|timestamp:{}", 
                                          message.from, message.to, message.timestamp);
                    
                    let decrypted = user_keypair.decrypt(&message.encrypted_content, metadata.as_bytes())?;
                    let content = String::from_utf8_lossy(&decrypted).to_string();
                    
                    decrypted_messages.push(format!("[{}] {}: {}", 
                        message.timestamp, message.from, content));
                } else {
                    println!("Invalid signature on message from {}", message.from);
                }
            }
        }
        
        Ok(decrypted_messages)
    }
}

fn secure_messaging_example() -> Result<()> {
    let mut messaging_system = MessagingSystem::new();
    
    // Register users
    messaging_system.register_user("alice")?;
    messaging_system.register_user("bob")?;
    messaging_system.register_user("charlie")?;
    
    // Send messages
    messaging_system.send_message("alice", "bob", "Hi Bob! How are you?")?;
    messaging_system.send_message("bob", "alice", "Hello Alice! I'm doing great.")?;
    messaging_system.send_message("charlie", "alice", "Alice, can we meet tomorrow?")?;
    
    // Read messages
    println!("\n📬 Alice's inbox:");
    let alice_messages = messaging_system.read_messages("alice")?;
    for message in alice_messages {
        println!("  {}", message);
    }
    
    println!("\n📬 Bob's inbox:");
    let bob_messages = messaging_system.read_messages("bob")?;
    for message in bob_messages {
        println!("  {}", message);
    }
    
    Ok(())
}
```

### Digital Document Signing

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
struct DigitalDocument {
    title: String,
    content: String,
    author: String,
    created_at: u64,
    version: u32,
    document_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct DocumentSignature {
    signer: String,
    signature: Vec<u8>,
    timestamp: u64,
    signature_type: SignatureType,
}

#[derive(Serialize, Deserialize)]
enum SignatureType {
    Author,
    Witness,
    Approver,
}

#[derive(Serialize, Deserialize)]
struct SignedDocument {
    document: DigitalDocument,
    signatures: Vec<DocumentSignature>,
    signature_chain_hash: [u8; 32],
}

struct DocumentSigningSystem {
    signers: HashMap<String, KeyPair>,
    documents: Vec<SignedDocument>,
}

impl DocumentSigningSystem {
    fn new() -> Self {
        Self {
            signers: HashMap::new(),
            documents: Vec::new(),
        }
    }
    
    fn register_signer(&mut self, name: &str, role: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.signers.insert(name.to_string(), keypair);
        println!("✍️ Signer '{}' ({}) registered: {}", name, role, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn create_document(&self, title: &str, content: &str, author: &str) -> Result<DigitalDocument> {
        let document_data = format!("{}|{}|{}", title, content, author);
        let document_hash = hashing::blake3_hash(document_data.as_bytes())?;
        
        let document = DigitalDocument {
            title: title.to_string(),
            content: content.to_string(),
            author: author.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            version: 1,
            document_hash,
        };
        
        println!(" Document created: '{}' by {}", title, author);
        Ok(document)
    }
    
    fn sign_document(&mut self, document: DigitalDocument, signer_name: &str, sig_type: SignatureType) -> Result<()> {
        let signer_keypair = self.signers.get(signer_name)
            .ok_or_else(|| anyhow::anyhow!("Signer not found: {}", signer_name))?;
        
        // Serialize document for signing
        let document_bytes = bincode::serialize(&document)?;
        let signature = signer_keypair.sign(&document_bytes)?;
        
        let doc_signature = DocumentSignature {
            signer: signer_name.to_string(),
            signature: signature.as_bytes().to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            signature_type: sig_type,
        };
        
        // Check if document already exists
        if let Some(existing_doc) = self.documents.iter_mut()
            .find(|d| d.document.document_hash == document.document_hash) {
            
            existing_doc.signatures.push(doc_signature);
            existing_doc.signature_chain_hash = self.compute_signature_chain_hash(&existing_doc.signatures)?;
        } else {
            let signatures = vec![doc_signature];
            let signature_chain_hash = self.compute_signature_chain_hash(&signatures)?;
            
            let signed_document = SignedDocument {
                document,
                signatures,
                signature_chain_hash,
            };
            
            self.documents.push(signed_document);
        }
        
        println!("Document signed by {}", signer_name);
        Ok(())
    }
    
    fn compute_signature_chain_hash(&self, signatures: &[DocumentSignature]) -> Result<[u8; 32]> {
        let mut chain_data = Vec::new();
        for sig in signatures {
            chain_data.extend_from_slice(sig.signer.as_bytes());
            chain_data.extend_from_slice(&sig.signature);
            chain_data.extend_from_slice(&sig.timestamp.to_le_bytes());
        }
        Ok(hashing::blake3_hash(&chain_data)?)
    }
    
    fn verify_document(&self, document_hash: &[u8; 32]) -> Result<bool> {
        let signed_doc = self.documents.iter()
            .find(|d| &d.document.document_hash == document_hash)
            .ok_or_else(|| anyhow::anyhow!("Document not found"))?;
        
        // Verify document hash
        let document_data = format!("{}|{}|{}", 
                                   signed_doc.document.title, 
                                   signed_doc.document.content, 
                                   signed_doc.document.author);
        let computed_hash = hashing::blake3_hash(document_data.as_bytes())?;
        
        if computed_hash != signed_doc.document.document_hash {
            return Ok(false);
        }
        
        // Verify all signatures
        let document_bytes = bincode::serialize(&signed_doc.document)?;
        
        for sig in &signed_doc.signatures {
            let signer_keypair = self.signers.get(&sig.signer)
                .ok_or_else(|| anyhow::anyhow!("Signer not found: {}", sig.signer))?;
            
            let signature = Signature::from_bytes(&sig.signature)?;
            if !signer_keypair.verify(&signature, &document_bytes)? {
                println!("Invalid signature from {}", sig.signer);
                return Ok(false);
            }
        }
        
        // Verify signature chain hash
        let computed_chain_hash = self.compute_signature_chain_hash(&signed_doc.signatures)?;
        if computed_chain_hash != signed_doc.signature_chain_hash {
            return Ok(false);
        }
        
        println!("Document verification successful");
        Ok(true)
    }
    
    fn get_document_info(&self, document_hash: &[u8; 32]) -> Result<()> {
        let signed_doc = self.documents.iter()
            .find(|d| &d.document.document_hash == document_hash)
            .ok_or_else(|| anyhow::anyhow!("Document not found"))?;
        
        println!("\nDocument Information:");
        println!("  Title: {}", signed_doc.document.title);
        println!("  Author: {}", signed_doc.document.author);
        println!("  Created: {}", signed_doc.document.created_at);
        println!("  Hash: {}", hex::encode(signed_doc.document.document_hash));
        println!("  Signatures ({}):", signed_doc.signatures.len());
        
        for sig in &signed_doc.signatures {
            println!("    - {} ({:?}) at {}", sig.signer, sig.signature_type, sig.timestamp);
        }
        
        Ok(())
    }
}

fn document_signing_example() -> Result<()> {
    let mut doc_system = DocumentSigningSystem::new();
    
    // Register signers
    doc_system.register_signer("john_doe", "Author")?;
    doc_system.register_signer("jane_smith", "Legal Reviewer")?;
    doc_system.register_signer("alice_manager", "Approver")?;
    
    // Create document
    let contract = doc_system.create_document(
        "Software Development Contract",
        "This contract defines the terms for software development services...",
        "john_doe"
    )?;
    
    let document_hash = contract.document_hash;
    
    // Multiple parties sign the document
    doc_system.sign_document(contract, "john_doe", SignatureType::Author)?;
    doc_system.sign_document(
        doc_system.documents[0].document.clone(),
        "jane_smith", 
        SignatureType::Witness
    )?;
    doc_system.sign_document(
        doc_system.documents[0].document.clone(),
        "alice_manager", 
        SignatureType::Approver
    )?;
    
    // Verify document
    let is_valid = doc_system.verify_document(&document_hash)?;
    println!("Document validity: {}", is_valid);
    
    // Show document information
    doc_system.get_document_info(&document_hash)?;
    
    Ok(())
}
```

### Secure File Storage

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    filename: String,
    encrypted_data: Vec<u8>,
    file_hash: [u8; 32],
    encryption_key_id: String,
    nonce: [u8; 12],
    created_at: u64,
    size: u64,
}

#[derive(Serialize, Deserialize)]
struct FileIndex {
    files: Vec<EncryptedFile>,
    index_hash: [u8; 32],
}

struct SecureFileStorage {
    master_keypair: KeyPair,
    storage_path: std::path::PathBuf,
    file_index: FileIndex,
}

impl SecureFileStorage {
    fn new(storage_path: &Path) -> Result<Self> {
        fs::create_dir_all(storage_path)?;
        
        let index_path = storage_path.join("file_index.enc");
        let file_index = if index_path.exists() {
            // Load existing index (simplified - would need proper decryption)
            FileIndex {
                files: Vec::new(),
                index_hash: [0u8; 32],
            }
        } else {
            FileIndex {
                files: Vec::new(),
                index_hash: [0u8; 32],
            }
        };
        
        Ok(Self {
            master_keypair: KeyPair::generate()?,
            storage_path: storage_path.to_path_buf(),
            file_index,
        })
    }
    
    fn encrypt_and_store(&mut self, filename: &str, data: &[u8]) -> Result<String> {
        // Generate unique seed for this file and derive a symmetric encryption key from it.
        // This avoids relying on non-existent deterministic PQ key generation.
        let file_seed = random::secure_random_bytes::<32>()?;
        let file_key = hashing::derive_key_blake3("FILE_ENC_KEY_V1", &file_seed);
        let key_id = hex::encode(file_key);
        
        // Hash original file for integrity
        let file_hash = hashing::blake3_hash(data)?;
        
        // Encrypt file data
        let metadata = format!("file:{}|size:{}|created:{}", 
                              filename, data.len(),
                              std::time::SystemTime::now()
                                  .duration_since(std::time::UNIX_EPOCH)?
                                  .as_secs());
        
        let encrypted_data = symmetric::encrypt_data_with_ad(data, &file_key, metadata.as_bytes())?;
        
        let encrypted_file = EncryptedFile {
            filename: filename.to_string(),
            encrypted_data: encrypted_data.clone(),
            file_hash,
            encryption_key_id: key_id.clone(),
            nonce: random::secure_random_bytes::<12>()?,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            size: data.len() as u64,
        };
        
        // Store encrypted file
        let storage_filename = format!("{}.enc", hex::encode(&file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        fs::write(&storage_path, &encrypted_data)?;
        
        // Store file seed encrypted with master key (so we can re-derive the file key later)
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted_seed = self.master_keypair.encrypt(&file_seed, b"file_seed")?;
        fs::write(&key_storage_path, encrypted_seed)?;
        
        // Update index
        self.file_index.files.push(encrypted_file);
        self.update_index_hash()?;
        
        println!(" File '{}' encrypted and stored (ID: {})", filename, &key_id[..8]);
        Ok(key_id)
    }
    
    fn decrypt_and_retrieve(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        // Find file in index
        let encrypted_file = self.file_index.files.iter()
            .find(|f| f.encryption_key_id == key_id)
            .ok_or_else(|| anyhow::anyhow!("File not found with key ID: {}", key_id))?;
        
        // Load and decrypt file seed
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted_seed = fs::read(&key_storage_path)?;
        let file_seed = self.master_keypair.decrypt(&encrypted_seed, b"file_seed")?;
        let file_key = hashing::derive_key_blake3("FILE_ENC_KEY_V1", &file_seed);
        
        // Load and decrypt file data
        let storage_filename = format!("{}.enc", hex::encode(&encrypted_file.file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        let encrypted_data = fs::read(&storage_path)?;
        
        let metadata = format!("file:{}|size:{}|created:{}", 
                              encrypted_file.filename, encrypted_file.size, encrypted_file.created_at);
        
        let decrypted_data = symmetric::decrypt_data_with_ad(&encrypted_data, &file_key, metadata.as_bytes())?;
        
        // Verify file integrity
        let computed_hash = hashing::blake3_hash(&decrypted_data)?;
        if computed_hash != encrypted_file.file_hash {
            return Err(anyhow::anyhow!("File integrity check failed"));
        }
        
        println!("🔓 File '{}' decrypted and retrieved", encrypted_file.filename);
        Ok((encrypted_file.filename.clone(), decrypted_data))
    }
    
    fn list_files(&self) -> Vec<(String, String, u64, u64)> {
        self.file_index.files.iter().map(|f| (
            f.filename.clone(),
            f.encryption_key_id[..8].to_string(), // Short ID
            f.size,
            f.created_at,
        )).collect()
    }
    
    fn delete_file(&mut self, key_id: &str) -> Result<()> {
        // Find and remove file from index
        let file_index = self.file_index.files.iter()
            .position(|f| f.encryption_key_id == key_id)
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;
        
        let encrypted_file = self.file_index.files.remove(file_index);
        
        // Delete encrypted file
        let storage_filename = format!("{}.enc", hex::encode(&encrypted_file.file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        if storage_path.exists() {
            fs::remove_file(&storage_path)?;
        }
        
        // Delete key file
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        if key_storage_path.exists() {
            fs::remove_file(&key_storage_path)?;
        }
        
        self.update_index_hash()?;
        
        println!("🗑️ File '{}' deleted", encrypted_file.filename);
        Ok(())
    }
    
    fn update_index_hash(&mut self) -> Result<()> {
        let index_data = bincode::serialize(&self.file_index.files)?;
        self.file_index.index_hash = hashing::blake3_hash(&index_data)?;
        Ok(())
    }
}

fn secure_file_storage_example() -> Result<()> {
    let storage_path = std::env::temp_dir().join("secure_storage_demo");
    let mut file_storage = SecureFileStorage::new(&storage_path)?;
    
    // Store some files
    let document1 = b"This is a confidential document with sensitive information.";
    let document2 = b"Another secret file containing important data.";
    let image_data = vec![0u8; 10240]; // Simulate 10KB image
    
    let doc1_id = file_storage.encrypt_and_store("confidential.txt", document1)?;
    let doc2_id = file_storage.encrypt_and_store("secrets.txt", document2)?;
    let img_id = file_storage.encrypt_and_store("photo.jpg", &image_data)?;
    
    // List stored files
    println!("\n Stored Files:");
    let files = file_storage.list_files();
    for (filename, short_id, size, created_at) in files {
        println!("  {} [{}...] - {} bytes (created: {})", 
                 filename, short_id, size, created_at);
    }
    
    // Retrieve and verify files
    let (retrieved_name, retrieved_data) = file_storage.decrypt_and_retrieve(&doc1_id)?;
    println!("\n Retrieved '{}': {}", 
             retrieved_name, String::from_utf8_lossy(&retrieved_data));
    
    // Delete a file
    file_storage.delete_file(&doc2_id)?;
    
    // Show remaining files
    println!("\n Remaining Files:");
    let remaining_files = file_storage.list_files();
    for (filename, short_id, size, _) in remaining_files {
        println!("  {} [{}...] - {} bytes", filename, short_id, size);
    }
    
    // Cleanup
    fs::remove_dir_all(&storage_path)?;
    
    Ok(())
}
```

## Advanced Cryptographic Examples

### Multi-Party Key Exchange

```rust
use lib_crypto::*;
use std::collections::HashMap;

struct MultiPartyKeyExchange {
    participants: HashMap<String, KeyPair>,
    shared_secrets: HashMap<String, [u8; 32]>,
    group_key: Option<[u8; 32]>,
}

impl MultiPartyKeyExchange {
    fn new() -> Self {
        Self {
            participants: HashMap::new(),
            shared_secrets: HashMap::new(),
            group_key: None,
        }
    }
    
    fn add_participant(&mut self, name: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.participants.insert(name.to_string(), keypair);
        println!("Participant '{}' joined: {}", name, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn perform_key_exchange(&mut self) -> Result<[u8; 32]> {
        let participant_names: Vec<String> = self.participants.keys().cloned().collect();
        
        if participant_names.len() < 2 {
            return Err(anyhow::anyhow!("Need at least 2 participants"));
        }
        
        // Simplified multi-party key exchange (Diffie-Hellman-like)
        // In practice, would use proper multi-party protocols
        
        // Step 1: Each pair computes shared secret
        for i in 0..participant_names.len() {
            for j in (i + 1)..participant_names.len() {
                let name1 = &participant_names[i];
                let name2 = &participant_names[j];
                
                let keypair1 = &self.participants[name1];
                let keypair2 = &self.participants[name2];
                
                // Compute shared secret between pair
                let shared_secret = self.compute_pairwise_secret(keypair1, keypair2)?;
                let pair_key = format!("{}:{}", name1, name2);
                self.shared_secrets.insert(pair_key, shared_secret);
            }
        }
        
        // Step 2: Combine all pairwise secrets into group key
        let mut group_key_material = Vec::new();
        for (_, secret) in &self.shared_secrets {
            group_key_material.extend_from_slice(secret);
        }
        
        let group_key = hashing::blake3_derive_key(&group_key_material, b"GROUP_KEY");
        self.group_key = Some(group_key);
        
        println!(" Group key established between {} participants", participant_names.len());
        Ok(group_key)
    }
    
    fn compute_pairwise_secret(&self, kp1: &KeyPair, kp2: &KeyPair) -> Result<[u8; 32]> {
        // Simplified ECDH-like computation
        let mut secret_material = Vec::new();
        secret_material.extend_from_slice(&kp1.public_key().as_bytes());
        secret_material.extend_from_slice(&kp2.public_key().as_bytes());
        
        Ok(hashing::blake3_derive_key(&secret_material, b"PAIRWISE_SECRET"))
    }
    
    fn encrypt_group_message(&self, message: &[u8], sender: &str) -> Result<Vec<u8>> {
        let group_key = self.group_key
            .ok_or_else(|| anyhow::anyhow!("Group key not established"))?;
        
        let sender_keypair = self.participants.get(sender)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", sender))?;
        
        // Sign message with sender's key
        let signature = sender_keypair.sign(message)?;
        
        // Encrypt with group key
        let metadata = format!("sender:{}|group_message", sender);
        let encrypted_message = symmetric::encrypt_chacha20poly1305(
            message,
            metadata.as_bytes(),
            &group_key,
            &random::secure_random_bytes::<12>()?
        )?;
        
        // Format: [SIGNATURE][NONCE][ENCRYPTED_MESSAGE]
        let mut group_message = Vec::new();
        group_message.extend_from_slice(&signature.as_bytes());
        group_message.extend_from_slice(&encrypted_message);
        
        Ok(group_message)
    }
    
    fn decrypt_group_message(&self, encrypted_message: &[u8], expected_sender: &str) -> Result<Vec<u8>> {
        let group_key = self.group_key
            .ok_or_else(|| anyhow::anyhow!("Group key not established"))?;
        
        let sender_keypair = self.participants.get(expected_sender)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", expected_sender))?;
        
        // Extract signature and encrypted data
        let signature_bytes = &encrypted_message[..64];
        let encrypted_data = &encrypted_message[64..];
        
        // Extract nonce and ciphertext
        let nonce = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];
        
        // Decrypt message
        let metadata = format!("sender:{}|group_message", expected_sender);
        let decrypted_message = symmetric::decrypt_chacha20poly1305(
            ciphertext,
            metadata.as_bytes(),
            &group_key,
            nonce.try_into()?
        )?;
        
        // Verify signature
        let signature = Signature::from_bytes(signature_bytes)?;
        if !sender_keypair.verify(&signature, &decrypted_message)? {
            return Err(anyhow::anyhow!("Invalid signature from sender"));
        }
        
        Ok(decrypted_message)
    }
}

fn multi_party_key_exchange_example() -> Result<()> {
    let mut mpke = MultiPartyKeyExchange::new();
    
    // Add participants
    mpke.add_participant("alice")?;
    mpke.add_participant("bob")?;
    mpke.add_participant("charlie")?;
    mpke.add_participant("diana")?;
    
    // Perform key exchange
    let group_key = mpke.perform_key_exchange()?;
    println!("Group key: {}", hex::encode(&group_key[..8]));
    
    // Group messaging
    let message = b"This is a confidential group message";
    let encrypted = mpke.encrypt_group_message(message, "alice")?;
    
    // All participants can decrypt
    let decrypted = mpke.decrypt_group_message(&encrypted, "alice")?;
    println!("Group message: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
```

### Zero-Knowledge Proof System

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct AgeVerificationClaim {
    commitment: [u8; 32],
    proof: Vec<u8>,
    public_parameters: Vec<u8>,
}

struct ZeroKnowledgeProofSystem {
    verifier_keypair: KeyPair,
    verified_claims: Vec<AgeVerificationClaim>,
}

impl ZeroKnowledgeProofSystem {
    fn new() -> Result<Self> {
        Ok(Self {
            verifier_keypair: KeyPair::generate()?,
            verified_claims: Vec::new(),
        })
    }
    
    fn generate_age_proof(&self, actual_age: u32, required_age: u32, identity_seed: &[u8; 32]) -> Result<AgeVerificationClaim> {
        if actual_age < required_age {
            return Err(anyhow::anyhow!("Age requirement not met"));
        }
        
        // Simplified ZK proof (in practice would use proper ZK-SNARK library)
        
        // Step 1: Create commitment to age
        let commitment_input = format!("age:{}|identity:{}", actual_age, hex::encode(identity_seed));
        let commitment = hashing::blake3_hash(commitment_input.as_bytes())?;
        
        // Step 2: Generate proof that age >= required_age without revealing actual age
        let proof_input = format!("commitment:{}|min_age:{}|salt:{}", 
                                 hex::encode(commitment),
                                 required_age,
                                 hex::encode(random::secure_random_bytes::<16>()?));
        
        let proof_hash = hashing::blake3_hash(proof_input.as_bytes())?;
        
        // Step 3: Create cryptographic proof
        let proof_data = format!("proof_type:age_verification|commitment:{}|requirement:{}", 
                                hex::encode(commitment), required_age);
        let proof_signature = self.verifier_keypair.sign(proof_data.as_bytes())?;
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&proof_hash);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        let public_parameters = format!("min_age:{}|proof_version:1", required_age).into_bytes();
        
        Ok(AgeVerificationClaim {
            commitment,
            proof,
            public_parameters,
        })
    }
    
    fn verify_age_proof(&mut self, claim: &AgeVerificationClaim, required_age: u32) -> Result<bool> {
        // Extract proof components
        let proof_hash = &claim.proof[..32];
        let proof_signature_bytes = &claim.proof[32..];
        
        // Verify proof signature
        let proof_data = format!("proof_type:age_verification|commitment:{}|requirement:{}", 
                                hex::encode(claim.commitment), required_age);
        
        let proof_signature = Signature::from_bytes(proof_signature_bytes)?;
        let signature_valid = self.verifier_keypair.verify(&proof_signature, proof_data.as_bytes())?;
        
        if !signature_valid {
            return Ok(false);
        }
        
        // Verify public parameters match requirement
        let params_str = String::from_utf8_lossy(&claim.public_parameters);
        if !params_str.contains(&format!("min_age:{}", required_age)) {
            return Ok(false);
        }
        
        // Check if this commitment was already used (prevent replay)
        if self.verified_claims.iter().any(|c| c.commitment == claim.commitment) {
            return Err(anyhow::anyhow!("Proof already used"));
        }
        
        // Store verified claim
        self.verified_claims.push(claim.clone());
        
        println!("Zero-knowledge age proof verified (age >= {})", required_age);
        Ok(true)
    }
    
    fn generate_membership_proof(&self, member_list: &[String], member_identity: &str, identity_seed: &[u8; 32]) -> Result<Vec<u8>> {
        if !member_list.contains(&member_identity.to_string()) {
            return Err(anyhow::anyhow!("Not a member of the group"));
        }
        
        // Create ring signature-like proof of membership without revealing which member
        let mut membership_data = Vec::new();
        
        // Include all member identities in proof
        for member in member_list {
            let member_hash = hashing::blake3_hash(member.as_bytes())?;
            membership_data.extend_from_slice(&member_hash);
        }
        
        // Add secret identity commitment
        let identity_commitment = hashing::blake3_hash(
            &format!("{}:{}", member_identity, hex::encode(identity_seed))
                .as_bytes()
        )?;
        membership_data.extend_from_slice(&identity_commitment);
        
        // Generate proof
        let proof_data = hashing::blake3_hash(&membership_data)?;
        let proof_signature = self.verifier_keypair.sign(&proof_data)?;
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&proof_data);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        Ok(proof)
    }
}

fn zero_knowledge_proof_example() -> Result<()> {
    let mut zk_system = ZeroKnowledgeProofSystem::new()?;
    
    // Alice wants to prove she's over 18 without revealing her exact age
    let alice_age = 25;
    let alice_identity_seed = random::secure_random_bytes::<32>()?;
    
    let age_proof = zk_system.generate_age_proof(alice_age, 18, &alice_identity_seed)?;
    let is_valid = zk_system.verify_age_proof(&age_proof, 18)?;
    
    println!("Alice's age proof (>= 18): {}", is_valid);
    
    // Bob tries with insufficient age
    let bob_age = 16;
    let bob_identity_seed = random::secure_random_bytes::<32>()?;
    
    match zk_system.generate_age_proof(bob_age, 18, &bob_identity_seed) {
        Ok(_) => println!("Bob's age proof should have failed!"),
        Err(_) => println!("Bob's age proof correctly rejected (age < 18)"),
    }
    
    // Membership proof example
    let vip_members = vec![
        "alice_vip".to_string(),
        "bob_vip".to_string(),
        "charlie_vip".to_string(),
        "diana_vip".to_string(),
    ];
    
    let membership_proof = zk_system.generate_membership_proof(
        &vip_members, 
        "alice_vip", 
        &alice_identity_seed
    )?;
    
    println!("Membership proof generated: {} bytes", membership_proof.len());
    
    Ok(())
}
```

## Running the Examples

### Example Runner

```rust
use lib_crypto::*;

fn main() -> Result<()> {
    println!(" SOVEREIGN_NET Crypto Examples\n");
    
    // Basic examples
    println!("=== Basic Examples ===");
    hello_crypto_world()?;
    println!();
    
    key_management_example()?;
    println!();
    
    // Real-world applications
    println!("=== Real-World Applications ===");
    secure_messaging_example()?;
    println!();
    
    document_signing_example()?;
    println!();
    
    secure_file_storage_example()?;
    println!();
    
    // Advanced cryptography
    println!("=== Advanced Cryptography ===");
    multi_party_key_exchange_example()?;
    println!();
    
    zero_knowledge_proof_example()?;
    println!();
    
    println!(" All examples completed successfully!");
    
    Ok(())
}
```

### Performance Benchmarks

```rust
use lib_crypto::*;
use std::time::Instant;

fn benchmark_crypto_operations() -> Result<()> {
    println!(" Performance Benchmarks\n");
    
    let iterations = 1000;
    
    // Key generation benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = KeyPair::generate()?;
    }
    let key_gen_time = start.elapsed();
    println!("Key Generation: {} keys in {:?} ({:.2} keys/sec)", 
             iterations, key_gen_time, 
             iterations as f64 / key_gen_time.as_secs_f64());
    
    // Signing benchmark
    let keypair = KeyPair::generate()?;
    let message = b"Benchmark message for signing performance test";
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keypair.sign(message)?;
    }
    let signing_time = start.elapsed();
    println!("Signing: {} signatures in {:?} ({:.2} sigs/sec)", 
             iterations, signing_time, 
             iterations as f64 / signing_time.as_secs_f64());
    
    // Verification benchmark
    let signature = keypair.sign(message)?;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keypair.verify(&signature, message)?;
    }
    let verify_time = start.elapsed();
    println!("Verification: {} verifications in {:?} ({:.2} verif/sec)", 
             iterations, verify_time, 
             iterations as f64 / verify_time.as_secs_f64());
    
    // Encryption benchmark
    let data = vec![0u8; 1024]; // 1KB
    
    let start = Instant::now();
    for i in 0..iterations {
        let metadata = format!("benchmark_{}", i);
        let _ = keypair.encrypt(&data, metadata.as_bytes())?;
    }
    let encrypt_time = start.elapsed();
    let throughput_mb = (iterations as f64 * data.len() as f64) / (1024.0 * 1024.0) / encrypt_time.as_secs_f64();
    println!("Encryption: {} × 1KB in {:?} ({:.2} MB/s)", 
             iterations, encrypt_time, throughput_mb);
    
    // Hashing benchmark
    let hash_data = vec![0u8; 10240]; // 10KB
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hashing::blake3_hash(&hash_data)?;
    }
    let hash_time = start.elapsed();
    let hash_throughput = (iterations as f64 * hash_data.len() as f64) / (1024.0 * 1024.0) / hash_time.as_secs_f64();
    println!("Hashing (BLAKE3): {} × 10KB in {:?} ({:.2} MB/s)", 
             iterations, hash_time, hash_throughput);
    
    Ok(())
}
```

These examples demonstrate the full range of lib-crypto capabilities in practical, real-world scenarios within the SOVEREIGN_NET ecosystem. Each example includes proper error handling, security best practices, and comprehensive documentation to help developers integrate cryptographic functionality effectively.
=======
# Examples

Comprehensive examples demonstrating real-world usage patterns of lib-crypto in the SOVEREIGN_NET ecosystem. From basic operations to advanced cryptographic protocols and complete application scenarios.

## Basic Examples

### Hello Crypto World

```rust
use lib_crypto::*;

fn hello_crypto_world() -> Result<()> {
    println!(" Welcome to SOVEREIGN_NET Cryptography!");
    
    // Generate a keypair
    let keypair = KeyPair::generate()?;
    println!("Generated keypair with public key: {}", 
             hex::encode(keypair.public_key().as_bytes()));
    
    // Sign and verify a message
    let message = b"Hello, cryptographic world!";
    let signature = keypair.sign(message)?;
    let is_valid = keypair.verify(&signature, message)?;
    
    println!("Message: {}", String::from_utf8_lossy(message));
    println!("Signature valid: {}", is_valid);
    
    // Encrypt and decrypt data
    let secret_data = b"This is confidential information";
    let metadata = b"example_encryption";
    
    let encrypted = keypair.encrypt(secret_data, metadata)?;
    let decrypted = keypair.decrypt(&encrypted, metadata)?;
    
    println!("Original: {}", String::from_utf8_lossy(secret_data));
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
```

### Key Generation and Management

```rust
use lib_crypto::*;
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
struct SecureKeyManager {
    master_seed: [u8; 32],
    operational_keys: Vec<KeyPair>,
}

impl SecureKeyManager {
    fn new() -> Result<Self> {
        let master_seed = random::secure_random_bytes::<32>()?;
        
        Ok(Self {
            master_seed,
            operational_keys: Vec::new(),
        })
    }
    
    fn new_operational_keypair(&mut self, purpose: &str, index: u32) -> Result<KeyPair> {
        // Derive a deterministic key identifier for tracking and purpose separation.
        //
        // NOTE: This does NOT deterministically generate PQ key material. PQ keypairs are generated
        // randomly; only the `key_id` is deterministic. Use identity-layer derivation
        // (`lib-identity-core`) for deterministic identity anchors.
        let purpose_data = format!("{}:{}", purpose, index);
        let derived_key_id = hashing::derive_key_blake3(
            &format!("ZHTP_OP_KEY_ID_V1:{}", purpose_data),
            &self.master_seed,
        );
        
        let mut keypair = KeyPair::generate()?;
        keypair.public_key.key_id = derived_key_id;
        self.operational_keys.push(keypair.clone());
        
        println!("Derived key for '{}' #{}: {}", 
                 purpose, index, hex::encode(keypair.public_key.key_id));
        
        Ok(keypair)
    }
    
    fn get_signing_key(&mut self) -> Result<KeyPair> {
        self.new_operational_keypair("signing", 0)
    }
    
    fn get_encryption_key(&mut self) -> Result<KeyPair> {
        self.new_operational_keypair("encryption", 0)
    }
    
    fn get_identity_key(&mut self, identity_id: u32) -> Result<KeyPair> {
        self.derive_key("identity", identity_id)
    }
}

fn key_management_example() -> Result<()> {
    let mut key_manager = SecureKeyManager::new()?;
    
    // Derive different keys for different purposes
    let signing_key = key_manager.get_signing_key()?;
    let encryption_key = key_manager.get_encryption_key()?;
    let alice_identity = key_manager.get_identity_key(1001)?;
    let bob_identity = key_manager.get_identity_key(1002)?;
    
    // Use keys for their intended purposes
    let document = b"Important contract to sign";
    let signature = signing_key.sign(document)?;
    println!("Document signed with signing key");
    
    let confidential_data = b"Confidential business data";
    let encrypted = encryption_key.encrypt(confidential_data, b"business_data")?;
    println!("Data encrypted with encryption key");
    
    // Identity-based messaging
    let message_to_bob = b"Hello Bob, this is Alice";
    let alice_signed = alice_identity.sign(message_to_bob)?;
    println!("Alice sent authenticated message to Bob");
    
    Ok(())
}
```

## Real-World Application Examples

### Secure Messaging System

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone)]
struct SecureMessage {
    from: String,
    to: String,
    encrypted_content: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    nonce: [u8; 12],
}

struct MessagingSystem {
    users: HashMap<String, KeyPair>,
    message_history: Vec<SecureMessage>,
}

impl MessagingSystem {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            message_history: Vec::new(),
        }
    }
    
    fn register_user(&mut self, username: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.users.insert(username.to_string(), keypair);
        println!("User '{}' registered with public key: {}", username, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn send_message(&mut self, from: &str, to: &str, content: &str) -> Result<()> {
        let sender_keypair = self.users.get(from)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", from))?;
        
        let recipient_keypair = self.users.get(to)
            .ok_or_else(|| anyhow::anyhow!("Recipient not found: {}", to))?;
        
        // Encrypt content for recipient
        let content_bytes = content.as_bytes();
        let metadata = format!("from:{}|to:{}|timestamp:{}", 
                              from, to, 
                              std::time::SystemTime::now()
                                  .duration_since(std::time::UNIX_EPOCH)?
                                  .as_secs());
        
        let encrypted_content = recipient_keypair.encrypt(content_bytes, metadata.as_bytes())?;
        
        // Sign message with sender's key
        let message_data = format!("{}|{}|{}", from, to, hex::encode(&encrypted_content));
        let signature = sender_keypair.sign(message_data.as_bytes())?;
        
        let secure_message = SecureMessage {
            from: from.to_string(),
            to: to.to_string(),
            encrypted_content,
            signature: signature.as_bytes().to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            nonce: random::secure_random_bytes::<12>()?,
        };
        
        self.message_history.push(secure_message);
        println!("Message sent from {} to {}", from, to);
        
        Ok(())
    }
    
    fn read_messages(&self, username: &str) -> Result<Vec<String>> {
        let user_keypair = self.users.get(username)
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", username))?;
        
        let mut decrypted_messages = Vec::new();
        
        for message in &self.message_history {
            if message.to == username {
                // Verify sender's signature
                let sender_keypair = self.users.get(&message.from)
                    .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", message.from))?;
                
                let message_data = format!("{}|{}|{}", 
                                          message.from, message.to, 
                                          hex::encode(&message.encrypted_content));
                let signature = Signature::from_bytes(&message.signature)?;
                
                if sender_keypair.verify(&signature, message_data.as_bytes())? {
                    // Decrypt message
                    let metadata = format!("from:{}|to:{}|timestamp:{}", 
                                          message.from, message.to, message.timestamp);
                    
                    let decrypted = user_keypair.decrypt(&message.encrypted_content, metadata.as_bytes())?;
                    let content = String::from_utf8_lossy(&decrypted).to_string();
                    
                    decrypted_messages.push(format!("[{}] {}: {}", 
                        message.timestamp, message.from, content));
                } else {
                    println!("Invalid signature on message from {}", message.from);
                }
            }
        }
        
        Ok(decrypted_messages)
    }
}

fn secure_messaging_example() -> Result<()> {
    let mut messaging_system = MessagingSystem::new();
    
    // Register users
    messaging_system.register_user("alice")?;
    messaging_system.register_user("bob")?;
    messaging_system.register_user("charlie")?;
    
    // Send messages
    messaging_system.send_message("alice", "bob", "Hi Bob! How are you?")?;
    messaging_system.send_message("bob", "alice", "Hello Alice! I'm doing great.")?;
    messaging_system.send_message("charlie", "alice", "Alice, can we meet tomorrow?")?;
    
    // Read messages
    println!("\n📬 Alice's inbox:");
    let alice_messages = messaging_system.read_messages("alice")?;
    for message in alice_messages {
        println!("  {}", message);
    }
    
    println!("\n📬 Bob's inbox:");
    let bob_messages = messaging_system.read_messages("bob")?;
    for message in bob_messages {
        println!("  {}", message);
    }
    
    Ok(())
}
```

### Digital Document Signing

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
struct DigitalDocument {
    title: String,
    content: String,
    author: String,
    created_at: u64,
    version: u32,
    document_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct DocumentSignature {
    signer: String,
    signature: Vec<u8>,
    timestamp: u64,
    signature_type: SignatureType,
}

#[derive(Serialize, Deserialize)]
enum SignatureType {
    Author,
    Witness,
    Approver,
}

#[derive(Serialize, Deserialize)]
struct SignedDocument {
    document: DigitalDocument,
    signatures: Vec<DocumentSignature>,
    signature_chain_hash: [u8; 32],
}

struct DocumentSigningSystem {
    signers: HashMap<String, KeyPair>,
    documents: Vec<SignedDocument>,
}

impl DocumentSigningSystem {
    fn new() -> Self {
        Self {
            signers: HashMap::new(),
            documents: Vec::new(),
        }
    }
    
    fn register_signer(&mut self, name: &str, role: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.signers.insert(name.to_string(), keypair);
        println!("✍️ Signer '{}' ({}) registered: {}", name, role, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn create_document(&self, title: &str, content: &str, author: &str) -> Result<DigitalDocument> {
        let document_data = format!("{}|{}|{}", title, content, author);
        let document_hash = hashing::blake3_hash(document_data.as_bytes())?;
        
        let document = DigitalDocument {
            title: title.to_string(),
            content: content.to_string(),
            author: author.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            version: 1,
            document_hash,
        };
        
        println!(" Document created: '{}' by {}", title, author);
        Ok(document)
    }
    
    fn sign_document(&mut self, document: DigitalDocument, signer_name: &str, sig_type: SignatureType) -> Result<()> {
        let signer_keypair = self.signers.get(signer_name)
            .ok_or_else(|| anyhow::anyhow!("Signer not found: {}", signer_name))?;
        
        // Serialize document for signing
        let document_bytes = bincode::serialize(&document)?;
        let signature = signer_keypair.sign(&document_bytes)?;
        
        let doc_signature = DocumentSignature {
            signer: signer_name.to_string(),
            signature: signature.as_bytes().to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            signature_type: sig_type,
        };
        
        // Check if document already exists
        if let Some(existing_doc) = self.documents.iter_mut()
            .find(|d| d.document.document_hash == document.document_hash) {
            
            existing_doc.signatures.push(doc_signature);
            existing_doc.signature_chain_hash = self.compute_signature_chain_hash(&existing_doc.signatures)?;
        } else {
            let signatures = vec![doc_signature];
            let signature_chain_hash = self.compute_signature_chain_hash(&signatures)?;
            
            let signed_document = SignedDocument {
                document,
                signatures,
                signature_chain_hash,
            };
            
            self.documents.push(signed_document);
        }
        
        println!("Document signed by {}", signer_name);
        Ok(())
    }
    
    fn compute_signature_chain_hash(&self, signatures: &[DocumentSignature]) -> Result<[u8; 32]> {
        let mut chain_data = Vec::new();
        for sig in signatures {
            chain_data.extend_from_slice(sig.signer.as_bytes());
            chain_data.extend_from_slice(&sig.signature);
            chain_data.extend_from_slice(&sig.timestamp.to_le_bytes());
        }
        Ok(hashing::blake3_hash(&chain_data)?)
    }
    
    fn verify_document(&self, document_hash: &[u8; 32]) -> Result<bool> {
        let signed_doc = self.documents.iter()
            .find(|d| &d.document.document_hash == document_hash)
            .ok_or_else(|| anyhow::anyhow!("Document not found"))?;
        
        // Verify document hash
        let document_data = format!("{}|{}|{}", 
                                   signed_doc.document.title, 
                                   signed_doc.document.content, 
                                   signed_doc.document.author);
        let computed_hash = hashing::blake3_hash(document_data.as_bytes())?;
        
        if computed_hash != signed_doc.document.document_hash {
            return Ok(false);
        }
        
        // Verify all signatures
        let document_bytes = bincode::serialize(&signed_doc.document)?;
        
        for sig in &signed_doc.signatures {
            let signer_keypair = self.signers.get(&sig.signer)
                .ok_or_else(|| anyhow::anyhow!("Signer not found: {}", sig.signer))?;
            
            let signature = Signature::from_bytes(&sig.signature)?;
            if !signer_keypair.verify(&signature, &document_bytes)? {
                println!("Invalid signature from {}", sig.signer);
                return Ok(false);
            }
        }
        
        // Verify signature chain hash
        let computed_chain_hash = self.compute_signature_chain_hash(&signed_doc.signatures)?;
        if computed_chain_hash != signed_doc.signature_chain_hash {
            return Ok(false);
        }
        
        println!("Document verification successful");
        Ok(true)
    }
    
    fn get_document_info(&self, document_hash: &[u8; 32]) -> Result<()> {
        let signed_doc = self.documents.iter()
            .find(|d| &d.document.document_hash == document_hash)
            .ok_or_else(|| anyhow::anyhow!("Document not found"))?;
        
        println!("\nDocument Information:");
        println!("  Title: {}", signed_doc.document.title);
        println!("  Author: {}", signed_doc.document.author);
        println!("  Created: {}", signed_doc.document.created_at);
        println!("  Hash: {}", hex::encode(signed_doc.document.document_hash));
        println!("  Signatures ({}):", signed_doc.signatures.len());
        
        for sig in &signed_doc.signatures {
            println!("    - {} ({:?}) at {}", sig.signer, sig.signature_type, sig.timestamp);
        }
        
        Ok(())
    }
}

fn document_signing_example() -> Result<()> {
    let mut doc_system = DocumentSigningSystem::new();
    
    // Register signers
    doc_system.register_signer("john_doe", "Author")?;
    doc_system.register_signer("jane_smith", "Legal Reviewer")?;
    doc_system.register_signer("alice_manager", "Approver")?;
    
    // Create document
    let contract = doc_system.create_document(
        "Software Development Contract",
        "This contract defines the terms for software development services...",
        "john_doe"
    )?;
    
    let document_hash = contract.document_hash;
    
    // Multiple parties sign the document
    doc_system.sign_document(contract, "john_doe", SignatureType::Author)?;
    doc_system.sign_document(
        doc_system.documents[0].document.clone(),
        "jane_smith", 
        SignatureType::Witness
    )?;
    doc_system.sign_document(
        doc_system.documents[0].document.clone(),
        "alice_manager", 
        SignatureType::Approver
    )?;
    
    // Verify document
    let is_valid = doc_system.verify_document(&document_hash)?;
    println!("Document validity: {}", is_valid);
    
    // Show document information
    doc_system.get_document_info(&document_hash)?;
    
    Ok(())
}
```

### Secure File Storage

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct EncryptedFile {
    filename: String,
    encrypted_data: Vec<u8>,
    file_hash: [u8; 32],
    encryption_key_id: String,
    nonce: [u8; 12],
    created_at: u64,
    size: u64,
}

#[derive(Serialize, Deserialize)]
struct FileIndex {
    files: Vec<EncryptedFile>,
    index_hash: [u8; 32],
}

struct SecureFileStorage {
    master_keypair: KeyPair,
    storage_path: std::path::PathBuf,
    file_index: FileIndex,
}

impl SecureFileStorage {
    fn new(storage_path: &Path) -> Result<Self> {
        fs::create_dir_all(storage_path)?;
        
        let index_path = storage_path.join("file_index.enc");
        let file_index = if index_path.exists() {
            // Load existing index (simplified - would need proper decryption)
            FileIndex {
                files: Vec::new(),
                index_hash: [0u8; 32],
            }
        } else {
            FileIndex {
                files: Vec::new(),
                index_hash: [0u8; 32],
            }
        };
        
        Ok(Self {
            master_keypair: KeyPair::generate()?,
            storage_path: storage_path.to_path_buf(),
            file_index,
        })
    }
    
    fn encrypt_and_store(&mut self, filename: &str, data: &[u8]) -> Result<String> {
        // Generate unique seed for this file and derive a symmetric encryption key from it.
        // This avoids relying on non-existent deterministic PQ key generation.
        let file_seed = random::secure_random_bytes::<32>()?;
        let file_key = hashing::derive_key_blake3("FILE_ENC_KEY_V1", &file_seed);
        let key_id = hex::encode(file_key);
        
        // Hash original file for integrity
        let file_hash = hashing::blake3_hash(data)?;
        
        // Encrypt file data
        let metadata = format!("file:{}|size:{}|created:{}", 
                              filename, data.len(),
                              std::time::SystemTime::now()
                                  .duration_since(std::time::UNIX_EPOCH)?
                                  .as_secs());
        
        let encrypted_data = symmetric::encrypt_data_with_ad(data, &file_key, metadata.as_bytes())?;
        
        let encrypted_file = EncryptedFile {
            filename: filename.to_string(),
            encrypted_data: encrypted_data.clone(),
            file_hash,
            encryption_key_id: key_id.clone(),
            nonce: random::secure_random_bytes::<12>()?,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            size: data.len() as u64,
        };
        
        // Store encrypted file
        let storage_filename = format!("{}.enc", hex::encode(&file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        fs::write(&storage_path, &encrypted_data)?;
        
        // Store file seed encrypted with master key (so we can re-derive the file key later)
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted_seed = self.master_keypair.encrypt(&file_seed, b"file_seed")?;
        fs::write(&key_storage_path, encrypted_seed)?;
        
        // Update index
        self.file_index.files.push(encrypted_file);
        self.update_index_hash()?;
        
        println!(" File '{}' encrypted and stored (ID: {})", filename, &key_id[..8]);
        Ok(key_id)
    }
    
    fn decrypt_and_retrieve(&self, key_id: &str) -> Result<(String, Vec<u8>)> {
        // Find file in index
        let encrypted_file = self.file_index.files.iter()
            .find(|f| f.encryption_key_id == key_id)
            .ok_or_else(|| anyhow::anyhow!("File not found with key ID: {}", key_id))?;
        
        // Load and decrypt file seed
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        let encrypted_seed = fs::read(&key_storage_path)?;
        let file_seed = self.master_keypair.decrypt(&encrypted_seed, b"file_seed")?;
        let file_key = hashing::derive_key_blake3("FILE_ENC_KEY_V1", &file_seed);
        
        // Load and decrypt file data
        let storage_filename = format!("{}.enc", hex::encode(&encrypted_file.file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        let encrypted_data = fs::read(&storage_path)?;
        
        let metadata = format!("file:{}|size:{}|created:{}", 
                              encrypted_file.filename, encrypted_file.size, encrypted_file.created_at);
        
        let decrypted_data = symmetric::decrypt_data_with_ad(&encrypted_data, &file_key, metadata.as_bytes())?;
        
        // Verify file integrity
        let computed_hash = hashing::blake3_hash(&decrypted_data)?;
        if computed_hash != encrypted_file.file_hash {
            return Err(anyhow::anyhow!("File integrity check failed"));
        }
        
        println!("🔓 File '{}' decrypted and retrieved", encrypted_file.filename);
        Ok((encrypted_file.filename.clone(), decrypted_data))
    }
    
    fn list_files(&self) -> Vec<(String, String, u64, u64)> {
        self.file_index.files.iter().map(|f| (
            f.filename.clone(),
            f.encryption_key_id[..8].to_string(), // Short ID
            f.size,
            f.created_at,
        )).collect()
    }
    
    fn delete_file(&mut self, key_id: &str) -> Result<()> {
        // Find and remove file from index
        let file_index = self.file_index.files.iter()
            .position(|f| f.encryption_key_id == key_id)
            .ok_or_else(|| anyhow::anyhow!("File not found"))?;
        
        let encrypted_file = self.file_index.files.remove(file_index);
        
        // Delete encrypted file
        let storage_filename = format!("{}.enc", hex::encode(&encrypted_file.file_hash));
        let storage_path = self.storage_path.join(&storage_filename);
        if storage_path.exists() {
            fs::remove_file(&storage_path)?;
        }
        
        // Delete key file
        let key_storage_path = self.storage_path.join(format!("{}.key", key_id));
        if key_storage_path.exists() {
            fs::remove_file(&key_storage_path)?;
        }
        
        self.update_index_hash()?;
        
        println!("🗑️ File '{}' deleted", encrypted_file.filename);
        Ok(())
    }
    
    fn update_index_hash(&mut self) -> Result<()> {
        let index_data = bincode::serialize(&self.file_index.files)?;
        self.file_index.index_hash = hashing::blake3_hash(&index_data)?;
        Ok(())
    }
}

fn secure_file_storage_example() -> Result<()> {
    let storage_path = std::env::temp_dir().join("secure_storage_demo");
    let mut file_storage = SecureFileStorage::new(&storage_path)?;
    
    // Store some files
    let document1 = b"This is a confidential document with sensitive information.";
    let document2 = b"Another secret file containing important data.";
    let image_data = vec![0u8; 10240]; // Simulate 10KB image
    
    let doc1_id = file_storage.encrypt_and_store("confidential.txt", document1)?;
    let doc2_id = file_storage.encrypt_and_store("secrets.txt", document2)?;
    let img_id = file_storage.encrypt_and_store("photo.jpg", &image_data)?;
    
    // List stored files
    println!("\n Stored Files:");
    let files = file_storage.list_files();
    for (filename, short_id, size, created_at) in files {
        println!("  {} [{}...] - {} bytes (created: {})", 
                 filename, short_id, size, created_at);
    }
    
    // Retrieve and verify files
    let (retrieved_name, retrieved_data) = file_storage.decrypt_and_retrieve(&doc1_id)?;
    println!("\n Retrieved '{}': {}", 
             retrieved_name, String::from_utf8_lossy(&retrieved_data));
    
    // Delete a file
    file_storage.delete_file(&doc2_id)?;
    
    // Show remaining files
    println!("\n Remaining Files:");
    let remaining_files = file_storage.list_files();
    for (filename, short_id, size, _) in remaining_files {
        println!("  {} [{}...] - {} bytes", filename, short_id, size);
    }
    
    // Cleanup
    fs::remove_dir_all(&storage_path)?;
    
    Ok(())
}
```

## Advanced Cryptographic Examples

### Multi-Party Key Exchange

```rust
use lib_crypto::*;
use std::collections::HashMap;

struct MultiPartyKeyExchange {
    participants: HashMap<String, KeyPair>,
    shared_secrets: HashMap<String, [u8; 32]>,
    group_key: Option<[u8; 32]>,
}

impl MultiPartyKeyExchange {
    fn new() -> Self {
        Self {
            participants: HashMap::new(),
            shared_secrets: HashMap::new(),
            group_key: None,
        }
    }
    
    fn add_participant(&mut self, name: &str) -> Result<String> {
        let keypair = KeyPair::generate()?;
        let public_key_hex = hex::encode(keypair.public_key().as_bytes());
        
        self.participants.insert(name.to_string(), keypair);
        println!("Participant '{}' joined: {}", name, &public_key_hex[..16]);
        
        Ok(public_key_hex)
    }
    
    fn perform_key_exchange(&mut self) -> Result<[u8; 32]> {
        let participant_names: Vec<String> = self.participants.keys().cloned().collect();
        
        if participant_names.len() < 2 {
            return Err(anyhow::anyhow!("Need at least 2 participants"));
        }
        
        // Simplified multi-party key exchange (Diffie-Hellman-like)
        // In practice, would use proper multi-party protocols
        
        // Step 1: Each pair computes shared secret
        for i in 0..participant_names.len() {
            for j in (i + 1)..participant_names.len() {
                let name1 = &participant_names[i];
                let name2 = &participant_names[j];
                
                let keypair1 = &self.participants[name1];
                let keypair2 = &self.participants[name2];
                
                // Compute shared secret between pair
                let shared_secret = self.compute_pairwise_secret(keypair1, keypair2)?;
                let pair_key = format!("{}:{}", name1, name2);
                self.shared_secrets.insert(pair_key, shared_secret);
            }
        }
        
        // Step 2: Combine all pairwise secrets into group key
        let mut group_key_material = Vec::new();
        for (_, secret) in &self.shared_secrets {
            group_key_material.extend_from_slice(secret);
        }
        
        let group_key = hashing::blake3_derive_key(&group_key_material, b"GROUP_KEY");
        self.group_key = Some(group_key);
        
        println!(" Group key established between {} participants", participant_names.len());
        Ok(group_key)
    }
    
    fn compute_pairwise_secret(&self, kp1: &KeyPair, kp2: &KeyPair) -> Result<[u8; 32]> {
        // Simplified ECDH-like computation
        let mut secret_material = Vec::new();
        secret_material.extend_from_slice(&kp1.public_key().as_bytes());
        secret_material.extend_from_slice(&kp2.public_key().as_bytes());
        
        Ok(hashing::blake3_derive_key(&secret_material, b"PAIRWISE_SECRET"))
    }
    
    fn encrypt_group_message(&self, message: &[u8], sender: &str) -> Result<Vec<u8>> {
        let group_key = self.group_key
            .ok_or_else(|| anyhow::anyhow!("Group key not established"))?;
        
        let sender_keypair = self.participants.get(sender)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", sender))?;
        
        // Sign message with sender's key
        let signature = sender_keypair.sign(message)?;
        
        // Encrypt with group key
        let metadata = format!("sender:{}|group_message", sender);
        let encrypted_message = symmetric::encrypt_chacha20poly1305(
            message,
            metadata.as_bytes(),
            &group_key,
            &random::secure_random_bytes::<12>()?
        )?;
        
        // Format: [SIGNATURE][NONCE][ENCRYPTED_MESSAGE]
        let mut group_message = Vec::new();
        group_message.extend_from_slice(&signature.as_bytes());
        group_message.extend_from_slice(&encrypted_message);
        
        Ok(group_message)
    }
    
    fn decrypt_group_message(&self, encrypted_message: &[u8], expected_sender: &str) -> Result<Vec<u8>> {
        let group_key = self.group_key
            .ok_or_else(|| anyhow::anyhow!("Group key not established"))?;
        
        let sender_keypair = self.participants.get(expected_sender)
            .ok_or_else(|| anyhow::anyhow!("Sender not found: {}", expected_sender))?;
        
        // Extract signature and encrypted data
        let signature_bytes = &encrypted_message[..64];
        let encrypted_data = &encrypted_message[64..];
        
        // Extract nonce and ciphertext
        let nonce = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];
        
        // Decrypt message
        let metadata = format!("sender:{}|group_message", expected_sender);
        let decrypted_message = symmetric::decrypt_chacha20poly1305(
            ciphertext,
            metadata.as_bytes(),
            &group_key,
            nonce.try_into()?
        )?;
        
        // Verify signature
        let signature = Signature::from_bytes(signature_bytes)?;
        if !sender_keypair.verify(&signature, &decrypted_message)? {
            return Err(anyhow::anyhow!("Invalid signature from sender"));
        }
        
        Ok(decrypted_message)
    }
}

fn multi_party_key_exchange_example() -> Result<()> {
    let mut mpke = MultiPartyKeyExchange::new();
    
    // Add participants
    mpke.add_participant("alice")?;
    mpke.add_participant("bob")?;
    mpke.add_participant("charlie")?;
    mpke.add_participant("diana")?;
    
    // Perform key exchange
    let group_key = mpke.perform_key_exchange()?;
    println!("Group key: {}", hex::encode(&group_key[..8]));
    
    // Group messaging
    let message = b"This is a confidential group message";
    let encrypted = mpke.encrypt_group_message(message, "alice")?;
    
    // All participants can decrypt
    let decrypted = mpke.decrypt_group_message(&encrypted, "alice")?;
    println!("Group message: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
```

### Zero-Knowledge Proof System

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct AgeVerificationClaim {
    commitment: [u8; 32],
    proof: Vec<u8>,
    public_parameters: Vec<u8>,
}

struct ZeroKnowledgeProofSystem {
    verifier_keypair: KeyPair,
    verified_claims: Vec<AgeVerificationClaim>,
}

impl ZeroKnowledgeProofSystem {
    fn new() -> Result<Self> {
        Ok(Self {
            verifier_keypair: KeyPair::generate()?,
            verified_claims: Vec::new(),
        })
    }
    
    fn generate_age_proof(&self, actual_age: u32, required_age: u32, identity_seed: &[u8; 32]) -> Result<AgeVerificationClaim> {
        if actual_age < required_age {
            return Err(anyhow::anyhow!("Age requirement not met"));
        }
        
        // Simplified ZK proof (in practice would use proper ZK-SNARK library)
        
        // Step 1: Create commitment to age
        let commitment_input = format!("age:{}|identity:{}", actual_age, hex::encode(identity_seed));
        let commitment = hashing::blake3_hash(commitment_input.as_bytes())?;
        
        // Step 2: Generate proof that age >= required_age without revealing actual age
        let proof_input = format!("commitment:{}|min_age:{}|salt:{}", 
                                 hex::encode(commitment),
                                 required_age,
                                 hex::encode(random::secure_random_bytes::<16>()?));
        
        let proof_hash = hashing::blake3_hash(proof_input.as_bytes())?;
        
        // Step 3: Create cryptographic proof
        let proof_data = format!("proof_type:age_verification|commitment:{}|requirement:{}", 
                                hex::encode(commitment), required_age);
        let proof_signature = self.verifier_keypair.sign(proof_data.as_bytes())?;
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&proof_hash);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        let public_parameters = format!("min_age:{}|proof_version:1", required_age).into_bytes();
        
        Ok(AgeVerificationClaim {
            commitment,
            proof,
            public_parameters,
        })
    }
    
    fn verify_age_proof(&mut self, claim: &AgeVerificationClaim, required_age: u32) -> Result<bool> {
        // Extract proof components
        let proof_hash = &claim.proof[..32];
        let proof_signature_bytes = &claim.proof[32..];
        
        // Verify proof signature
        let proof_data = format!("proof_type:age_verification|commitment:{}|requirement:{}", 
                                hex::encode(claim.commitment), required_age);
        
        let proof_signature = Signature::from_bytes(proof_signature_bytes)?;
        let signature_valid = self.verifier_keypair.verify(&proof_signature, proof_data.as_bytes())?;
        
        if !signature_valid {
            return Ok(false);
        }
        
        // Verify public parameters match requirement
        let params_str = String::from_utf8_lossy(&claim.public_parameters);
        if !params_str.contains(&format!("min_age:{}", required_age)) {
            return Ok(false);
        }
        
        // Check if this commitment was already used (prevent replay)
        if self.verified_claims.iter().any(|c| c.commitment == claim.commitment) {
            return Err(anyhow::anyhow!("Proof already used"));
        }
        
        // Store verified claim
        self.verified_claims.push(claim.clone());
        
        println!("Zero-knowledge age proof verified (age >= {})", required_age);
        Ok(true)
    }
    
    fn generate_membership_proof(&self, member_list: &[String], member_identity: &str, identity_seed: &[u8; 32]) -> Result<Vec<u8>> {
        if !member_list.contains(&member_identity.to_string()) {
            return Err(anyhow::anyhow!("Not a member of the group"));
        }
        
        // Create ring signature-like proof of membership without revealing which member
        let mut membership_data = Vec::new();
        
        // Include all member identities in proof
        for member in member_list {
            let member_hash = hashing::blake3_hash(member.as_bytes())?;
            membership_data.extend_from_slice(&member_hash);
        }
        
        // Add secret identity commitment
        let identity_commitment = hashing::blake3_hash(
            &format!("{}:{}", member_identity, hex::encode(identity_seed))
                .as_bytes()
        )?;
        membership_data.extend_from_slice(&identity_commitment);
        
        // Generate proof
        let proof_data = hashing::blake3_hash(&membership_data)?;
        let proof_signature = self.verifier_keypair.sign(&proof_data)?;
        
        let mut proof = Vec::new();
        proof.extend_from_slice(&proof_data);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        Ok(proof)
    }
}

fn zero_knowledge_proof_example() -> Result<()> {
    let mut zk_system = ZeroKnowledgeProofSystem::new()?;
    
    // Alice wants to prove she's over 18 without revealing her exact age
    let alice_age = 25;
    let alice_identity_seed = random::secure_random_bytes::<32>()?;
    
    let age_proof = zk_system.generate_age_proof(alice_age, 18, &alice_identity_seed)?;
    let is_valid = zk_system.verify_age_proof(&age_proof, 18)?;
    
    println!("Alice's age proof (>= 18): {}", is_valid);
    
    // Bob tries with insufficient age
    let bob_age = 16;
    let bob_identity_seed = random::secure_random_bytes::<32>()?;
    
    match zk_system.generate_age_proof(bob_age, 18, &bob_identity_seed) {
        Ok(_) => println!("Bob's age proof should have failed!"),
        Err(_) => println!("Bob's age proof correctly rejected (age < 18)"),
    }
    
    // Membership proof example
    let vip_members = vec![
        "alice_vip".to_string(),
        "bob_vip".to_string(),
        "charlie_vip".to_string(),
        "diana_vip".to_string(),
    ];
    
    let membership_proof = zk_system.generate_membership_proof(
        &vip_members, 
        "alice_vip", 
        &alice_identity_seed
    )?;
    
    println!("Membership proof generated: {} bytes", membership_proof.len());
    
    Ok(())
}
```

## Running the Examples

### Example Runner

```rust
use lib_crypto::*;

fn main() -> Result<()> {
    println!(" SOVEREIGN_NET Crypto Examples\n");
    
    // Basic examples
    println!("=== Basic Examples ===");
    hello_crypto_world()?;
    println!();
    
    key_management_example()?;
    println!();
    
    // Real-world applications
    println!("=== Real-World Applications ===");
    secure_messaging_example()?;
    println!();
    
    document_signing_example()?;
    println!();
    
    secure_file_storage_example()?;
    println!();
    
    // Advanced cryptography
    println!("=== Advanced Cryptography ===");
    multi_party_key_exchange_example()?;
    println!();
    
    zero_knowledge_proof_example()?;
    println!();
    
    println!(" All examples completed successfully!");
    
    Ok(())
}
```

### Performance Benchmarks

```rust
use lib_crypto::*;
use std::time::Instant;

fn benchmark_crypto_operations() -> Result<()> {
    println!(" Performance Benchmarks\n");
    
    let iterations = 1000;
    
    // Key generation benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = KeyPair::generate()?;
    }
    let key_gen_time = start.elapsed();
    println!("Key Generation: {} keys in {:?} ({:.2} keys/sec)", 
             iterations, key_gen_time, 
             iterations as f64 / key_gen_time.as_secs_f64());
    
    // Signing benchmark
    let keypair = KeyPair::generate()?;
    let message = b"Benchmark message for signing performance test";
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keypair.sign(message)?;
    }
    let signing_time = start.elapsed();
    println!("Signing: {} signatures in {:?} ({:.2} sigs/sec)", 
             iterations, signing_time, 
             iterations as f64 / signing_time.as_secs_f64());
    
    // Verification benchmark
    let signature = keypair.sign(message)?;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = keypair.verify(&signature, message)?;
    }
    let verify_time = start.elapsed();
    println!("Verification: {} verifications in {:?} ({:.2} verif/sec)", 
             iterations, verify_time, 
             iterations as f64 / verify_time.as_secs_f64());
    
    // Encryption benchmark
    let data = vec![0u8; 1024]; // 1KB
    
    let start = Instant::now();
    for i in 0..iterations {
        let metadata = format!("benchmark_{}", i);
        let _ = keypair.encrypt(&data, metadata.as_bytes())?;
    }
    let encrypt_time = start.elapsed();
    let throughput_mb = (iterations as f64 * data.len() as f64) / (1024.0 * 1024.0) / encrypt_time.as_secs_f64();
    println!("Encryption: {} × 1KB in {:?} ({:.2} MB/s)", 
             iterations, encrypt_time, throughput_mb);
    
    // Hashing benchmark
    let hash_data = vec![0u8; 10240]; // 10KB
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hashing::blake3_hash(&hash_data)?;
    }
    let hash_time = start.elapsed();
    let hash_throughput = (iterations as f64 * hash_data.len() as f64) / (1024.0 * 1024.0) / hash_time.as_secs_f64();
    println!("Hashing (BLAKE3): {} × 10KB in {:?} ({:.2} MB/s)", 
             iterations, hash_time, hash_throughput);
    
    Ok(())
}
```

These examples demonstrate the full range of lib-crypto capabilities in practical, real-world scenarios within the SOVEREIGN_NET ecosystem. Each example includes proper error handling, security best practices, and comprehensive documentation to help developers integrate cryptographic functionality effectively.
>>>>>>> c4b7181335bd61771d1d7f3e410fb0b739d7476d
