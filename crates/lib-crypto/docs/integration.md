<<<<<<< HEAD
# Integration Guide

Complete guide for integrating lib-crypto into SOVEREIGN_NET applications and external systems. Covers setup, configuration, API usage patterns, and best practices for different integration scenarios.

## Quick Start Integration

### Basic Setup

```rust
// Cargo.toml
[dependencies]
lib-crypto = { path = "../lib-crypto", version = "0.1.0" }
anyhow = "1.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }

// main.rs
use lib_crypto::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize cryptographic subsystem
    let keypair = KeyPair::generate()?;
    println!("Crypto system initialized with public key: {}", 
             hex::encode(keypair.public_key().as_bytes()));
    
    // Basic encryption/decryption
    let message = b"Hello, SOVEREIGN_NET!";
    let encrypted = keypair.encrypt(message, b"metadata")?;
    let decrypted = keypair.decrypt(&encrypted, b"metadata")?;
    
    assert_eq!(message, &decrypted[..]);
    println!("Basic crypto operations successful");
    
    Ok(())
}
```

### Feature Configuration

```rust
// Enable specific cryptographic features
use lib_crypto::{
    KeyPair,                    // Always available
    post_quantum::*,           // Post-quantum algorithms
    advanced::{RingSignature, MultiSignature}, // Advanced signatures
    symmetric::*,              // Symmetric encryption
    hashing::*,               // Hash functions
    random::*,                // Secure randomness
};

fn configure_crypto_features() -> Result<()> {
    // Feature detection
    println!("Available features:");
    println!("- Ed25519 signatures: ");
    println!("- CRYSTALS-Dilithium: {}", if cfg!(feature = "post-quantum") { "" } else { "✗" });
    println!("- Ring signatures: {}", if cfg!(feature = "advanced") { "" } else { "✗" });
    println!("- ChaCha20-Poly1305: ");
    println!("- BLAKE3 hashing: ");
    
    Ok(())
}
```

## Application Integration Patterns

### Web Application Integration

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct UserSession {
    user_id: String,
    session_token: String,
    keypair: KeyPair,
    created_at: u64,
    expires_at: u64,
}

struct WebCryptoService {
    sessions: Arc<RwLock<HashMap<String, UserSession>>>,
    server_keypair: KeyPair,
}

impl WebCryptoService {
    fn new() -> Result<Self> {
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            server_keypair: KeyPair::generate()?,
        })
    }
    
    async fn create_user_session(&self, user_id: String) -> Result<String> {
        let user_keypair = KeyPair::generate()?;
        let session_token = hex::encode(random::secure_random_bytes::<32>()?);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let session = UserSession {
            user_id: user_id.clone(),
            session_token: session_token.clone(),
            keypair: user_keypair,
            created_at: current_time,
            expires_at: current_time + 3600, // 1 hour
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(user_id, session);
        
        Ok(session_token)
    }
    
    async fn encrypt_user_data(&self, user_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(user_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        // Check session expiry
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if current_time > session.expires_at {
            return Err(anyhow::anyhow!("Session expired"));
        }
        
        // Encrypt with user's keypair
        let metadata = format!("user_id={},session={}", user_id, session.session_token);
        session.keypair.encrypt(data, metadata.as_bytes())
    }
    
    async fn sign_server_response(&self, response_data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.server_keypair.sign(response_data)?;
        
        // Format: [RESPONSE_DATA][SIGNATURE]
        let mut signed_response = Vec::new();
        signed_response.extend_from_slice(response_data);
        signed_response.extend_from_slice(&signature.as_bytes());
        
        Ok(signed_response)
    }
}

// Web framework integration example
async fn web_crypto_integration() -> Result<()> {
    let crypto_service = WebCryptoService::new()?;
    
    // User registration/login
    let session_token = crypto_service.create_user_session("alice".to_string()).await?;
    println!("Session created: {}", session_token);
    
    // Encrypt user data
    let user_data = b"Sensitive user information";
    let encrypted_data = crypto_service.encrypt_user_data("alice", user_data).await?;
    
    // Sign server response
    let response = b"Server response with encrypted data";
    let signed_response = crypto_service.sign_server_response(response).await?;
    
    println!("Web crypto integration successful");
    Ok(())
}
```

### Database Integration

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct EncryptedRecord {
    id: u64,
    encrypted_data: Vec<u8>,
    data_hash: [u8; 32],
    encryption_metadata: String,
    created_at: u64,
}

struct DatabaseCryptoLayer {
    database_keypair: KeyPair,
    table_keys: std::collections::HashMap<String, [u8; 32]>,
}

impl DatabaseCryptoLayer {
    fn new() -> Result<Self> {
        Ok(Self {
            database_keypair: KeyPair::generate()?,
            table_keys: std::collections::HashMap::new(),
        })
    }
    
    fn initialize_table(&mut self, table_name: &str) -> Result<()> {
        let table_key = random::secure_random_bytes::<32>()?;
        self.table_keys.insert(table_name.to_string(), table_key);
        println!("Initialized encryption for table: {}", table_name);
        Ok(())
    }
    
    fn encrypt_record(&self, table_name: &str, data: &[u8]) -> Result<EncryptedRecord> {
        let table_key = self.table_keys.get(table_name)
            .ok_or_else(|| anyhow::anyhow!("Table key not found: {}", table_name))?;
        
        // Generate record ID and metadata
        let record_id = random::secure_random_u64()?;
        let metadata = format!("table={},id={}", table_name, record_id);
        
        // Hash original data for integrity verification
        let data_hash = hashing::blake3_hash(data)?;
        
        // Encrypt data using hybrid encryption
        let encrypted_data = symmetric::encrypt_chacha20poly1305(
            data,
            metadata.as_bytes(),
            table_key,
            &random::secure_random_bytes::<12>()?
        )?;
        
        Ok(EncryptedRecord {
            id: record_id,
            encrypted_data,
            data_hash,
            encryption_metadata: metadata,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }
    
    fn decrypt_record(&self, table_name: &str, record: &EncryptedRecord) -> Result<Vec<u8>> {
        let table_key = self.table_keys.get(table_name)
            .ok_or_else(|| anyhow::anyhow!("Table key not found: {}", table_name))?;
        
        // Extract nonce from encrypted data (first 12 bytes)
        let nonce = &record.encrypted_data[..12];
        let ciphertext = &record.encrypted_data[12..];
        
        // Decrypt data
        let decrypted_data = symmetric::decrypt_chacha20poly1305(
            ciphertext,
            record.encryption_metadata.as_bytes(),
            table_key,
            nonce.try_into()?
        )?;
        
        // Verify data integrity
        let computed_hash = hashing::blake3_hash(&decrypted_data)?;
        if computed_hash != record.data_hash {
            return Err(anyhow::anyhow!("Data integrity check failed"));
        }
        
        Ok(decrypted_data)
    }
}

fn database_integration() -> Result<()> {
    let mut db_crypto = DatabaseCryptoLayer::new()?;
    
    // Initialize tables
    db_crypto.initialize_table("users")?;
    db_crypto.initialize_table("transactions")?;
    
    // Encrypt and store data
    let user_data = b"Sensitive user profile information";
    let encrypted_record = db_crypto.encrypt_record("users", user_data)?;
    
    // Later: decrypt data
    let decrypted_data = db_crypto.decrypt_record("users", &encrypted_record)?;
    assert_eq!(user_data, &decrypted_data[..]);
    
    println!("Database integration successful");
    Ok(())
}
```

### Network Protocol Integration

```rust
use lib_crypto::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct SecureProtocol {
    server_keypair: KeyPair,
    client_sessions: std::collections::HashMap<String, SessionState>,
}

struct SessionState {
    client_pubkey: [u8; 32],
    shared_secret: [u8; 32],
    message_counter: u64,
    established_at: std::time::SystemTime,
}

impl SecureProtocol {
    fn new() -> Result<Self> {
        Ok(Self {
            server_keypair: KeyPair::generate()?,
            client_sessions: std::collections::HashMap::new(),
        })
    }
    
    async fn handle_handshake(&mut self, client_pubkey: [u8; 32]) -> Result<([u8; 32], Vec<u8>)> {
        // Generate ephemeral key for this session
        let session_keypair = KeyPair::generate()?;
        
        // Perform key exchange (simplified ECDH-like)
        let shared_secret = self.compute_shared_secret(&client_pubkey, &session_keypair)?;
        
        // Store session state
        let session_id = hex::encode(random::secure_random_bytes::<16>()?);
        self.client_sessions.insert(session_id.clone(), SessionState {
            client_pubkey,
            shared_secret,
            message_counter: 0,
            established_at: std::time::SystemTime::now(),
        });
        
        // Return server's ephemeral public key
        Ok((shared_secret, session_keypair.public_key().as_bytes().to_vec()))
    }
    
    fn compute_shared_secret(&self, client_pubkey: &[u8; 32], session_keypair: &KeyPair) -> Result<[u8; 32]> {
        // Simplified key derivation - in practice use proper ECDH
        let mut key_material = Vec::new();
        key_material.extend_from_slice(client_pubkey);
        key_material.extend_from_slice(&session_keypair.public_key().as_bytes());
        key_material.extend_from_slice(&self.server_keypair.public_key().as_bytes());
        
        Ok(hashing::blake3_derive_key(&key_material, b"SOVEREIGN_NET_KDF"))
    }
    
    async fn encrypt_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let session = self.client_sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        // Create nonce from counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&session.message_counter.to_le_bytes());
        session.message_counter += 1;
        
        // Encrypt message
        let metadata = format!("session={}", session_id);
        let encrypted = symmetric::encrypt_chacha20poly1305(
            message,
            metadata.as_bytes(),
            &session.shared_secret,
            &nonce
        )?;
        
        // Format: [SESSION_ID][NONCE][ENCRYPTED_DATA]
        let mut packet = Vec::new();
        packet.extend_from_slice(session_id.as_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&encrypted);
        
        Ok(packet)
    }
}

async fn network_protocol_integration() -> Result<()> {
    let mut protocol = SecureProtocol::new()?;
    
    // Simulate client handshake
    let client_keypair = KeyPair::generate()?;
    let (shared_secret, server_pubkey) = protocol.handle_handshake(
        client_keypair.public_key().as_bytes().try_into()?
    ).await?;
    
    // Simulate encrypted communication
    let session_id = "test_session";
    let message = b"Secure network message";
    let encrypted_packet = protocol.encrypt_message(session_id, message).await?;
    
    println!("Network protocol integration successful, packet size: {} bytes", 
             encrypted_packet.len());
    
    Ok(())
}
```

## Blockchain Integration

### Transaction Signing

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
    timestamp: u64,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SignedTransaction {
    transaction: Transaction,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

struct BlockchainCrypto {
    validator_keypairs: Vec<KeyPair>,
    threshold: usize,
}

impl BlockchainCrypto {
    fn new(num_validators: usize, threshold: usize) -> Result<Self> {
        let validators = (0..num_validators)
            .map(|_| KeyPair::generate())
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            validator_keypairs: validators,
            threshold,
        })
    }
    
    fn sign_transaction(&self, transaction: &Transaction, signer_index: usize) -> Result<SignedTransaction> {
        let keypair = &self.validator_keypairs[signer_index];
        
        // Serialize transaction for signing
        let tx_bytes = bincode::serialize(transaction)?;
        let signature = keypair.sign(&tx_bytes)?;
        
        Ok(SignedTransaction {
            transaction: transaction.clone(),
            signature: signature.as_bytes().to_vec(),
            public_key: keypair.public_key().as_bytes().to_vec(),
        })
    }
    
    fn verify_transaction(&self, signed_tx: &SignedTransaction) -> Result<bool> {
        // Serialize transaction
        let tx_bytes = bincode::serialize(&signed_tx.transaction)?;
        
        // Reconstruct public key and verify
        let pubkey = PublicKey::from_bytes(&signed_tx.public_key)?;
        let signature = Signature::from_bytes(&signed_tx.signature)?;
        
        let keypair = KeyPair::from_public_key(pubkey);
        keypair.verify(&signature, &tx_bytes)
    }
    
    fn create_multi_sig_transaction(&self, transaction: &Transaction) -> Result<Vec<u8>> {
        let tx_bytes = bincode::serialize(transaction)?;
        
        // Get signatures from threshold number of validators
        let signatures: Result<Vec<_>, _> = self.validator_keypairs
            .iter()
            .take(self.threshold)
            .map(|kp| kp.sign(&tx_bytes))
            .collect();
        let signatures = signatures?;
        
        // Combine signatures (simplified - implementation would use proper multi-sig)
        let mut multi_sig = Vec::new();
        for sig in signatures {
            multi_sig.extend_from_slice(&sig.as_bytes());
        }
        
        Ok(multi_sig)
    }
}

fn blockchain_integration() -> Result<()> {
    let blockchain_crypto = BlockchainCrypto::new(5, 3)?; // 3-of-5 multi-sig
    
    // Create transaction
    let transaction = Transaction {
        from: "alice".to_string(),
        to: "bob".to_string(),
        amount: 1000,
        nonce: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        data: b"Payment for services".to_vec(),
    };
    
    // Sign transaction
    let signed_tx = blockchain_crypto.sign_transaction(&transaction, 0)?;
    
    // Verify transaction
    let is_valid = blockchain_crypto.verify_transaction(&signed_tx)?;
    println!("Transaction verification: {}", is_valid);
    
    // Multi-signature transaction
    let multi_sig = blockchain_crypto.create_multi_sig_transaction(&transaction)?;
    println!("Multi-signature created: {} bytes", multi_sig.len());
    
    Ok(())
}
```

### Smart Contract Integration

```rust
use lib_crypto::*;

struct SmartContract {
    contract_keypair: KeyPair,
    state_hash: [u8; 32],
    execution_log: Vec<ExecutionRecord>,
}

struct ExecutionRecord {
    function_name: String,
    parameters: Vec<u8>,
    result: Vec<u8>,
    gas_used: u64,
    timestamp: u64,
    signature: Vec<u8>,
}

impl SmartContract {
    fn new() -> Result<Self> {
        Ok(Self {
            contract_keypair: KeyPair::generate()?,
            state_hash: [0u8; 32],
            execution_log: Vec::new(),
        })
    }
    
    fn execute_function(&mut self, function_name: &str, parameters: &[u8], executor_pubkey: &[u8]) -> Result<Vec<u8>> {
        // Verify executor has permission (simplified)
        let permission_granted = self.verify_execution_permission(executor_pubkey)?;
        if !permission_granted {
            return Err(anyhow::anyhow!("Execution permission denied"));
        }
        
        // Execute function (simplified)
        let result = match function_name {
            "transfer" => self.execute_transfer(parameters)?,
            "balance" => self.get_balance(parameters)?,
            _ => return Err(anyhow::anyhow!("Unknown function: {}", function_name)),
        };
        
        // Update state hash
        self.update_state_hash(function_name, parameters, &result)?;
        
        // Create execution record
        let execution_data = format!("{}:{}", function_name, hex::encode(parameters));
        let signature = self.contract_keypair.sign(execution_data.as_bytes())?;
        
        let record = ExecutionRecord {
            function_name: function_name.to_string(),
            parameters: parameters.to_vec(),
            result: result.clone(),
            gas_used: 21000, // Simplified
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            signature: signature.as_bytes().to_vec(),
        };
        
        self.execution_log.push(record);
        
        Ok(result)
    }
    
    fn verify_execution_permission(&self, executor_pubkey: &[u8]) -> Result<bool> {
        // Simplified permission check - in practice would check ACL
        Ok(executor_pubkey.len() == 32) // Basic validation
    }
    
    fn execute_transfer(&self, parameters: &[u8]) -> Result<Vec<u8>> {
        // Simplified transfer logic
        Ok(b"Transfer successful".to_vec())
    }
    
    fn get_balance(&self, parameters: &[u8]) -> Result<Vec<u8> {
        // Simplified balance query
        Ok(b"1000".to_vec())
    }
    
    fn update_state_hash(&mut self, function: &str, params: &[u8], result: &[u8]) -> Result<()> {
        let mut state_data = Vec::new();
        state_data.extend_from_slice(&self.state_hash);
        state_data.extend_from_slice(function.as_bytes());
        state_data.extend_from_slice(params);
        state_data.extend_from_slice(result);
        
        self.state_hash = hashing::blake3_hash(&state_data)?;
        Ok(())
    }
    
    fn get_state_proof(&self) -> Result<Vec<u8>> {
        // Generate cryptographic proof of current state
        let state_commitment = hashing::blake3_hash(&bincode::serialize(&self.execution_log)?)?;
        let proof_signature = self.contract_keypair.sign(&state_commitment)?;
        
        // Combine state hash and signature
        let mut proof = Vec::new();
        proof.extend_from_slice(&self.state_hash);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        Ok(proof)
    }
}

fn smart_contract_integration() -> Result<()> {
    let mut contract = SmartContract::new()?;
    let executor_keypair = KeyPair::generate()?;
    
    // Execute contract function
    let transfer_params = b"alice:bob:100";
    let result = contract.execute_function(
        "transfer", 
        transfer_params,
        &executor_keypair.public_key().as_bytes()
    )?;
    
    println!("Contract execution result: {}", String::from_utf8_lossy(&result));
    
    // Generate state proof
    let state_proof = contract.get_state_proof()?;
    println!("State proof generated: {} bytes", state_proof.len());
    
    Ok(())
}
```

## Microservices Integration

### Service-to-Service Authentication

```rust
use lib_crypto::*;
use tokio::time::{Duration, Instant};

struct ServiceAuthenticator {
    service_keypair: KeyPair,
    trusted_services: std::collections::HashMap<String, [u8; 32]>, // service_id -> public_key
    token_cache: std::collections::HashMap<String, (String, Instant)>, // service_id -> (token, expiry)
}

impl ServiceAuthenticator {
    fn new(service_id: &str) -> Result<Self> {
        Ok(Self {
            service_keypair: KeyPair::generate()?,
            trusted_services: std::collections::HashMap::new(),
            token_cache: std::collections::HashMap::new(),
        })
    }
    
    fn register_trusted_service(&mut self, service_id: &str, public_key: &[u8; 32]) {
        self.trusted_services.insert(service_id.to_string(), *public_key);
        println!("Registered trusted service: {}", service_id);
    }
    
    fn generate_auth_token(&mut self, target_service: &str) -> Result<String> {
        // Create JWT-like token with cryptographic signature
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let token_data = serde_json::json!({
            "iss": "current_service",
            "aud": target_service,
            "iat": current_time,
            "exp": current_time + 3600, // 1 hour expiry
            "nonce": hex::encode(random::secure_random_bytes::<16>()?)
        });
        
        let token_bytes = token_data.to_string().into_bytes();
        let signature = self.service_keypair.sign(&token_bytes)?;
        
        // Base64 encode token and signature
        let token_b64 = base64::encode(&token_bytes);
        let sig_b64 = base64::encode(signature.as_bytes());
        
        let auth_token = format!("{}.{}", token_b64, sig_b64);
        
        // Cache token
        self.token_cache.insert(
            target_service.to_string(),
            (auth_token.clone(), Instant::now() + Duration::from_secs(3600))
        );
        
        Ok(auth_token)
    }
    
    fn verify_auth_token(&self, token: &str, sender_service: &str) -> Result<bool> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Ok(false);
        }
        
        let token_bytes = base64::decode(parts[0])?;
        let signature_bytes = base64::decode(parts[1])?;
        
        // Get sender's public key
        let sender_pubkey = self.trusted_services.get(sender_service)
            .ok_or_else(|| anyhow::anyhow!("Untrusted service: {}", sender_service))?;
        
        // Verify signature
        let sender_keypair = KeyPair::from_public_key(PublicKey::from_bytes(sender_pubkey)?);
        let signature = Signature::from_bytes(&signature_bytes)?;
        let is_valid = sender_keypair.verify(&signature, &token_bytes)?;
        
        if !is_valid {
            return Ok(false);
        }
        
        // Parse and validate token claims
        let token_data: serde_json::Value = serde_json::from_slice(&token_bytes)?;
        let exp = token_data["exp"].as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid token format"))?;
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        Ok(current_time < exp)
    }
}

async fn microservices_integration() -> Result<()> {
    // Service A
    let mut service_a = ServiceAuthenticator::new("service-a")?;
    let service_a_pubkey = service_a.service_keypair.public_key().as_bytes().try_into()?;
    
    // Service B
    let mut service_b = ServiceAuthenticator::new("service-b")?;
    let service_b_pubkey = service_b.service_keypair.public_key().as_bytes().try_into()?;
    
    // Register mutual trust
    service_a.register_trusted_service("service-b", &service_b_pubkey);
    service_b.register_trusted_service("service-a", &service_a_pubkey);
    
    // Service A authenticates to Service B
    let auth_token = service_a.generate_auth_token("service-b")?;
    let is_valid = service_b.verify_auth_token(&auth_token, "service-a")?;
    
    println!("Service authentication: {}", is_valid);
    
    Ok(())
}
```

## Performance Optimization

### Crypto Operation Caching

```rust
use lib_crypto::*;
use std::collections::LRU; // Hypothetical LRU cache

struct CryptoCache {
    signature_cache: LRU<([u8; 32], [u8; 64]), bool>, // (message_hash, signature) -> valid
    hash_cache: LRU<Vec<u8>, [u8; 32]>, // data -> hash
    keypair_cache: LRU<[u8; 32], KeyPair>, // seed -> keypair
}

impl CryptoCache {
    fn new() -> Self {
        Self {
            signature_cache: LRU::new(1000),
            hash_cache: LRU::new(5000),
            keypair_cache: LRU::new(100),
        }
    }
    
    fn cached_verify(&mut self, signature: &[u8; 64], message: &[u8], pubkey: &[u8; 32]) -> Result<bool> {
        let message_hash = self.cached_hash(message)?;
        let cache_key = (message_hash, *signature);
        
        if let Some(&cached_result) = self.signature_cache.get(&cache_key) {
            return Ok(cached_result);
        }
        
        // Perform actual verification
        let keypair = KeyPair::from_public_key(PublicKey::from_bytes(pubkey)?);
        let sig = Signature::from_bytes(signature)?;
        let result = keypair.verify(&sig, message)?;
        
        // Cache result
        self.signature_cache.insert(cache_key, result);
        
        Ok(result)
    }
    
    fn cached_hash(&mut self, data: &[u8]) -> Result<[u8; 32]> {
        if let Some(&cached_hash) = self.hash_cache.get(data) {
            return Ok(cached_hash);
        }
        
        let hash = hashing::blake3_hash(data)?;
        self.hash_cache.insert(data.to_vec(), hash);
        
        Ok(hash)
    }
}
```

### Batch Operations

```rust
use lib_crypto::*;
use rayon::prelude::*;

struct BatchCryptoProcessor {
    thread_pool: rayon::ThreadPool,
}

impl BatchCryptoProcessor {
    fn new() -> Self {
        Self {
            thread_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .unwrap(),
        }
    }
    
    fn batch_verify_signatures(&self, jobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> Vec<Result<bool>> {
        // Parallel signature verification
        jobs.par_iter()
            .map(|(signature, message, pubkey)| {
                let keypair = KeyPair::from_public_key(PublicKey::from_bytes(pubkey)?)?;
                let sig = Signature::from_bytes(signature)?;
                keypair.verify(&sig, message)
            })
            .collect()
    }
    
    fn batch_hash(&self, data_chunks: Vec<Vec<u8>>) -> Vec<[u8; 32]> {
        data_chunks.par_iter()
            .map(|data| hashing::blake3_hash(data).unwrap())
            .collect()
    }
    
    fn batch_encrypt(&self, plaintexts: Vec<Vec<u8>>, keypair: &KeyPair) -> Vec<Result<Vec<u8>>> {
        plaintexts.par_iter()
            .enumerate()
            .map(|(i, plaintext)| {
                let metadata = format!("batch_item_{}", i);
                keypair.encrypt(plaintext, metadata.as_bytes())
            })
            .collect()
    }
}

fn performance_optimization() -> Result<()> {
    let processor = BatchCryptoProcessor::new();
    
    // Prepare batch operations
    let keypair = KeyPair::generate()?;
    let messages: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    
    // Batch signature verification
    let signatures: Result<Vec<_>, _> = messages.iter()
        .map(|msg| keypair.sign(msg).map(|sig| sig.as_bytes().to_vec()))
        .collect();
    let signatures = signatures?;
    
    let verification_jobs: Vec<_> = signatures.iter()
        .zip(messages.iter())
        .map(|(sig, msg)| (sig.clone(), msg.clone(), keypair.public_key().as_bytes().to_vec()))
        .collect();
    
    let start = std::time::Instant::now();
    let results = processor.batch_verify_signatures(verification_jobs);
    let batch_time = start.elapsed();
    
    let valid_count = results.iter().filter(|r| r.as_ref().unwrap_or(&false)).count();
    println!("Batch verified {}/{} signatures in {:?}", valid_count, results.len(), batch_time);
    
    // Batch encryption
    let start = std::time::Instant::now();
    let encrypted_messages = processor.batch_encrypt(messages, &keypair);
    let encrypt_time = start.elapsed();
    
    let success_count = encrypted_messages.iter().filter(|r| r.is_ok()).count();
    println!("Batch encrypted {}/{} messages in {:?}", success_count, encrypted_messages.len(), encrypt_time);
    
    Ok(())
}
```

## Testing Integration

### Integration Test Framework

```rust
use lib_crypto::*;

struct CryptoIntegrationTest {
    test_keypairs: Vec<KeyPair>,
    test_data: Vec<Vec<u8>>,
}

impl CryptoIntegrationTest {
    fn new() -> Result<Self> {
        let keypairs = (0..10)
            .map(|_| KeyPair::generate())
            .collect::<Result<Vec<_>, _>>()?;
        
        let test_data = vec![
            b"Short message".to_vec(),
            vec![0u8; 1024], // 1KB
            vec![0u8; 1024 * 1024], // 1MB
            b"Unicode test: 💻".to_vec(),
            Vec::new(), // Empty
        ];
        
        Ok(Self {
            test_keypairs: keypairs,
            test_data,
        })
    }
    
    fn test_end_to_end_encryption(&self) -> Result<()> {
        for (i, keypair) in self.test_keypairs.iter().enumerate() {
            for (j, data) in self.test_data.iter().enumerate() {
                let metadata = format!("test_{}_{}", i, j);
                
                // Encrypt
                let encrypted = keypair.encrypt(data, metadata.as_bytes())?;
                
                // Decrypt
                let decrypted = keypair.decrypt(&encrypted, metadata.as_bytes())?;
                
                // Verify
                if data != &decrypted {
                    return Err(anyhow::anyhow!("E2E test failed: keypair {}, data {}", i, j));
                }
            }
        }
        
        println!(" End-to-end encryption tests passed");
        Ok(())
    }
    
    fn test_signature_verification(&self) -> Result<()> {
        for (i, keypair) in self.test_keypairs.iter().enumerate() {
            for (j, data) in self.test_data.iter().enumerate() {
                if data.is_empty() { continue; } // Skip empty messages
                
                // Sign
                let signature = keypair.sign(data)?;
                
                // Verify with correct key
                if !keypair.verify(&signature, data)? {
                    return Err(anyhow::anyhow!("Signature verification failed: keypair {}, data {}", i, j));
                }
                
                // Verify with wrong key (should fail)
                if let Some(wrong_keypair) = self.test_keypairs.get((i + 1) % self.test_keypairs.len()) {
                    if wrong_keypair.verify(&signature, data).unwrap_or(false) {
                        return Err(anyhow::anyhow!("Wrong key verified signature: keypair {}, data {}", i, j));
                    }
                }
            }
        }
        
        println!(" Signature verification tests passed");
        Ok(())
    }
    
    fn test_cross_compatibility(&self) -> Result<()> {
        // Test that different instances can interoperate
        let alice_keypair = &self.test_keypairs[0];
        let bob_keypair = &self.test_keypairs[1];
        
        let message = b"Cross-compatibility test message";
        
        // Alice encrypts for Alice (self)
        let alice_encrypted = alice_keypair.encrypt(message, b"alice_to_alice")?;
        let alice_decrypted = alice_keypair.decrypt(&alice_encrypted, b"alice_to_alice")?;
        assert_eq!(message, &alice_decrypted[..]);
        
        // Alice signs, Bob verifies (with Alice's public key)
        let alice_signature = alice_keypair.sign(message)?;
        let alice_pubkey = alice_keypair.public_key();
        let alice_keypair_from_pubkey = KeyPair::from_public_key(alice_pubkey);
        let bob_verifies_alice = alice_keypair_from_pubkey.verify(&alice_signature, message)?;
        assert!(bob_verifies_alice);
        
        println!(" Cross-compatibility tests passed");
        Ok(())
    }
    
    fn run_all_tests(&self) -> Result<()> {
        println!("Running crypto integration tests...");
        
        self.test_end_to_end_encryption()?;
        self.test_signature_verification()?;
        self.test_cross_compatibility()?;
        
        println!(" All integration tests passed!");
        Ok(())
    }
}

fn integration_testing() -> Result<()> {
    let test_suite = CryptoIntegrationTest::new()?;
    test_suite.run_all_tests()?;
    Ok(())
}
```

This integration guide provides comprehensive examples for integrating lib-crypto into various application architectures within the SOVEREIGN_NET ecosystem, covering web applications, databases, blockchain systems, microservices, and performance optimization strategies.
=======
# Integration Guide

Complete guide for integrating lib-crypto into SOVEREIGN_NET applications and external systems. Covers setup, configuration, API usage patterns, and best practices for different integration scenarios.

## Quick Start Integration

### Basic Setup

```rust
// Cargo.toml
[dependencies]
lib-crypto = { path = "../lib-crypto", version = "0.1.0" }
anyhow = "1.0"
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }

// main.rs
use lib_crypto::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize cryptographic subsystem
    let keypair = KeyPair::generate()?;
    println!("Crypto system initialized with public key: {}", 
             hex::encode(keypair.public_key().as_bytes()));
    
    // Basic encryption/decryption
    let message = b"Hello, SOVEREIGN_NET!";
    let encrypted = keypair.encrypt(message, b"metadata")?;
    let decrypted = keypair.decrypt(&encrypted, b"metadata")?;
    
    assert_eq!(message, &decrypted[..]);
    println!("Basic crypto operations successful");
    
    Ok(())
}
```

### Feature Configuration

```rust
// Enable specific cryptographic features
use lib_crypto::{
    KeyPair,                    // Always available
    post_quantum::*,           // Post-quantum algorithms
    advanced::{RingSignature, MultiSignature}, // Advanced signatures
    symmetric::*,              // Symmetric encryption
    hashing::*,               // Hash functions
    random::*,                // Secure randomness
};

fn configure_crypto_features() -> Result<()> {
    // Feature detection
    println!("Available features:");
    println!("- Ed25519 signatures: ");
    println!("- CRYSTALS-Dilithium: {}", if cfg!(feature = "post-quantum") { "" } else { "✗" });
    println!("- Ring signatures: {}", if cfg!(feature = "advanced") { "" } else { "✗" });
    println!("- ChaCha20-Poly1305: ");
    println!("- BLAKE3 hashing: ");
    
    Ok(())
}
```

## Application Integration Patterns

### Web Application Integration

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
struct UserSession {
    user_id: String,
    session_token: String,
    keypair: KeyPair,
    created_at: u64,
    expires_at: u64,
}

struct WebCryptoService {
    sessions: Arc<RwLock<HashMap<String, UserSession>>>,
    server_keypair: KeyPair,
}

impl WebCryptoService {
    fn new() -> Result<Self> {
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            server_keypair: KeyPair::generate()?,
        })
    }
    
    async fn create_user_session(&self, user_id: String) -> Result<String> {
        let user_keypair = KeyPair::generate()?;
        let session_token = hex::encode(random::secure_random_bytes::<32>()?);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let session = UserSession {
            user_id: user_id.clone(),
            session_token: session_token.clone(),
            keypair: user_keypair,
            created_at: current_time,
            expires_at: current_time + 3600, // 1 hour
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(user_id, session);
        
        Ok(session_token)
    }
    
    async fn encrypt_user_data(&self, user_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(user_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        // Check session expiry
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if current_time > session.expires_at {
            return Err(anyhow::anyhow!("Session expired"));
        }
        
        // Encrypt with user's keypair
        let metadata = format!("user_id={},session={}", user_id, session.session_token);
        session.keypair.encrypt(data, metadata.as_bytes())
    }
    
    async fn sign_server_response(&self, response_data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.server_keypair.sign(response_data)?;
        
        // Format: [RESPONSE_DATA][SIGNATURE]
        let mut signed_response = Vec::new();
        signed_response.extend_from_slice(response_data);
        signed_response.extend_from_slice(&signature.as_bytes());
        
        Ok(signed_response)
    }
}

// Web framework integration example
async fn web_crypto_integration() -> Result<()> {
    let crypto_service = WebCryptoService::new()?;
    
    // User registration/login
    let session_token = crypto_service.create_user_session("alice".to_string()).await?;
    println!("Session created: {}", session_token);
    
    // Encrypt user data
    let user_data = b"Sensitive user information";
    let encrypted_data = crypto_service.encrypt_user_data("alice", user_data).await?;
    
    // Sign server response
    let response = b"Server response with encrypted data";
    let signed_response = crypto_service.sign_server_response(response).await?;
    
    println!("Web crypto integration successful");
    Ok(())
}
```

### Database Integration

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct EncryptedRecord {
    id: u64,
    encrypted_data: Vec<u8>,
    data_hash: [u8; 32],
    encryption_metadata: String,
    created_at: u64,
}

struct DatabaseCryptoLayer {
    database_keypair: KeyPair,
    table_keys: std::collections::HashMap<String, [u8; 32]>,
}

impl DatabaseCryptoLayer {
    fn new() -> Result<Self> {
        Ok(Self {
            database_keypair: KeyPair::generate()?,
            table_keys: std::collections::HashMap::new(),
        })
    }
    
    fn initialize_table(&mut self, table_name: &str) -> Result<()> {
        let table_key = random::secure_random_bytes::<32>()?;
        self.table_keys.insert(table_name.to_string(), table_key);
        println!("Initialized encryption for table: {}", table_name);
        Ok(())
    }
    
    fn encrypt_record(&self, table_name: &str, data: &[u8]) -> Result<EncryptedRecord> {
        let table_key = self.table_keys.get(table_name)
            .ok_or_else(|| anyhow::anyhow!("Table key not found: {}", table_name))?;
        
        // Generate record ID and metadata
        let record_id = random::secure_random_u64()?;
        let metadata = format!("table={},id={}", table_name, record_id);
        
        // Hash original data for integrity verification
        let data_hash = hashing::blake3_hash(data)?;
        
        // Encrypt data using hybrid encryption
        let encrypted_data = symmetric::encrypt_chacha20poly1305(
            data,
            metadata.as_bytes(),
            table_key,
            &random::secure_random_bytes::<12>()?
        )?;
        
        Ok(EncryptedRecord {
            id: record_id,
            encrypted_data,
            data_hash,
            encryption_metadata: metadata,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }
    
    fn decrypt_record(&self, table_name: &str, record: &EncryptedRecord) -> Result<Vec<u8>> {
        let table_key = self.table_keys.get(table_name)
            .ok_or_else(|| anyhow::anyhow!("Table key not found: {}", table_name))?;
        
        // Extract nonce from encrypted data (first 12 bytes)
        let nonce = &record.encrypted_data[..12];
        let ciphertext = &record.encrypted_data[12..];
        
        // Decrypt data
        let decrypted_data = symmetric::decrypt_chacha20poly1305(
            ciphertext,
            record.encryption_metadata.as_bytes(),
            table_key,
            nonce.try_into()?
        )?;
        
        // Verify data integrity
        let computed_hash = hashing::blake3_hash(&decrypted_data)?;
        if computed_hash != record.data_hash {
            return Err(anyhow::anyhow!("Data integrity check failed"));
        }
        
        Ok(decrypted_data)
    }
}

fn database_integration() -> Result<()> {
    let mut db_crypto = DatabaseCryptoLayer::new()?;
    
    // Initialize tables
    db_crypto.initialize_table("users")?;
    db_crypto.initialize_table("transactions")?;
    
    // Encrypt and store data
    let user_data = b"Sensitive user profile information";
    let encrypted_record = db_crypto.encrypt_record("users", user_data)?;
    
    // Later: decrypt data
    let decrypted_data = db_crypto.decrypt_record("users", &encrypted_record)?;
    assert_eq!(user_data, &decrypted_data[..]);
    
    println!("Database integration successful");
    Ok(())
}
```

### Network Protocol Integration

```rust
use lib_crypto::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct SecureProtocol {
    server_keypair: KeyPair,
    client_sessions: std::collections::HashMap<String, SessionState>,
}

struct SessionState {
    client_pubkey: [u8; 32],
    shared_secret: [u8; 32],
    message_counter: u64,
    established_at: std::time::SystemTime,
}

impl SecureProtocol {
    fn new() -> Result<Self> {
        Ok(Self {
            server_keypair: KeyPair::generate()?,
            client_sessions: std::collections::HashMap::new(),
        })
    }
    
    async fn handle_handshake(&mut self, client_pubkey: [u8; 32]) -> Result<([u8; 32], Vec<u8>)> {
        // Generate ephemeral key for this session
        let session_keypair = KeyPair::generate()?;
        
        // Perform key exchange (simplified ECDH-like)
        let shared_secret = self.compute_shared_secret(&client_pubkey, &session_keypair)?;
        
        // Store session state
        let session_id = hex::encode(random::secure_random_bytes::<16>()?);
        self.client_sessions.insert(session_id.clone(), SessionState {
            client_pubkey,
            shared_secret,
            message_counter: 0,
            established_at: std::time::SystemTime::now(),
        });
        
        // Return server's ephemeral public key
        Ok((shared_secret, session_keypair.public_key().as_bytes().to_vec()))
    }
    
    fn compute_shared_secret(&self, client_pubkey: &[u8; 32], session_keypair: &KeyPair) -> Result<[u8; 32]> {
        // Simplified key derivation - in practice use proper ECDH
        let mut key_material = Vec::new();
        key_material.extend_from_slice(client_pubkey);
        key_material.extend_from_slice(&session_keypair.public_key().as_bytes());
        key_material.extend_from_slice(&self.server_keypair.public_key().as_bytes());
        
        Ok(hashing::blake3_derive_key(&key_material, b"SOVEREIGN_NET_KDF"))
    }
    
    async fn encrypt_message(&mut self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let session = self.client_sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        // Create nonce from counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&session.message_counter.to_le_bytes());
        session.message_counter += 1;
        
        // Encrypt message
        let metadata = format!("session={}", session_id);
        let encrypted = symmetric::encrypt_chacha20poly1305(
            message,
            metadata.as_bytes(),
            &session.shared_secret,
            &nonce
        )?;
        
        // Format: [SESSION_ID][NONCE][ENCRYPTED_DATA]
        let mut packet = Vec::new();
        packet.extend_from_slice(session_id.as_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&encrypted);
        
        Ok(packet)
    }
}

async fn network_protocol_integration() -> Result<()> {
    let mut protocol = SecureProtocol::new()?;
    
    // Simulate client handshake
    let client_keypair = KeyPair::generate()?;
    let (shared_secret, server_pubkey) = protocol.handle_handshake(
        client_keypair.public_key().as_bytes().try_into()?
    ).await?;
    
    // Simulate encrypted communication
    let session_id = "test_session";
    let message = b"Secure network message";
    let encrypted_packet = protocol.encrypt_message(session_id, message).await?;
    
    println!("Network protocol integration successful, packet size: {} bytes", 
             encrypted_packet.len());
    
    Ok(())
}
```

## Blockchain Integration

### Transaction Signing

```rust
use lib_crypto::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
    nonce: u64,
    timestamp: u64,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SignedTransaction {
    transaction: Transaction,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

struct BlockchainCrypto {
    validator_keypairs: Vec<KeyPair>,
    threshold: usize,
}

impl BlockchainCrypto {
    fn new(num_validators: usize, threshold: usize) -> Result<Self> {
        let validators = (0..num_validators)
            .map(|_| KeyPair::generate())
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            validator_keypairs: validators,
            threshold,
        })
    }
    
    fn sign_transaction(&self, transaction: &Transaction, signer_index: usize) -> Result<SignedTransaction> {
        let keypair = &self.validator_keypairs[signer_index];
        
        // Serialize transaction for signing
        let tx_bytes = bincode::serialize(transaction)?;
        let signature = keypair.sign(&tx_bytes)?;
        
        Ok(SignedTransaction {
            transaction: transaction.clone(),
            signature: signature.as_bytes().to_vec(),
            public_key: keypair.public_key().as_bytes().to_vec(),
        })
    }
    
    fn verify_transaction(&self, signed_tx: &SignedTransaction) -> Result<bool> {
        // Serialize transaction
        let tx_bytes = bincode::serialize(&signed_tx.transaction)?;
        
        // Reconstruct public key and verify
        let pubkey = PublicKey::from_bytes(&signed_tx.public_key)?;
        let signature = Signature::from_bytes(&signed_tx.signature)?;
        
        let keypair = KeyPair::from_public_key(pubkey);
        keypair.verify(&signature, &tx_bytes)
    }
    
    fn create_multi_sig_transaction(&self, transaction: &Transaction) -> Result<Vec<u8>> {
        let tx_bytes = bincode::serialize(transaction)?;
        
        // Get signatures from threshold number of validators
        let signatures: Result<Vec<_>, _> = self.validator_keypairs
            .iter()
            .take(self.threshold)
            .map(|kp| kp.sign(&tx_bytes))
            .collect();
        let signatures = signatures?;
        
        // Combine signatures (simplified - implementation would use proper multi-sig)
        let mut multi_sig = Vec::new();
        for sig in signatures {
            multi_sig.extend_from_slice(&sig.as_bytes());
        }
        
        Ok(multi_sig)
    }
}

fn blockchain_integration() -> Result<()> {
    let blockchain_crypto = BlockchainCrypto::new(5, 3)?; // 3-of-5 multi-sig
    
    // Create transaction
    let transaction = Transaction {
        from: "alice".to_string(),
        to: "bob".to_string(),
        amount: 1000,
        nonce: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        data: b"Payment for services".to_vec(),
    };
    
    // Sign transaction
    let signed_tx = blockchain_crypto.sign_transaction(&transaction, 0)?;
    
    // Verify transaction
    let is_valid = blockchain_crypto.verify_transaction(&signed_tx)?;
    println!("Transaction verification: {}", is_valid);
    
    // Multi-signature transaction
    let multi_sig = blockchain_crypto.create_multi_sig_transaction(&transaction)?;
    println!("Multi-signature created: {} bytes", multi_sig.len());
    
    Ok(())
}
```

### Smart Contract Integration

```rust
use lib_crypto::*;

struct SmartContract {
    contract_keypair: KeyPair,
    state_hash: [u8; 32],
    execution_log: Vec<ExecutionRecord>,
}

struct ExecutionRecord {
    function_name: String,
    parameters: Vec<u8>,
    result: Vec<u8>,
    gas_used: u64,
    timestamp: u64,
    signature: Vec<u8>,
}

impl SmartContract {
    fn new() -> Result<Self> {
        Ok(Self {
            contract_keypair: KeyPair::generate()?,
            state_hash: [0u8; 32],
            execution_log: Vec::new(),
        })
    }
    
    fn execute_function(&mut self, function_name: &str, parameters: &[u8], executor_pubkey: &[u8]) -> Result<Vec<u8>> {
        // Verify executor has permission (simplified)
        let permission_granted = self.verify_execution_permission(executor_pubkey)?;
        if !permission_granted {
            return Err(anyhow::anyhow!("Execution permission denied"));
        }
        
        // Execute function (simplified)
        let result = match function_name {
            "transfer" => self.execute_transfer(parameters)?,
            "balance" => self.get_balance(parameters)?,
            _ => return Err(anyhow::anyhow!("Unknown function: {}", function_name)),
        };
        
        // Update state hash
        self.update_state_hash(function_name, parameters, &result)?;
        
        // Create execution record
        let execution_data = format!("{}:{}", function_name, hex::encode(parameters));
        let signature = self.contract_keypair.sign(execution_data.as_bytes())?;
        
        let record = ExecutionRecord {
            function_name: function_name.to_string(),
            parameters: parameters.to_vec(),
            result: result.clone(),
            gas_used: 21000, // Simplified
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            signature: signature.as_bytes().to_vec(),
        };
        
        self.execution_log.push(record);
        
        Ok(result)
    }
    
    fn verify_execution_permission(&self, executor_pubkey: &[u8]) -> Result<bool> {
        // Simplified permission check - in practice would check ACL
        Ok(executor_pubkey.len() == 32) // Basic validation
    }
    
    fn execute_transfer(&self, parameters: &[u8]) -> Result<Vec<u8>> {
        // Simplified transfer logic
        Ok(b"Transfer successful".to_vec())
    }
    
    fn get_balance(&self, parameters: &[u8]) -> Result<Vec<u8> {
        // Simplified balance query
        Ok(b"1000".to_vec())
    }
    
    fn update_state_hash(&mut self, function: &str, params: &[u8], result: &[u8]) -> Result<()> {
        let mut state_data = Vec::new();
        state_data.extend_from_slice(&self.state_hash);
        state_data.extend_from_slice(function.as_bytes());
        state_data.extend_from_slice(params);
        state_data.extend_from_slice(result);
        
        self.state_hash = hashing::blake3_hash(&state_data)?;
        Ok(())
    }
    
    fn get_state_proof(&self) -> Result<Vec<u8>> {
        // Generate cryptographic proof of current state
        let state_commitment = hashing::blake3_hash(&bincode::serialize(&self.execution_log)?)?;
        let proof_signature = self.contract_keypair.sign(&state_commitment)?;
        
        // Combine state hash and signature
        let mut proof = Vec::new();
        proof.extend_from_slice(&self.state_hash);
        proof.extend_from_slice(&proof_signature.as_bytes());
        
        Ok(proof)
    }
}

fn smart_contract_integration() -> Result<()> {
    let mut contract = SmartContract::new()?;
    let executor_keypair = KeyPair::generate()?;
    
    // Execute contract function
    let transfer_params = b"alice:bob:100";
    let result = contract.execute_function(
        "transfer", 
        transfer_params,
        &executor_keypair.public_key().as_bytes()
    )?;
    
    println!("Contract execution result: {}", String::from_utf8_lossy(&result));
    
    // Generate state proof
    let state_proof = contract.get_state_proof()?;
    println!("State proof generated: {} bytes", state_proof.len());
    
    Ok(())
}
```

## Microservices Integration

### Service-to-Service Authentication

```rust
use lib_crypto::*;
use tokio::time::{Duration, Instant};

struct ServiceAuthenticator {
    service_keypair: KeyPair,
    trusted_services: std::collections::HashMap<String, [u8; 32]>, // service_id -> public_key
    token_cache: std::collections::HashMap<String, (String, Instant)>, // service_id -> (token, expiry)
}

impl ServiceAuthenticator {
    fn new(service_id: &str) -> Result<Self> {
        Ok(Self {
            service_keypair: KeyPair::generate()?,
            trusted_services: std::collections::HashMap::new(),
            token_cache: std::collections::HashMap::new(),
        })
    }
    
    fn register_trusted_service(&mut self, service_id: &str, public_key: &[u8; 32]) {
        self.trusted_services.insert(service_id.to_string(), *public_key);
        println!("Registered trusted service: {}", service_id);
    }
    
    fn generate_auth_token(&mut self, target_service: &str) -> Result<String> {
        // Create JWT-like token with cryptographic signature
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let token_data = serde_json::json!({
            "iss": "current_service",
            "aud": target_service,
            "iat": current_time,
            "exp": current_time + 3600, // 1 hour expiry
            "nonce": hex::encode(random::secure_random_bytes::<16>()?)
        });
        
        let token_bytes = token_data.to_string().into_bytes();
        let signature = self.service_keypair.sign(&token_bytes)?;
        
        // Base64 encode token and signature
        let token_b64 = base64::encode(&token_bytes);
        let sig_b64 = base64::encode(signature.as_bytes());
        
        let auth_token = format!("{}.{}", token_b64, sig_b64);
        
        // Cache token
        self.token_cache.insert(
            target_service.to_string(),
            (auth_token.clone(), Instant::now() + Duration::from_secs(3600))
        );
        
        Ok(auth_token)
    }
    
    fn verify_auth_token(&self, token: &str, sender_service: &str) -> Result<bool> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Ok(false);
        }
        
        let token_bytes = base64::decode(parts[0])?;
        let signature_bytes = base64::decode(parts[1])?;
        
        // Get sender's public key
        let sender_pubkey = self.trusted_services.get(sender_service)
            .ok_or_else(|| anyhow::anyhow!("Untrusted service: {}", sender_service))?;
        
        // Verify signature
        let sender_keypair = KeyPair::from_public_key(PublicKey::from_bytes(sender_pubkey)?);
        let signature = Signature::from_bytes(&signature_bytes)?;
        let is_valid = sender_keypair.verify(&signature, &token_bytes)?;
        
        if !is_valid {
            return Ok(false);
        }
        
        // Parse and validate token claims
        let token_data: serde_json::Value = serde_json::from_slice(&token_bytes)?;
        let exp = token_data["exp"].as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid token format"))?;
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        Ok(current_time < exp)
    }
}

async fn microservices_integration() -> Result<()> {
    // Service A
    let mut service_a = ServiceAuthenticator::new("service-a")?;
    let service_a_pubkey = service_a.service_keypair.public_key().as_bytes().try_into()?;
    
    // Service B
    let mut service_b = ServiceAuthenticator::new("service-b")?;
    let service_b_pubkey = service_b.service_keypair.public_key().as_bytes().try_into()?;
    
    // Register mutual trust
    service_a.register_trusted_service("service-b", &service_b_pubkey);
    service_b.register_trusted_service("service-a", &service_a_pubkey);
    
    // Service A authenticates to Service B
    let auth_token = service_a.generate_auth_token("service-b")?;
    let is_valid = service_b.verify_auth_token(&auth_token, "service-a")?;
    
    println!("Service authentication: {}", is_valid);
    
    Ok(())
}
```

## Performance Optimization

### Crypto Operation Caching

```rust
use lib_crypto::*;
use std::collections::LRU; // Hypothetical LRU cache

struct CryptoCache {
    signature_cache: LRU<([u8; 32], [u8; 64]), bool>, // (message_hash, signature) -> valid
    hash_cache: LRU<Vec<u8>, [u8; 32]>, // data -> hash
    keypair_cache: LRU<[u8; 32], KeyPair>, // seed -> keypair
}

impl CryptoCache {
    fn new() -> Self {
        Self {
            signature_cache: LRU::new(1000),
            hash_cache: LRU::new(5000),
            keypair_cache: LRU::new(100),
        }
    }
    
    fn cached_verify(&mut self, signature: &[u8; 64], message: &[u8], pubkey: &[u8; 32]) -> Result<bool> {
        let message_hash = self.cached_hash(message)?;
        let cache_key = (message_hash, *signature);
        
        if let Some(&cached_result) = self.signature_cache.get(&cache_key) {
            return Ok(cached_result);
        }
        
        // Perform actual verification
        let keypair = KeyPair::from_public_key(PublicKey::from_bytes(pubkey)?);
        let sig = Signature::from_bytes(signature)?;
        let result = keypair.verify(&sig, message)?;
        
        // Cache result
        self.signature_cache.insert(cache_key, result);
        
        Ok(result)
    }
    
    fn cached_hash(&mut self, data: &[u8]) -> Result<[u8; 32]> {
        if let Some(&cached_hash) = self.hash_cache.get(data) {
            return Ok(cached_hash);
        }
        
        let hash = hashing::blake3_hash(data)?;
        self.hash_cache.insert(data.to_vec(), hash);
        
        Ok(hash)
    }
}
```

### Batch Operations

```rust
use lib_crypto::*;
use rayon::prelude::*;

struct BatchCryptoProcessor {
    thread_pool: rayon::ThreadPool,
}

impl BatchCryptoProcessor {
    fn new() -> Self {
        Self {
            thread_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .unwrap(),
        }
    }
    
    fn batch_verify_signatures(&self, jobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> Vec<Result<bool>> {
        // Parallel signature verification
        jobs.par_iter()
            .map(|(signature, message, pubkey)| {
                let keypair = KeyPair::from_public_key(PublicKey::from_bytes(pubkey)?)?;
                let sig = Signature::from_bytes(signature)?;
                keypair.verify(&sig, message)
            })
            .collect()
    }
    
    fn batch_hash(&self, data_chunks: Vec<Vec<u8>>) -> Vec<[u8; 32]> {
        data_chunks.par_iter()
            .map(|data| hashing::blake3_hash(data).unwrap())
            .collect()
    }
    
    fn batch_encrypt(&self, plaintexts: Vec<Vec<u8>>, keypair: &KeyPair) -> Vec<Result<Vec<u8>>> {
        plaintexts.par_iter()
            .enumerate()
            .map(|(i, plaintext)| {
                let metadata = format!("batch_item_{}", i);
                keypair.encrypt(plaintext, metadata.as_bytes())
            })
            .collect()
    }
}

fn performance_optimization() -> Result<()> {
    let processor = BatchCryptoProcessor::new();
    
    // Prepare batch operations
    let keypair = KeyPair::generate()?;
    let messages: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    
    // Batch signature verification
    let signatures: Result<Vec<_>, _> = messages.iter()
        .map(|msg| keypair.sign(msg).map(|sig| sig.as_bytes().to_vec()))
        .collect();
    let signatures = signatures?;
    
    let verification_jobs: Vec<_> = signatures.iter()
        .zip(messages.iter())
        .map(|(sig, msg)| (sig.clone(), msg.clone(), keypair.public_key().as_bytes().to_vec()))
        .collect();
    
    let start = std::time::Instant::now();
    let results = processor.batch_verify_signatures(verification_jobs);
    let batch_time = start.elapsed();
    
    let valid_count = results.iter().filter(|r| r.as_ref().unwrap_or(&false)).count();
    println!("Batch verified {}/{} signatures in {:?}", valid_count, results.len(), batch_time);
    
    // Batch encryption
    let start = std::time::Instant::now();
    let encrypted_messages = processor.batch_encrypt(messages, &keypair);
    let encrypt_time = start.elapsed();
    
    let success_count = encrypted_messages.iter().filter(|r| r.is_ok()).count();
    println!("Batch encrypted {}/{} messages in {:?}", success_count, encrypted_messages.len(), encrypt_time);
    
    Ok(())
}
```

## Testing Integration

### Integration Test Framework

```rust
use lib_crypto::*;

struct CryptoIntegrationTest {
    test_keypairs: Vec<KeyPair>,
    test_data: Vec<Vec<u8>>,
}

impl CryptoIntegrationTest {
    fn new() -> Result<Self> {
        let keypairs = (0..10)
            .map(|_| KeyPair::generate())
            .collect::<Result<Vec<_>, _>>()?;
        
        let test_data = vec![
            b"Short message".to_vec(),
            vec![0u8; 1024], // 1KB
            vec![0u8; 1024 * 1024], // 1MB
            b"Unicode test: 💻".to_vec(),
            Vec::new(), // Empty
        ];
        
        Ok(Self {
            test_keypairs: keypairs,
            test_data,
        })
    }
    
    fn test_end_to_end_encryption(&self) -> Result<()> {
        for (i, keypair) in self.test_keypairs.iter().enumerate() {
            for (j, data) in self.test_data.iter().enumerate() {
                let metadata = format!("test_{}_{}", i, j);
                
                // Encrypt
                let encrypted = keypair.encrypt(data, metadata.as_bytes())?;
                
                // Decrypt
                let decrypted = keypair.decrypt(&encrypted, metadata.as_bytes())?;
                
                // Verify
                if data != &decrypted {
                    return Err(anyhow::anyhow!("E2E test failed: keypair {}, data {}", i, j));
                }
            }
        }
        
        println!(" End-to-end encryption tests passed");
        Ok(())
    }
    
    fn test_signature_verification(&self) -> Result<()> {
        for (i, keypair) in self.test_keypairs.iter().enumerate() {
            for (j, data) in self.test_data.iter().enumerate() {
                if data.is_empty() { continue; } // Skip empty messages
                
                // Sign
                let signature = keypair.sign(data)?;
                
                // Verify with correct key
                if !keypair.verify(&signature, data)? {
                    return Err(anyhow::anyhow!("Signature verification failed: keypair {}, data {}", i, j));
                }
                
                // Verify with wrong key (should fail)
                if let Some(wrong_keypair) = self.test_keypairs.get((i + 1) % self.test_keypairs.len()) {
                    if wrong_keypair.verify(&signature, data).unwrap_or(false) {
                        return Err(anyhow::anyhow!("Wrong key verified signature: keypair {}, data {}", i, j));
                    }
                }
            }
        }
        
        println!(" Signature verification tests passed");
        Ok(())
    }
    
    fn test_cross_compatibility(&self) -> Result<()> {
        // Test that different instances can interoperate
        let alice_keypair = &self.test_keypairs[0];
        let bob_keypair = &self.test_keypairs[1];
        
        let message = b"Cross-compatibility test message";
        
        // Alice encrypts for Alice (self)
        let alice_encrypted = alice_keypair.encrypt(message, b"alice_to_alice")?;
        let alice_decrypted = alice_keypair.decrypt(&alice_encrypted, b"alice_to_alice")?;
        assert_eq!(message, &alice_decrypted[..]);
        
        // Alice signs, Bob verifies (with Alice's public key)
        let alice_signature = alice_keypair.sign(message)?;
        let alice_pubkey = alice_keypair.public_key();
        let alice_keypair_from_pubkey = KeyPair::from_public_key(alice_pubkey);
        let bob_verifies_alice = alice_keypair_from_pubkey.verify(&alice_signature, message)?;
        assert!(bob_verifies_alice);
        
        println!(" Cross-compatibility tests passed");
        Ok(())
    }
    
    fn run_all_tests(&self) -> Result<()> {
        println!("Running crypto integration tests...");
        
        self.test_end_to_end_encryption()?;
        self.test_signature_verification()?;
        self.test_cross_compatibility()?;
        
        println!(" All integration tests passed!");
        Ok(())
    }
}

fn integration_testing() -> Result<()> {
    let test_suite = CryptoIntegrationTest::new()?;
    test_suite.run_all_tests()?;
    Ok(())
}
```

This integration guide provides comprehensive examples for integrating lib-crypto into various application architectures within the SOVEREIGN_NET ecosystem, covering web applications, databases, blockchain systems, microservices, and performance optimization strategies.
>>>>>>> c4b7181335bd61771d1d7f3e410fb0b739d7476d
