# Symmetric Module

Implementation of symmetric encryption algorithms: ChaCha20-Poly1305 for AEAD encryption and hybrid post-quantum encryption schemes. Provides fast, secure symmetric cryptography for bulk data protection.

## Overview

- **ChaCha20-Poly1305**: Authenticated encryption with associated data (AEAD)
- **Hybrid Encryption**: Post-quantum KEM + symmetric encryption
- **Performance**: Optimized for high-throughput applications
- **Security**: Authenticated encryption prevents tampering

## ChaCha20-Poly1305 AEAD

### Algorithm Overview
- **Cipher**: ChaCha20 stream cipher for encryption
- **Authenticator**: Poly1305 MAC for authentication
- **AEAD**: Authenticated Encryption with Associated Data
- **Performance**: Fast on all platforms, especially mobile/IoT

### Basic Usage

```rust
use lib_crypto::symmetric::{
    encrypt_chacha20poly1305, decrypt_chacha20poly1305,
    generate_chacha20_key, generate_nonce
};

fn chacha20_basic() -> Result<()> {
    let key = generate_chacha20_key();
    let nonce = generate_nonce();
    let plaintext = b"Secret message to encrypt";
    let associated_data = b"public metadata";
    
    // Encrypt
    let ciphertext = encrypt_chacha20poly1305(
        plaintext,
        associated_data, 
        &key,
        &nonce
    )?;
    
    // Decrypt
    let decrypted = decrypt_chacha20poly1305(
        &ciphertext,
        associated_data,
        &key, 
        &nonce
    )?;
    
    assert_eq!(plaintext, &decrypted[..]);
    println!("ChaCha20-Poly1305 encryption successful");
    Ok(())
}
```

## Hybrid Encryption

### KeyPair Integration

```rust
use lib_crypto::{KeyPair, symmetric::HybridEncryption};

fn hybrid_encryption() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let plaintext = b"Large amount of data to encrypt securely";
    let metadata = b"file version info";
    
    // Hybrid: Kyber1024 + ChaCha20-Poly1305
    let ciphertext = keypair.encrypt(plaintext, metadata)?;
    
    // Structure: [Kyber Ciphertext][Nonce][Encrypted Data]
    println!("Hybrid ciphertext size: {} bytes", ciphertext.len());
    
    // Decrypt
    let decrypted = keypair.decrypt(&ciphertext, metadata)?;
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}
```

### Manual Hybrid Construction

```rust
use lib_crypto::{
    KeyPair,
    symmetric::{encrypt_chacha20poly1305, decrypt_chacha20poly1305, generate_nonce}
};
use chacha20poly1305::{Key, KeyInit, ChaCha20Poly1305};

fn manual_hybrid() -> Result<()> {
    let keypair = KeyPair::generate()?;
    let plaintext = b"Data for manual hybrid encryption";
    
    // Step 1: Generate shared secret via KEM
    let encapsulation = keypair.encapsulate()?;
    let shared_secret = &encapsulation.shared_secret;
    
    // Step 2: Encrypt with symmetric key
    let nonce = generate_nonce();
    let ciphertext = encrypt_chacha20poly1305(
        plaintext,
        b"", // no additional associated data
        shared_secret,
        &nonce
    )?;
    
    // Combine KEM ciphertext + nonce + symmetric ciphertext
    let mut combined = Vec::new();
    combined.extend_from_slice(&encapsulation.ciphertext);
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);
    
    // Decrypt: Extract components and reverse process
    let kem_ct_size = encapsulation.ciphertext.len();
    let kem_ciphertext = &combined[..kem_ct_size];
    let nonce_extracted = &combined[kem_ct_size..kem_ct_size + 12];
    let sym_ciphertext = &combined[kem_ct_size + 12..];
    
    // Recover shared secret
    let recovered_secret = keypair.decapsulate(&Encapsulation {
        ciphertext: kem_ciphertext.to_vec(),
        shared_secret: [0u8; 32], // Will be overwritten
        kdf_info: encapsulation.kdf_info.clone(),
    })?;
    
    // Decrypt symmetric part
    let decrypted = decrypt_chacha20poly1305(
        sym_ciphertext,
        b"",
        &recovered_secret,
        nonce_extracted.try_into().unwrap()
    )?;
    
    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}
```

## Performance Optimization

### Streaming Encryption

```rust
use lib_crypto::symmetric::ChaCha20Encryptor;

fn streaming_encryption() -> Result<()> {
    let key = generate_chacha20_key();
    let nonce = generate_nonce();
    
    let mut encryptor = ChaCha20Encryptor::new(&key, &nonce);
    
    // Encrypt large data in chunks
    let large_data = vec![0u8; 10_000_000]; // 10MB
    let mut encrypted_chunks = Vec::new();
    
    for chunk in large_data.chunks(8192) {
        let encrypted_chunk = encryptor.encrypt_chunk(chunk)?;
        encrypted_chunks.push(encrypted_chunk);
    }
    
    // Authentication tag at end
    let auth_tag = encryptor.finalize(b"associated_data")?;
    
    println!("Streamed {} MB of data", large_data.len() / 1_000_000);
    Ok(())
}
```

### Parallel Processing

```rust
use lib_crypto::symmetric::*;
use rayon::prelude::*;

fn parallel_encryption() -> Result<()> {
    let key = generate_chacha20_key();
    
    // Multiple independent messages
    let messages: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("Message {}", i).into_bytes())
        .collect();
    
    // Encrypt in parallel (each needs unique nonce)
    let encrypted: Vec<_> = messages
        .par_iter()
        .enumerate()
        .map(|(i, msg)| {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[8..].copy_from_slice(&(i as u32).to_le_bytes());
            
            encrypt_chacha20poly1305(msg, b"", &key, &nonce_bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    
    println!("Encrypted {} messages in parallel", messages.len());
    Ok(())
}
```

## Security Features

### Associated Data Protection

```rust
use lib_crypto::symmetric::*;

fn associated_data_example() -> Result<()> {
    let key = generate_chacha20_key();
    let nonce = generate_nonce();
    
    let secret_payload = b"Secret document content";
    let public_metadata = b"filename=document.txt,version=1.2";
    
    // Encrypt payload, authenticate metadata
    let ciphertext = encrypt_chacha20poly1305(
        secret_payload,
        public_metadata, // Authenticated but not encrypted
        &key,
        &nonce
    )?;
    
    // Correct decryption with matching metadata
    let decrypted = decrypt_chacha20poly1305(
        &ciphertext,
        public_metadata,
        &key,
        &nonce
    )?;
    assert_eq!(secret_payload, &decrypted[..]);
    
    // Tampered metadata causes decryption failure
    let tampered_metadata = b"filename=malware.exe,version=1.2";
    let result = decrypt_chacha20poly1305(
        &ciphertext,
        tampered_metadata,
        &key,
        &nonce
    );
    assert!(result.is_err()); // Authentication failure
    
    Ok(())
}
```

### Nonce Management

```rust
use lib_crypto::symmetric::*;

fn nonce_management() -> Result<()> {
    let key = generate_chacha20_key();
    
    // Never reuse nonces with same key
    let nonce = generate_nonce();
    let msg1 = b"First message";
    let msg2 = b"Second message";
    
    let _ct1 = encrypt_chacha20poly1305(msg1, b"", &key, &nonce)?;
    // let _ct2 = encrypt_chacha20poly1305(msg2, b"", &key, &nonce)?; // INSECURE!
    
    // Use different nonce for each encryption
    let nonce2 = generate_nonce();
    let _ct2 = encrypt_chacha20poly1305(msg2, b"", &key, &nonce2)?;
    
    // Or use counter-based nonces (be careful with concurrency)
    for i in 0..10 {
        let mut counter_nonce = [0u8; 12];
        counter_nonce[8..].copy_from_slice(&(i as u32).to_le_bytes());
        
        let message = format!("Message {}", i);
        let _ct = encrypt_chacha20poly1305(
            message.as_bytes(), 
            b"", 
            &key, 
            &counter_nonce
        )?;
    }
    
    Ok(())
}
```

## Integration Examples

### File Encryption

```rust
use lib_crypto::{KeyPair, symmetric::*};
use std::fs;

fn file_encryption() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Read file content
    let file_content = b"File content to encrypt and store securely";
    let file_metadata = b"filename=secret.txt,size=42";
    
    // Encrypt file
    let encrypted_file = keypair.encrypt(file_content, file_metadata)?;
    
    // Store encrypted file (safe to write to disk)
    // fs::write("secret.enc", &encrypted_file)?;
    
    // Later: read and decrypt
    // let stored_data = fs::read("secret.enc")?;
    let decrypted_file = keypair.decrypt(&encrypted_file, file_metadata)?;
    
    assert_eq!(file_content, &decrypted_file[..]);
    println!("File encryption/decryption successful");
    Ok(())
}
```

### Network Communication

```rust
use lib_crypto::{KeyPair, symmetric::*};

fn secure_communication() -> Result<()> {
    // Establish shared key via key exchange
    let alice_keypair = KeyPair::generate()?;
    let bob_keypair = KeyPair::generate()?;
    
    // Alice generates shared secret for Bob
    let alice_to_bob = alice_keypair.encapsulate()?;
    
    // Alice encrypts message with shared secret
    let message = b"Confidential communication from Alice to Bob";
    let session_info = b"session_id=123,timestamp=1640995200";
    
    let encrypted_msg = encrypt_chacha20poly1305(
        message,
        session_info,
        &alice_to_bob.shared_secret,
        &generate_nonce()
    )?;
    
    // Send: [KEM Ciphertext][Nonce][Encrypted Message] 
    let mut transmission = Vec::new();
    transmission.extend_from_slice(&alice_to_bob.ciphertext);
    // ... add nonce and encrypted message ...
    
    println!("Secure communication established");
    Ok(())
}
```

### Database Encryption

```rust
use lib_crypto::{KeyPair, symmetric::*};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct EncryptedRecord {
    id: u32,
    encrypted_data: Vec<u8>,
    metadata: Vec<u8>,
}

fn database_encryption() -> Result<()> {
    let keypair = KeyPair::generate()?;
    
    // Sensitive record to store
    let sensitive_data = b"Social Security Number: 123-45-6789";
    let record_metadata = b"user_id=12345,table=users";
    
    // Encrypt for database storage
    let encrypted_data = keypair.encrypt(sensitive_data, record_metadata)?;
    
    let record = EncryptedRecord {
        id: 12345,
        encrypted_data,
        metadata: record_metadata.to_vec(),
    };
    
    // Store in database (encrypted_data is safe)
    let serialized = bincode::serialize(&record)?;
    
    // Later: retrieve and decrypt
    let restored: EncryptedRecord = bincode::deserialize(&serialized)?;
    let decrypted = keypair.decrypt(&restored.encrypted_data, &restored.metadata)?;
    
    assert_eq!(sensitive_data, &decrypted[..]);
    println!("Database record encrypted/decrypted successfully");
    Ok(())
}
```

## Error Handling

```rust
use lib_crypto::symmetric::*;
use anyhow::{Result, Context};

fn robust_symmetric_operations() -> Result<()> {
    let key = generate_chacha20_key();
    let nonce = generate_nonce();
    let data = b"Test data";
    
    // Handle encryption errors
    let ciphertext = encrypt_chacha20poly1305(data, b"", &key, &nonce)
        .context("Encryption failed")?;
    
    // Handle decryption errors (common with wrong key/nonce/data)
    match decrypt_chacha20poly1305(&ciphertext, b"", &key, &nonce) {
        Ok(plaintext) => println!("Decryption successful"),
        Err(e) => {
            // Could be:
            // - Wrong key
            // - Wrong nonce  
            // - Corrupted ciphertext
            // - Wrong associated data
            println!("Decryption failed: {}", e);
        }
    }
    
    // Validate key/nonce lengths
    let wrong_key = [0u8; 16]; // ChaCha20 needs 32 bytes
    let result = encrypt_chacha20poly1305(data, b"", &wrong_key, &nonce);
    assert!(result.is_err());
    
    Ok(())
}
```

## Best Practices

### 1. Key Management

```rust
use lib_crypto::symmetric::*;

fn key_management_practices() -> Result<()> {
    // Generate random keys
    let key = generate_chacha20_key();
    
    // Don't use predictable keys
    // let weak_key = [0u8; 32]; // All zeros
    // let weak_key = b"password".as_slice(); // Too short, predictable
    
    // Derive keys properly if needed
    use lib_crypto::hashing::blake3_derive_key;
    let master_key = b"high-entropy-master-key-32-bytes";
    let derived_key = blake3_derive_key(master_key, b"SYMMETRIC_KEY_V1");
    
    // Rotate keys periodically
    // Use separate keys for different purposes
    // Store keys securely (HSM, key management service)
    
    Ok(())
}
```

### 2. Nonce Practices

```rust
use lib_crypto::symmetric::*;

fn nonce_best_practices() -> Result<()> {
    let key = generate_chacha20_key();
    
    // Random nonces (if you can store them)
    let random_nonce = generate_nonce();
    
    // Counter nonces (if sequential and no concurrency)
    let mut counter = 0u64;
    let mut counter_nonce = [0u8; 12];
    counter_nonce[4..].copy_from_slice(&counter.to_le_bytes());
    counter += 1;
    
    // Timestamp + random (for distributed systems)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as u32;
    let mut time_nonce = [0u8; 12];
    time_nonce[0..4].copy_from_slice(&timestamp.to_be_bytes());
    // Fill rest with random bytes
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut time_nonce[4..]);
    
    println!("Nonce strategies implemented");
    Ok(())
}
```

### 3. Performance Guidelines

```rust
use lib_crypto::symmetric::*;

fn performance_guidelines() -> Result<()> {
    // For small data (< 1KB): direct encryption
    let small_data = b"Small message";
    let key = generate_chacha20_key();
    let nonce = generate_nonce();
    let _encrypted = encrypt_chacha20poly1305(small_data, b"", &key, &nonce)?;
    
    // For large data (> 1MB): consider streaming
    let large_data = vec![0u8; 10_000_000];
    // Use ChaCha20Encryptor for streaming interface
    
    // For very large data: chunk processing
    for chunk in large_data.chunks(1_048_576) { // 1MB chunks
        let chunk_nonce = generate_nonce();
        let _encrypted_chunk = encrypt_chacha20poly1305(chunk, b"", &key, &chunk_nonce)?;
    }
    
    println!("Performance optimizations applied");
    Ok(())
}
```

The symmetric module provides efficient, authenticated encryption suitable for protecting data at rest and in transit within the SOVEREIGN_NET ecosystem.
