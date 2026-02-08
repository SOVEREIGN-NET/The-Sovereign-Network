# Random Module

Cryptographically secure random number generation using system entropy sources. Provides secure randomness for key generation, nonces, salts, and other cryptographic operations essential to SOVEREIGN_NET security.

## Overview

- **Secure Sources**: System entropy pools (OS-provided randomness)
- **Thread Safety**: Safe for concurrent use across multiple threads
- **Zero-Copy**: Efficient memory handling for large random data
- **Failure Handling**: Robust error handling for entropy exhaustion

## Core Functionality

### Basic Random Generation

```rust
use lib_crypto::random::{
    secure_random_bytes, secure_random_u32, secure_random_u64,
    fill_random, SecureRng
};

fn basic_randomness() -> Result<()> {
    // Generate random byte arrays
    let random_32 = secure_random_bytes::<32>()?;
    let random_64 = secure_random_bytes::<64>()?;
    println!("Generated 32 bytes: {:?}", hex::encode(random_32));
    
    // Generate random integers
    let rand_u32 = secure_random_u32()?;
    let rand_u64 = secure_random_u64()?;
    println!("Random u32: {}, u64: {}", rand_u32, rand_u64);
    
    // Fill existing buffer
    let mut buffer = [0u8; 1024];
    fill_random(&mut buffer)?;
    println!("Filled {} bytes with randomness", buffer.len());
    
    Ok(())
}
```

### Custom RNG Usage

```rust
use lib_crypto::random::SecureRng;
use rand::RngCore;

fn custom_rng_usage() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Generate various random values
    let random_byte = rng.next_u32() as u8;
    let random_bool = rng.next_u32() % 2 == 0;
    let random_range = (rng.next_u32() % 100) + 1; // 1-100
    
    // Fill arrays
    let mut key_material = [0u8; 32];
    rng.fill_bytes(&mut key_material);
    
    println!("Generated random: byte={}, bool={}, range={}", 
             random_byte, random_bool, random_range);
    
    Ok(())
}
```

## Cryptographic Applications

### Key Generation

```rust
use lib_crypto::{
    random::secure_random_bytes,
    KeyPair,
    symmetric::generate_chacha20_key
};

fn cryptographic_key_generation() -> Result<()> {
    // Generate keys for different algorithms
    
    // Post-quantum keypair (random, production-safe)
    //
    // NOTE: `KeyPair::from_seed()` is legacy and does not produce deterministic PQ keys.
    // Use identity-layer derivation (`lib-identity-core`) when you need deterministic identity anchors.
    let keypair = KeyPair::generate()?;
    
    // ChaCha20 key (32 bytes)
    let chacha_key = generate_chacha20_key();
    
    // HMAC key (recommended: >= 32 bytes)
    let hmac_key = secure_random_bytes::<64>()?;
    
    // Salt for key derivation (16-32 bytes)
    let kdf_salt = secure_random_bytes::<32>()?;
    
    println!("Generated all cryptographic key material securely");
    Ok(())
}
```

### Nonce Generation

```rust
use lib_crypto::random::secure_random_bytes;

fn nonce_generation() -> Result<()> {
    // ChaCha20-Poly1305 nonce (12 bytes)
    let chacha_nonce = secure_random_bytes::<12>()?;
    
    // AES-GCM nonce (12 bytes recommended)
    let aes_gcm_nonce = secure_random_bytes::<12>()?;
    
    // XChaCha20 nonce (24 bytes)
    let xchacha_nonce = secure_random_bytes::<24>()?;
    
    // Custom protocol nonce
    let protocol_nonce = secure_random_bytes::<16>()?;
    
    println!("Generated all nonces: ChaCha20={}, AES-GCM={}, XChaCha20={}, Custom={}", 
             hex::encode(chacha_nonce),
             hex::encode(aes_gcm_nonce), 
             hex::encode(xchacha_nonce),
             hex::encode(protocol_nonce));
    
    Ok(())
}
```

### Salt Generation

```rust
use lib_crypto::{
    random::secure_random_bytes,
    hashing::{blake3_derive_key, argon2_hash}
};

fn salt_generation() -> Result<()> {
    // Password hashing salt
    let password_salt = secure_random_bytes::<32>()?;
    let password = b"user_password";
    let hash = argon2_hash(password, &password_salt)?;
    
    // Key derivation salt
    let kdf_salt = secure_random_bytes::<32>()?;
    let master_key = b"master-key-material";
    let derived_key = blake3_derive_key(master_key, &kdf_salt);
    
    // Protocol-specific salt
    let protocol_salt = secure_random_bytes::<16>()?;
    
    println!("Generated salts for secure operations");
    Ok(())
}
```

## Advanced Random Operations

### Secure Random Numbers in Range

```rust
use lib_crypto::random::SecureRng;
use rand::{Rng, distributions::Uniform};

fn secure_random_ranges() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Uniform distribution (avoids modulo bias)
    let uniform_100 = Uniform::from(1..=100);
    let fair_roll = rng.sample(uniform_100);
    
    // Random index selection
    let array_len = 1000;
    let random_index = rng.gen_range(0..array_len);
    
    // Probability-based selection
    let probability = rng.gen::<f64>(); // 0.0 to 1.0
    let happens = probability < 0.1; // 10% chance
    
    // Random choice from options
    let options = ["alice", "bob", "charlie", "diana"];
    let random_choice = options[rng.gen_range(0..options.len())];
    
    println!("Random selections: roll={}, index={}, choice={}", 
             fair_roll, random_index, random_choice);
    
    Ok(())
}
```

### Shuffling and Sampling

```rust
use lib_crypto::random::SecureRng;
use rand::seq::SliceRandom;

fn secure_shuffling() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Shuffle array in-place
    let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    data.shuffle(&mut rng);
    println!("Shuffled: {:?}", data);
    
    // Random sampling
    let sample: Vec<_> = data.choose_multiple(&mut rng, 3).cloned().collect();
    println!("Random sample: {:?}", sample);
    
    // Weighted sampling (for different probabilities)
    use rand::distributions::WeightedIndex;
    let items = ["common", "uncommon", "rare", "epic"];
    let weights = [70, 20, 8, 2]; // Percentages
    let dist = WeightedIndex::new(&weights)?;
    let selected = items[dist.sample(&mut rng)];
    
    println!("Weighted selection: {}", selected);
    Ok(())
}
```

### Random Data Structures

```rust
use lib_crypto::random::{SecureRng, secure_random_bytes};
use std::collections::HashMap;

fn random_data_structures() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Random identifier generation
    let session_id = hex::encode(secure_random_bytes::<16>()?);
    let transaction_id = hex::encode(secure_random_bytes::<32>()?);
    
    // Random network peer selection
    let peer_ids = vec!["peer1", "peer2", "peer3", "peer4", "peer5"];
    let selected_peers: Vec<_> = peer_ids
        .choose_multiple(&mut rng, 3)
        .cloned()
        .collect();
    
    // Random delay for timing attacks mitigation
    let base_delay_ms = 100;
    let jitter_ms = rng.gen_range(0..50); // 0-50ms jitter
    let total_delay = base_delay_ms + jitter_ms;
    
    // Random challenge generation
    let challenge = secure_random_bytes::<32>()?;
    
    println!("Generated: session={}, peers={:?}, delay={}ms, challenge={}", 
             session_id, selected_peers, total_delay, hex::encode(challenge));
    
    Ok(())
}
```

## Security Considerations

### Entropy Sources

```rust
use lib_crypto::random::{SecureRng, check_entropy_available};

fn entropy_management() -> Result<()> {
    // Check system entropy availability
    if !check_entropy_available()? {
        println!("Warning: Low system entropy detected");
        // Consider waiting or using additional entropy sources
    }
    
    // Initialize RNG with entropy check
    let mut rng = SecureRng::new_with_entropy_check()?;
    
    // For high-security applications, consider entropy accumulation
    let mut high_entropy_seed = Vec::new();
    for _ in 0..10 {
        let entropy_chunk = secure_random_bytes::<32>()?;
        high_entropy_seed.extend_from_slice(&entropy_chunk);
        
        // Add timing jitter (microsecond-level timing differences)
        std::thread::sleep(std::time::Duration::from_micros(
            (rng.gen::<u32>() % 1000) as u64
        ));
    }
    
    println!("Accumulated {} bytes of high-entropy data", high_entropy_seed.len());
    Ok(())
}
```

### Secure Memory Handling

```rust
use lib_crypto::random::secure_random_bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SecureRandomData {
    data: [u8; 32],
}

fn secure_random_memory() -> Result<()> {
    // Generate random data in secure container
    let random_data = SecureRandomData {
        data: secure_random_bytes::<32>()?,
    };
    
    // Use the random data
    println!("Generated secure random data");
    
    // Data is automatically zeroed when dropped
    drop(random_data);
    
    // Manual zeroing for sensitive arrays
    let mut sensitive_buffer = secure_random_bytes::<64>()?;
    
    // ... use sensitive_buffer ...
    
    // Explicitly zero before it goes out of scope
    sensitive_buffer.zeroize();
    
    Ok(())
}
```

### Timing Attack Resistance

```rust
use lib_crypto::random::{SecureRng, secure_random_bytes};

fn timing_attack_mitigation() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Add random delays to mask timing patterns
    fn random_delay(rng: &mut SecureRng) {
        let delay_us = rng.gen_range(100..1000); // 0.1-1ms
        std::thread::sleep(std::time::Duration::from_micros(delay_us));
    }
    
    // Cryptographic operation with timing masking
    let key = secure_random_bytes::<32>()?;
    random_delay(&mut rng);
    
    let nonce = secure_random_bytes::<12>()?;
    random_delay(&mut rng);
    
    // Actual cryptographic operation
    // ... perform encryption/signing ...
    random_delay(&mut rng);
    
    println!("Completed operation with timing protection");
    Ok(())
}
```

## Performance Optimization

### Batch Generation

```rust
use lib_crypto::random::{SecureRng, fill_random};

fn batch_random_generation() -> Result<()> {
    // Generate large amounts of randomness efficiently
    let mut large_buffer = vec![0u8; 1_000_000]; // 1MB
    fill_random(&mut large_buffer)?;
    
    // Process in chunks
    for (i, chunk) in large_buffer.chunks(1024).enumerate() {
        // Use 1KB chunks of random data
        println!("Processing chunk {} with {} random bytes", i, chunk.len());
    }
    
    // Pre-generate nonces for batch operations
    let mut nonces = Vec::new();
    for _ in 0..1000 {
        nonces.push(secure_random_bytes::<12>()?);
    }
    
    println!("Pre-generated {} nonces for batch processing", nonces.len());
    Ok(())
}
```

### RNG Reuse

```rust
use lib_crypto::random::SecureRng;
use std::sync::{Arc, Mutex};

fn rng_reuse_patterns() -> Result<()> {
    // Thread-local RNG for single-threaded contexts
    thread_local! {
        static THREAD_RNG: RefCell<SecureRng> = 
            RefCell::new(SecureRng::new().unwrap());
    }
    
    THREAD_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let random_data = rng.next_u64();
        println!("Thread-local random: {}", random_data);
    });
    
    // Shared RNG for multi-threaded contexts (with proper locking)
    let shared_rng = Arc::new(Mutex::new(SecureRng::new()?));
    
    let rng_clone = shared_rng.clone();
    let handle = std::thread::spawn(move || {
        let mut rng = rng_clone.lock().unwrap();
        rng.next_u32()
    });
    
    let result = handle.join().unwrap();
    println!("Shared RNG result: {}", result);
    
    Ok(())
}
```

## Integration Examples

### Network Security

```rust
use lib_crypto::random::{secure_random_bytes, SecureRng};

fn network_security_randomness() -> Result<()> {
    // Session token generation
    let session_token = hex::encode(secure_random_bytes::<32>()?);
    
    // Challenge-response authentication
    let challenge = secure_random_bytes::<32>()?;
    
    // Connection jitter to prevent traffic analysis
    let mut rng = SecureRng::new()?;
    let connection_delay = rng.gen_range(50..500); // 50-500ms jitter
    
    // Random padding for constant-time operations
    let padding_size = rng.gen_range(16..64);
    let padding = secure_random_bytes::<64>()?;
    let actual_padding = &padding[..padding_size];
    
    println!("Network security: token={}, challenge={}, delay={}ms, padding={}b", 
             &session_token[..16], hex::encode(&challenge[..8]), 
             connection_delay, padding_size);
    
    Ok(())
}
```

### Blockchain Applications

```rust
use lib_crypto::{
    random::{secure_random_bytes, SecureRng},
    KeyPair
};

fn blockchain_randomness() -> Result<()> {
    // Transaction nonce (prevents replay attacks)
    let tx_nonce = secure_random_bytes::<32>()?;
    
    // Block mining nonce
    let mut rng = SecureRng::new()?;
    let mining_nonce = rng.next_u64();
    
    // Merkle tree salt
    let merkle_salt = secure_random_bytes::<32>()?;
    
    // Validator selection randomness
    let validator_seed = secure_random_bytes::<32>()?;
    
    // Zero-knowledge proof randomness
    let zk_randomness = secure_random_bytes::<32>()?;
    
    println!("Blockchain randomness: tx={}, mining={}, merkle={}, validator={}, zk={}", 
             hex::encode(&tx_nonce[..8]),
             mining_nonce,
             hex::encode(&merkle_salt[..8]),
             hex::encode(&validator_seed[..8]),
             hex::encode(&zk_randomness[..8]));
    
    Ok(())
}
```

### File System Security

```rust
use lib_crypto::random::{secure_random_bytes, SecureRng};
use std::path::PathBuf;

fn filesystem_security() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Temporary file naming (prevents predictable names)
    let temp_suffix = hex::encode(secure_random_bytes::<8>()?);
    let temp_file = format!("temp_{}.dat", temp_suffix);
    
    // Directory traversal prevention
    let safe_filename = format!("file_{}.enc", hex::encode(secure_random_bytes::<16>()?));
    
    // Backup verification code
    let backup_code = secure_random_bytes::<16>()?;
    let backup_code_str = base64::encode(backup_code);
    
    // Secure deletion overwrite pattern
    let mut secure_overwrite = vec![0u8; 4096];
    for pass in 0..3 {
        rng.fill_bytes(&mut secure_overwrite);
        println!("Secure deletion pass {}: pattern generated", pass + 1);
    }
    
    println!("File security: temp={}, safe={}, backup={}", 
             temp_file, safe_filename, backup_code_str);
    
    Ok(())
}
```

## Testing and Validation

### Randomness Quality Tests

```rust
use lib_crypto::random::{SecureRng, secure_random_bytes};

fn randomness_quality_tests() -> Result<()> {
    let mut rng = SecureRng::new()?;
    
    // Basic distribution test
    let mut counts = [0u32; 256];
    for _ in 0..10000 {
        let byte = (rng.next_u32() % 256) as u8;
        counts[byte as usize] += 1;
    }
    
    // Check for obvious bias (should be roughly uniform)
    let avg_count = 10000 / 256;
    let max_deviation = counts.iter().map(|&c| (c as i32 - avg_count as i32).abs()).max().unwrap();
    println!("Max deviation from uniform: {} (should be < {})", max_deviation, avg_count / 4);
    
    // Entropy estimation (simple)
    let sample = secure_random_bytes::<1000>()?;
    let mut byte_counts = [0u32; 256];
    for &byte in &sample {
        byte_counts[byte as usize] += 1;
    }
    
    let entropy = byte_counts.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / 1000.0;
            -p * p.log2()
        })
        .sum::<f64>();
    
    println!("Estimated entropy: {:.2} bits (max: 8.0)", entropy);
    
    Ok(())
}
```

## Error Handling

```rust
use lib_crypto::random::{SecureRng, RandomError};

fn random_error_handling() -> Result<()> {
    // Handle RNG initialization failure
    match SecureRng::new() {
        Ok(mut rng) => {
            let random_value = rng.next_u64();
            println!("RNG initialized: {}", random_value);
        },
        Err(RandomError::EntropyUnavailable) => {
            println!("System entropy exhausted - wait or use alternative source");
            return Err(anyhow::anyhow!("No entropy available"));
        },
        Err(RandomError::SystemError(e)) => {
            println!("System RNG error: {}", e);
            return Err(anyhow::anyhow!("System RNG failed: {}", e));
        },
        Err(e) => {
            println!("Other RNG error: {:?}", e);
            return Err(anyhow::anyhow!("RNG error: {:?}", e));
        }
    }
    
    // Graceful degradation for low-entropy situations
    if !check_entropy_sufficient()? {
        println!("Warning: Using fallback randomness source");
        // Implement fallback strategy
    }
    
    Ok(())
}

fn check_entropy_sufficient() -> Result<bool> {
    // Implementation would check system entropy levels
    Ok(true)
}
```

## Best Practices

### 1. Always Use Cryptographically Secure Sources

```rust
use lib_crypto::random::{SecureRng, secure_random_bytes};

fn secure_randomness_practices() -> Result<()> {
    // Use cryptographically secure RNG
    let secure_key = secure_random_bytes::<32>()?;
    
    // Never use predictable sources for cryptography
    // let weak_random = std::time::SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u32;
    // let weak_key = weak_random.to_be_bytes(); // INSECURE!
    
    // Use proper RNG for all cryptographic needs
    let mut rng = SecureRng::new()?;
    let nonce = rng.next_u64().to_be_bytes();
    
    println!("Using secure randomness for all cryptographic operations");
    Ok(())
}
```

### 2. Handle Entropy Properly

```rust
use lib_crypto::random::{SecureRng, secure_random_bytes, check_entropy_available};

fn entropy_best_practices() -> Result<()> {
    // Check entropy before critical operations
    if !check_entropy_available()? {
        // Wait for entropy or fail safely
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    // Initialize RNG once, reuse appropriately
    let mut rng = SecureRng::new()?;
    
    // For very sensitive operations, gather extra entropy
    let mut high_entropy_material = Vec::new();
    for _ in 0..5 {
        high_entropy_material.extend_from_slice(&secure_random_bytes::<32>()?);
    }
    
    println!("Entropy management implemented correctly");
    Ok(())
}
```

### 3. Memory Security

```rust
use lib_crypto::random::secure_random_bytes;
use zeroize::Zeroize;

fn memory_security_practices() -> Result<()> {
    // Zero sensitive random data after use
    let mut random_seed = secure_random_bytes::<32>()?;
    
    // ... use random_seed for key derivation ...
    
    // Clear from memory
    random_seed.zeroize();
    
    // Use stack allocation for temporary random data when possible
    {
        let temp_random = secure_random_bytes::<16>()?;
        // ... use temp_random ...
        // Automatically cleared when leaving scope
    }
    
    println!("Memory security practices implemented");
    Ok(())
}
```

The random module provides the cryptographic foundation for all random operations in SOVEREIGN_NET, ensuring security through proper entropy management and secure memory handling.
