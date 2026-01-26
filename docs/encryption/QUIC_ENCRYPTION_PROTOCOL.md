# QUIC Encryption Protocol Documentation

**Version:** 1.0
**Protocol:** ZHTP (Zero-trust Hierarchical Transport Protocol)
**Date:** 2025-12-23
**Status:** Production-Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Encryption Layers](#encryption-layers)
3. [Complete Handshake Flow](#complete-handshake-flow)
4. [Message Encryption/Decryption](#message-encryptiondecryption)
5. [Key Derivation](#key-derivation)
6. [Nonce Management](#nonce-management)
7. [Security Properties](#security-properties)
8. [Configuration](#configuration)
9. [Examples](#examples)

---

## Overview

ZHTP uses a **two-layer encryption model** for defense-in-depth security against both classical and quantum threats:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Message                          │
│                      (UTF-8 or Binary)                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────────┐
                    │  APPLICATION LAYER  │
                    │  ChaCha20Poly1305   │  Post-quantum confidentiality
                    │  + Kyber512 binding │  Cryptographic identity proof
                    └─────────────────────┘
                              ↓
                      ┌──────────────────┐
                      │  TRANSPORT LAYER │
                      │   TLS 1.3 (QUIC) │  Classical security + MitM protection
                      │  (Quinn Library) │  Connection-level authentication
                      └──────────────────┘
                              ↓
                      ┌──────────────────┐
                      │    UDP/IPv4      │  No encryption at network layer
                      │    over IP       │  (firewall traversal)
                      └──────────────────┘
```

**Key Insight:** Each layer serves a distinct security purpose:
- **Transport (TLS 1.3):** Protects against passive eavesdropping, MitM, classical cryptanalysis
- **Application (ChaCha20+Kyber):** Protects against quantum threats, binds identity to session

---

## Encryption Layers

### Layer 1: Transport Layer (TLS 1.3 via Quinn QUIC)

**Purpose:** Secure the QUIC connection itself

| Property | Value |
|----------|-------|
| **Algorithm** | TLS 1.3 (RFC 8446) |
| **Implementation** | Quinn QUIC library |
| **Key Exchange** | ECDHE (Elliptic Curve) |
| **Cipher Suite** | TLS_CHACHA20_POLY1305_SHA256 |
| **Handshake** | 1 RTT (0-RTT with resumption) |
| **Forward Secrecy** | Yes (ephemeral keys) |
| **PFS Duration** | Per connection (< 1 hour) |

**What it protects:**
- QUIC connection establishment
- QUIC header information (stream IDs, packet numbers)
- Provides baseline classical security

**What it doesn't protect:**
- Application layer messages (protected by Layer 2)
- Not quantum-resistant (mitigated by Layer 2)

**Handshake Flow (1-RTT):**

```
Client                                    Server
  |                                         |
  |-------- ClientHello + TLS 1.3 -------->|  (includes ephemeral ECDHE public key)
  |                                         |  (server selects cipher suite)
  |<------- ServerHello + Certificate ------|
  |         + ChangeCipherSpec             |  (server's ECDHE public key)
  |         + Finished                     |  (server computes session keys)
  |                                         |
  |         (client computes same keys)    |
  |<------- Server can now use keys -------|
  |                                         |
  |-------- Client Finished +App Data ---->|  (client now uses keys)
  |         (handshake complete)           |
  |
 TLS 1.3 is now ready for application data
```

### Layer 2: Application Layer (ChaCha20Poly1305 + Kyber512)

**Purpose:** Provide post-quantum confidentiality + cryptographic identity binding

| Property | Value |
|----------|-------|
| **Symmetric Cipher** | ChaCha20Poly1305 (AEAD) |
| **Key Exchange (PQC)** | Kyber512 (NIST FIPS 203) |
| **Authentication** | Dilithium-3 signatures (NIST FIPS 204) |
| **Key Derivation** | HKDF-SHA256 |
| **Nonce Size** | 96 bits (random per message) |
| **Handshake RTTs** | 2 RTTs total (1 for UHP, 1 for Kyber) |
| **Post-Quantum Secure** | Yes (Kyber + Dilithium) |

**What it protects:**
- Application layer messages (Mesh protocol messages)
- Provides quantum-resistant confidentiality
- Binds identity (Dilithium + NodeId) to session
- Prevents replay attacks (nonce + transcript validation)

**What it doesn't protect:**
- QUIC metadata (handled by TLS 1.3)
- Not concerned with classical cryptanalysis (TLS 1.3 handles that)

**Message Format:**

```
Plaintext Message
       ↓
ChaCha20(master_key, random_96bit_nonce) encrypt
       ↓
[12 bytes: nonce] [variable: ciphertext] [16 bytes: Poly1305 tag]
       ↓
Sent over TLS 1.3 encrypted QUIC stream
```

---

## Complete Handshake Flow

### Phase 1: UHP Authentication (Dilithium Signatures)

The **UHP (Unified Handshake Protocol)** authenticates both peers using Dilithium signatures.

**Timeline:**

```
Time    Client                            Server
 |
 0       ClientHello (sends)
         ├─ NodeId (Blake3 of DID+name)
         ├─ Dilithium public key (2432 bytes)
         ├─ Supported protocols/capabilities
         └─ Signature: sign(nonce_from_server)
                      ↓
                     TLS 1.3 encrypted QUIC stream
                      ↓
 1       ServerHello (receives & verifies)
         ├─ Verify ClientHello signature (Dilithium)
         ├─ Extract client's public key from announcement
         ├─ Send ServerHello
         │   ├─ NodeId (Blake3 of DID+name)
         │   ├─ Dilithium public key (2432 bytes)
         │   ├─ New nonce_for_client
         │   └─ Signature: sign(client_nonce)
         │
         ├─ Receive ClientFinish
         │   └─ Signature: sign(server_nonce)
         │
         ├─ Verify ClientFinish signature
         └─ Extract UHP session key (32 bytes)
                      ↓
 2       ClientFinish (sends & receives ServerHello)
         ├─ Sign server's nonce with Dilithium
         ├─ Send ClientFinish
         └─ Verify ServerHello signature
             └─ Extract UHP session key (same as server computed)
```

**Key Verification Steps:**

1. **ClientHello Signature Verification** (Server side)
   ```rust
   // Server receives ClientHello with signature
   client_public_key = extract_from(client_hello)
   is_valid = dilithium_verify(
       client_hello.signature,
       message = ClientHello contents,
       public_key = client_public_key
   )
   assert!(is_valid, "Client authentication failed");
   ```

2. **ServerHello Signature Verification** (Client side)
   ```rust
   // Client receives ServerHello with signature
   server_public_key = extract_from(server_hello)
   is_valid = dilithium_verify(
       server_hello.signature,
       message = ServerHello contents,
       public_key = server_public_key
   )
   assert!(is_valid, "Server authentication failed");
   ```

3. **ClientFinish Signature Verification** (Server side)
   ```rust
   // Server receives ClientFinish with signature
   is_valid = dilithium_verify(
       client_finish.signature,
       message = ClientFinish contents,
       public_key = client_public_key  // stored from ClientHello
   )
   assert!(is_valid, "ClientFinish authentication failed");
   ```

**Security Properties:**
- ✅ Mutual authentication (both peers verify each other)
- ✅ No pre-shared secrets (identity derives from Dilithium + NodeId)
- ✅ Classical security (Dilithium is lattice-based, hard for classical computers)
- ✅ Identity binding (NodeId is part of cryptographic proof)

---

### Phase 2: Kyber Key Exchange (Post-Quantum)

The **Kyber512 KEM (Key Encapsulation Mechanism)** generates post-quantum shared secret.

**Timeline:**

```
Time    Client                            Server
 |
 0       UHP phase complete (authentication done)
         Session key computed: UHP_key (32 bytes)

 1       KyberRequest (sends)
         ├─ Client's Kyber public key (1184 bytes)
         ├─ Binding to UHP transcript
         │   └─ Blake3(ClientHello || ServerHello || ClientFinish)
         └─ Signature on KyberRequest (to prevent tampering)
                      ↓
 2       KyberResponse (receives & processes)
         ├─ Verify KyberRequest signature
         ├─ Verify transcript hash (prevents splice attacks)
         ├─ Encapsulate to client's Kyber public key
         │   └─ Generates: (shared_secret, ciphertext)
         │      ├─ shared_secret (32 bytes) - to be kept secret
         │      └─ ciphertext (1088 bytes) - sent to client
         ├─ Send KyberResponse
         │   └─ ciphertext encrypted under TLS 1.3
         └─ Receive KyberAck
                      ↓
 3       KyberResponse (receives)
         ├─ Verify KyberResponse signature
         ├─ Decapsulate: ciphertext → shared_secret (32 bytes)
         ├─ Verify shared_secret matches server's (via hash)
         └─ Send KyberAck (confirmation)
             └─ Ephemeral key confirmed, ready for master key
```

**Shared Secret Agreement:**

```
Client                                    Server
  |                                         |
  | Kyber public key (1184 bytes)          |
  |---------- KyberRequest ------->|       |
  |                                 |       |
  |                                 | Encapsulate:
  |                                 |  input: client_kyber_public_key
  |                                 |  output: (shared_secret, ciphertext)
  |                                 |  - shared_secret: 32 bytes (random)
  |                                 |  - ciphertext: 1088 bytes (deterministic)
  |                                 |
  |<------ KyberResponse -----------|       |
  |      (ciphertext)                      |
  |                                 |       |
  | Decapsulate:                    |       |
  |  input: ciphertext              |       |
  |  output: shared_secret (32 bytes)|      |
  |                                 |       |
  | Both peers now have             |       |
  | shared_secret (same value)      |       |
```

**Security Properties:**
- ✅ Post-quantum confidentiality (Kyber is lattice-based)
- ✅ Ephemeral secret (generated fresh per session)
- ✅ Authenticated exchange (ciphertext only valid for this peer)
- ✅ Binding to UHP (transcript hash prevents splice attacks)

**Why Kyber512?**

| Kyber Variant | Security Level | Key Size | Ciphertext | Use Case |
|---------------|-----------------|----------|-----------|----------|
| **Kyber512** | 128-bit PQC | 800 bytes | 768 bytes | ✅ ZHTP (balanced) |
| Kyber768 | 192-bit PQC | 1184 bytes | 1088 bytes | Post-2030 upgrade |
| Kyber1024 | 256-bit PQC | 1568 bytes | 1568 bytes | Extreme paranoia |

Kyber512 provides sufficient post-quantum security for the foreseeable future while maintaining reasonable performance.

---

### Phase 3: Master Key Derivation

After both UHP and Kyber phases complete, both peers compute the same **master key**.

**Master Key Inputs (128 bytes total):**

```
┌──────────────────────────────────────────────────────────────────┐
│                      Master Key Derivation                        │
│                                                                   │
│  Input 1: UHP Session Key (32 bytes)                             │
│  └─ Derived from Dilithium signature verification + nonces       │
│  └─ Proves peer identity (classical security)                    │
│                                                                   │
│  Input 2: Kyber Shared Secret (32 bytes)                         │
│  └─ Result of Kyber512 decapsulation                             │
│  └─ Proves post-quantum key exchange                             │
│                                                                   │
│  Input 3: UHP Transcript Hash (32 bytes)                         │
│  └─ Blake3(ClientHello || ServerHello || ClientFinish)           │
│  └─ Binds all handshake messages (prevents splice attacks)       │
│                                                                   │
│  Input 4: Peer NodeId (32 bytes)                                 │
│  └─ Blake3(DID || device_name)                                   │
│  └─ Cryptographic identity of peer (prevents spoofing)           │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                    HKDF-SHA256 Derivation
                              ↓
                 Master Key (32 bytes)
```

**HKDF Computation:**

```
Step 1: Extract (reduce entropy)
  prk = HMAC-SHA256(
      salt = SHA256("zhtp-quic-mesh"),
      IKM = UHP_key || Kyber_secret || UHP_transcript || NodeId
  )
  → prk: 32 bytes (pseudorandom key)

Step 2: Expand (derive master key)
  master_key = HMAC-SHA256(prk, info="zhtp-quic-master", length=32)
  → master_key: 32 bytes (ready for ChaCha20)

Step 3: Derive Nonce Base
  nonce_base = HMAC-SHA256(prk, info="zhtp-quic-nonce", length=12)
  → nonce_base: 12 bytes (combined with random per-message)
```

**Why HKDF?**

| Property | Benefit |
|----------|---------|
| **Extract Phase** | Processes entropy, normalizes entropy source |
| **Expand Phase** | Cryptographically binds context (salt + info) |
| **HMAC-based** | Resistant to length-extension attacks |
| **NIST Approved** | Part of NIST SP 800-56C KDFs |
| **Proven** | Used in TLS 1.3, HKDF-SHA256 widely analyzed |

---

### Complete Handshake Timeline

```
Time  Message                    Direction   Size        Encrypted
──────────────────────────────────────────────────────────────────
  0   TLS 1.3 ClientHello        C → S       ~512 B      TLS only
  1   TLS 1.3 ServerHello        S → C       ~512 B      TLS only
      (both sides can now encrypt/decrypt with TLS 1.3 session keys)

  2   ClientHello                C → S       ~512 B      TLS 1.3
      (UHP: NodeId + Dilithium pubkey + signature)

  3   ServerHello                S → C       ~512 B      TLS 1.3
      (UHP: NodeId + Dilithium pubkey + signature)
      (Server computes: UHP_session_key)

  4   ClientFinish               C → S       ~256 B      TLS 1.3
      (UHP: Dilithium signature on server nonce)
      (Client & Server compute: master_key from UHP)

  5   KyberRequest               C → S       ~1200 B     TLS 1.3
      (Kyber: Client's public key + binding)

  6   KyberResponse              S → C       ~1100 B     TLS 1.3
      (Kyber: Server's encapsulation ciphertext)
      (Both compute: master_key = HKDF(UHP || Kyber || Hash || NodeId))

  7   KyberAck                   C → S       ~32 B       TLS 1.3 + ChaCha20
      (Confirmation: handshake complete, ready for application)

  8+  Application Messages       C ↔ S       variable    TLS 1.3 + ChaCha20
      (encrypted with master_key derived in step 6)
```

**Total Handshake Time:**
- RTT 1: TLS 1.3 ClientHello → ServerHello (handled by Quinn)
- RTT 2: UHP authentication (ClientHello → ServerHello → ClientFinish)
- RTT 3: Kyber exchange (KyberRequest → KyberResponse → KyberAck)
- **Total: ~3 RTTs (~150ms at 50ms/RTT)**

---

## Message Encryption/Decryption

Once handshake is complete, all application messages are encrypted with **ChaCha20Poly1305**.

### Encryption Process

**Input:**
```
plaintext = "Hello, ZHTP!"
master_key = 32 bytes (derived in handshake Phase 3)
```

**Steps:**

```
Step 1: Generate random nonce
  nonce = random_96_bits()  # 12 bytes

Step 2: Encrypt with ChaCha20Poly1305
  ciphertext = ChaCha20Poly1305.encrypt(
      key = master_key,
      nonce = nonce,
      plaintext = plaintext,
      aad = additional_authenticated_data (optional)
  )
  # Output: 16-byte Poly1305 authentication tag + encrypted data

Step 3: Construct encrypted message
  message = [nonce || ciphertext || tag]
            [12 B  || variable    || 16 B]

Step 4: Send over TLS 1.3
  # Message is now encrypted a 2nd time by TLS 1.3 session keys
  TLS1.3.send(message)
```

**Code Example:**

```rust
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::Rng;

// Generate random nonce
let mut nonce_bytes = [0u8; 12];
rand::thread_rng().fill(&mut nonce_bytes);
let nonce = Nonce::from(nonce_bytes);

// Encrypt message
let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())?;

// Package for transmission
let mut packet = Vec::new();
packet.extend_from_slice(&nonce_bytes);  // 12 bytes
packet.extend_from_slice(&ciphertext);    // variable length

// Send through TLS 1.3 encrypted QUIC stream
quic_stream.write_all(&packet)?;
```

### Decryption Process

**Input:**
```
received_message = [12 bytes nonce] [encrypted data] [16 bytes tag]
master_key = 32 bytes (same as sender)
```

**Steps:**

```
Step 1: Extract components
  nonce = received_message[0:12]
  ciphertext = received_message[12:]
  # Poly1305 tag is embedded in ciphertext

Step 2: Decrypt with ChaCha20Poly1305
  plaintext = ChaCha20Poly1305.decrypt(
      key = master_key,
      nonce = nonce,
      ciphertext = ciphertext,
      aad = additional_authenticated_data (must match sender)
  )

Step 3: Verify decryption succeeded
  assert!(plaintext != NULL, "Authentication tag verification failed")
  assert!(length(plaintext) > 0, "Empty plaintext indicates tampering")

Step 4: Process plaintext
  # Now safe to use plaintext
  message = deserialize(plaintext)
```

**Code Example:**

```rust
// Receive encrypted message
let received_packet = quic_stream.read().await?;

// Extract nonce
let nonce = Nonce::from(&received_packet[0:12]);

// Decrypt message
let plaintext = cipher.decrypt(
    &nonce,
    &received_packet[12..]
)?;

// Process decrypted message
let message: MeshMessage = serde_json::from_slice(&plaintext)?;
```

### Dual-Layer Decryption

The message goes through **two decryption steps**:

```
Encrypted Message (from network)
        ↓
Decrypt by TLS 1.3 (QUIC session keys)  ← Transport layer
        ↓
ChaCha20 encrypted data
        ↓
Decrypt by ChaCha20Poly1305 (master_key)  ← Application layer
        ↓
Plaintext Message
```

---

## Key Derivation

### HKDF-SHA256 Formula

The master key derivation uses HKDF with four cryptographic inputs:

```
Master Key Derivation Formula
═════════════════════════════════════════════════════════════

Input Material (IKM):
  IKM = UHP_session_key || Kyber_shared_secret || UHP_transcript_hash || Peer_NodeId
      = 32 bytes        || 32 bytes            || 32 bytes           || 32 bytes
      = 128 bytes total

HKDF-Extract Phase (reduce entropy to 32 bytes):
  salt = SHA256("zhtp-quic-mesh")
  prk = HMAC-SHA256(salt, IKM)
      = 32 bytes

HKDF-Expand Phase (expand to master key):
  master_key = HMAC-SHA256(prk, "zhtp-quic-master", 1) ||
               HMAC-SHA256(prk, "zhtp-quic-master", 2)[0:0]
             = 32 bytes

Result:
  master_key: 32 bytes (ready for ChaCha20Poly1305)
```

### Why Each Input?

| Input | Size | Purpose | Consequence if Missing |
|-------|------|---------|------------------------|
| UHP Session Key | 32 B | Classical authentication | No classical security |
| Kyber Shared Secret | 32 B | Post-quantum key exchange | Vulnerable to quantum |
| UHP Transcript Hash | 32 B | Bind all handshake messages | Splice attack possible |
| Peer NodeId | 32 B | Bind to peer identity | Peer impersonation |

**Example:** If we omitted NodeId:
```
Attack Scenario:
1. Alice ↔ Bob (exchange UHP + Kyber)
2. Attacker learns: UHP_key_AB and Kyber_secret_AB
3. Attacker creates fake session with Bob as if from Alice
4. Both Alice and Attacker's session would have same master_key
5. Result: Attacker can decrypt Alice's messages to Bob

Mitigation: NodeId binding prevents this (attacker's NodeId ≠ Alice's NodeId)
```

---

## Nonce Management

### Per-Message Randomness

Each encrypted message uses a **random 96-bit nonce**:

```
Nonce Generation:
  nonce = random_96_bits()

Why 96 bits (12 bytes)?
  - ChaCha20Poly1305 standard (RFC 7539)
  - Birthday bound: ~2^48 messages before 50% collision
  - With 1000 messages/sec: ~8.9 years before collision
  - Acceptable for short-lived sessions (< 1 hour)
```

### Nonce-Key Separation

Different uses have separate nonces:

```
For Message i at time t:
  nonce_i = HKDF(master_key, counter=i, nonce_base)
  ChaCha20(master_key, nonce_i, plaintext) → ciphertext_i
```

### Replay Protection

**Nonces prevent replay attacks:**

```
Attack: Attacker records message M1 encrypted with nonce N1
        Later, attacker resends same [N1 || ciphertext || tag]

Defense: Nonce is included in ciphertext
         Receiver sees duplicate nonce N1
         Sequence number check detects replay
         Message rejected
```

**Additional Protection: Sequence Numbers**
```rust
// QUIC streams have implicit sequence numbers
// Both peers track: last_sequence_number
// If sequence_number <= last_sequence_number: REJECT (replay)
```

### Rainbow Table Resistance

Since nonce is **random per message**:
- Can't pre-compute tables (different nonce for each message)
- Even if master_key is compromised, old messages are safe
- Nonce must be known to decrypt

---

## Security Properties

### Confidentiality

**Threat:** Attacker wants to read messages
**Defense:**
- TLS 1.3: Block network-level eavesdropping
- ChaCha20: Block application-level eavesdropping
- Combined: Multi-layered protection

**Strength:**
- Classical: ChaCha20 is proven secure (stream cipher, AEAD)
- Quantum: Kyber512 is lattice-based (hard for quantum computers)

### Authentication

**Threat:** Attacker wants to impersonate peer
**Defense:**
- UHP (Dilithium signatures): Classical authentication
- Kyber binding: Post-quantum proof of peer knowledge
- NodeId binding: Cryptographic identity proof

**Verification Steps:**
1. Verify Dilithium signature (ClientHello, ServerHello, ClientFinish)
2. Verify NodeId matches expected peer
3. Verify Kyber ciphertext decapsulates correctly

### Integrity

**Threat:** Attacker wants to modify messages
**Defense:**
- Poly1305 MAC: Detects any bit flips
- TLS 1.3 HMAC: Detects transport-layer tampering
- Combined: Two layers of integrity protection

**Result:** Modified messages detected (authentication tag mismatch)

### Forward Secrecy

**Threat:** Attacker steals master_key, wants to decrypt past messages
**Defense:**
- Each message uses random nonce
- Old messages have different nonce values
- Without both (key + nonce), decryption fails

**Practical Implication:** Even if master_key is compromised:
- Can't decrypt past messages (different nonces)
- Can only decrypt future messages sent after compromise

### Replay Protection

**Threat:** Attacker records message, resends it
**Defense:**
- Random nonce per message
- Sequence numbers on QUIC streams
- Nonce cache prevents duplicate processing

**Result:** Replayed messages are rejected

---

## Configuration

### Algorithm Parameters

```rust
// File: lib-network/src/protocols/quic_mesh.rs

const HKDF_SALT: &[u8] = b"zhtp-quic-mesh";
const HKDF_INFO: &[u8] = b"zhtp-quic-master";
const MASTER_KEY_LENGTH: usize = 32;      // 256 bits
const KYBER_KEY_SIZE: usize = 1184;       // Kyber512 public key
const DILITHIUM_KEY_SIZE: usize = 2432;   // Dilithium-3 public key
const NONCE_SIZE: usize = 12;             // 96 bits
const TAG_SIZE: usize = 16;               // Poly1305 tag
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const REHANDSHAKE_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
```

### TLS 1.3 Configuration (Quinn)

```rust
// File: lib-network/src/protocols/quic_mesh.rs::configure_server()

let mut server_config = ServerConfig::with_single_cert(
    vec![cert],
    private_key
)?;

server_config.transport_config = Arc::new(TransportConfig {
    max_idle_timeout: Some(IdleTimeout::try_from(Duration::from_secs(300))?)
        .unwrap(),
    max_concurrent_uni_streams: (0u32).into(),
    max_concurrent_bidi_streams: (100u32).into(),
    ..Default::default()
});
```

### Connection Limits

```rust
// File: lib-network/src/peer_registry/mod.rs

pub const MAX_PEERS: usize = 100;              // Maximum concurrent peers
pub const MAX_PENDING_CONNECTIONS: usize = 20; // Pending handshakes
pub const IDLE_TIMEOUT_SECS: u64 = 300;       // 5 minutes
pub const MAX_CONNECTION_AGE_SECS: u64 = 3600; // 1 hour (then rehandshake)
```

---

## Examples

### Example 1: Basic Message Encryption

```rust
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::Rng;

fn encrypt_message(master_key: &[u8; 32], message: &str) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(master_key.into());

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, message.as_bytes())
        .expect("encryption failed");

    // Package with nonce
    let mut packet = Vec::new();
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);

    packet
}

fn decrypt_message(master_key: &[u8; 32], packet: &[u8]) -> String {
    let cipher = ChaCha20Poly1305::new(master_key.into());

    // Extract nonce
    let nonce = Nonce::from(&packet[0:12]);

    // Decrypt
    let plaintext = cipher
        .decrypt(&nonce, &packet[12..])
        .expect("decryption failed");

    String::from_utf8(plaintext).expect("invalid UTF-8")
}

// Usage
let master_key: [u8; 32] = [0; 32]; // From HKDF derivation
let encrypted = encrypt_message(&master_key, "Hello, ZHTP!");
let decrypted = decrypt_message(&master_key, &encrypted);
assert_eq!(decrypted, "Hello, ZHTP!");
```

### Example 2: Master Key Derivation

```rust
use hkdf::Hkdf;
use sha2::Sha256;

fn derive_master_key(
    uhp_session_key: &[u8; 32],
    kyber_shared_secret: &[u8; 32],
    uhp_transcript_hash: &[u8; 32],
    peer_node_id: &[u8; 32],
) -> [u8; 32] {
    // Combine inputs
    let mut ikm = Vec::new();
    ikm.extend_from_slice(uhp_session_key);
    ikm.extend_from_slice(kyber_shared_secret);
    ikm.extend_from_slice(uhp_transcript_hash);
    ikm.extend_from_slice(peer_node_id);

    // HKDF-Extract
    let hkdf = Hkdf::<Sha256>::new(
        Some(b"zhtp-quic-mesh"),  // salt
        &ikm                       // IKM
    );

    // HKDF-Expand
    let mut okm = [0u8; 32];
    hkdf.expand(b"zhtp-quic-master", &mut okm)
        .expect("HKDF expand failed");

    okm
}

// Usage
let master_key = derive_master_key(
    &uhp_session_key,
    &kyber_shared_secret,
    &uhp_transcript_hash,
    &peer_node_id,
);
```

### Example 3: Complete Handshake Flow (Pseudocode)

```rust
// Server side
async fn handle_client_connection(client_stream: &mut QuicStream) {
    // Phase 1: UHP Authentication
    let client_hello = client_stream.read_message().await;
    verify_dilithium_signature(&client_hello);

    let server_hello = ServerHello::new();
    client_stream.write_message(&server_hello).await;

    let client_finish = client_stream.read_message().await;
    verify_dilithium_signature(&client_finish);

    // Compute UHP session key
    let uhp_session_key = derive_uhp_key(&client_hello, &server_hello);

    // Phase 2: Kyber Key Exchange
    let kyber_request = client_stream.read_message().await;
    verify_kyber_binding(&kyber_request);

    // Encapsulate to client's Kyber public key
    let (shared_secret, ciphertext) = kyber_encapsulate(&kyber_request.kyber_pubkey);

    let kyber_response = KyberResponse { ciphertext };
    client_stream.write_message(&kyber_response).await;

    // Phase 3: Master Key Derivation
    let uhp_transcript_hash = hash_transcript(&[client_hello, server_hello, client_finish]);
    let master_key = derive_master_key(
        &uhp_session_key,
        &shared_secret,
        &uhp_transcript_hash,
        &client_node_id,
    );

    // Ready for encrypted application messages
    loop {
        let encrypted_msg = client_stream.read_encrypted().await;
        let plaintext = decrypt_with_key(&encrypted_msg, &master_key);
        process_message(&plaintext).await;
    }
}
```

---

## Summary Table

| Layer | Purpose | Algorithm | Security |
|-------|---------|-----------|----------|
| **Transport (TLS 1.3)** | Connection protection | ChaCha20Poly1305 | Classical |
| **Application (ChaCha20+Kyber)** | Message protection | ChaCha20Poly1305 + Kyber512 | Post-Quantum |
| **Combined** | Defense-in-depth | Dual encryption | Classical + Quantum |

---

## References

- [RFC 8446] - TLS 1.3
- [RFC 9000] - QUIC Protocol
- [RFC 5869] - HKDF
- [RFC 7539] - ChaCha20 and Poly1305
- [FIPS 203] - NIST PQC: Kyber (2024)
- [FIPS 204] - NIST PQC: Dilithium (2024)
