# QUIC Encryption Defense-in-Depth: Complete Guide

**Comprehensive documentation for understanding ZHTP's dual-layer encryption architecture.**

---

## Quick Reference

| Question | Answer | Reference |
|----------|--------|-----------|
| **Why two encryption layers?** | Defense-in-depth: Classical (TLS 1.3) + Quantum (Kyber) | [ADR](./ADR_QUIC_ENCRYPTION.md) |
| **How do peers agree on keys?** | UHP auth + Kyber KEM → HKDF(4 inputs) → master_key | [Protocol Flow](./QUIC_ENCRYPTION_PROTOCOL.md#complete-handshake-flow) |
| **What if TLS 1.3 breaks?** | ChaCha20+Kyber still protects data (post-quantum) | [Threat Model](./ADR_QUIC_ENCRYPTION.md#threat-model) |
| **What if Kyber breaks?** | TLS 1.3 still protects data (proven classical) | [Threat Model](./ADR_QUIC_ENCRYPTION.md#threat-model) |
| **How long is handshake?** | ~3 RTTs (~150ms), then bulk encryption ready | [Handshake Timeline](./QUIC_ENCRYPTION_PROTOCOL.md#complete-handshake-timeline) |
| **Per-message overhead?** | 12-byte nonce + 16-byte tag = 28 bytes | [Message Format](./QUIC_ENCRYPTION_PROTOCOL.md#message-encryption-decryption) |
| **Forward secrecy?** | Yes: random nonce per message + ephemeral keys | [Security Properties](./QUIC_ENCRYPTION_PROTOCOL.md#forward-secrecy) |

---

## Documentation Map

### For Architects & Decision Makers
**Read:** [ADR_QUIC_ENCRYPTION.md](./ADR_QUIC_ENCRYPTION.md)

- Why defense-in-depth? (Threat model, trade-offs)
- Comparison to single-layer approaches
- Long-term upgrade path for post-quantum era
- Risk assessment and mitigations

**Time to read:** 30 minutes

### For Protocol Engineers
**Read:** [QUIC_ENCRYPTION_PROTOCOL.md](./QUIC_ENCRYPTION_PROTOCOL.md)

- Complete handshake flow with diagrams
- Message encryption/decryption process
- Key derivation formula and rationale
- Nonce management and security properties
- Code examples

**Time to read:** 45 minutes

### For Implementation & Security Review
**Files to review:**

1. **Handshake Implementation:** `lib-network/src/protocols/quic_handshake.rs`
   - UHP authentication (Dilithium verification)
   - Kyber key exchange (encapsulation)
   - Master key derivation (HKDF)

2. **Message Encryption:** `lib-network/src/protocols/quic_mesh.rs`
   - `send_encrypted_message()` - Encryption with ChaCha20
   - `recv_encrypted_message()` - Decryption with verification

3. **Cryptographic Primitives:** `lib-crypto/src/symmetric/chacha20.rs`
   - ChaCha20Poly1305 AEAD
   - Nonce generation and embedding

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  Application Layer                          │
│              (ZHTP Mesh Messages)                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────────────────────────┐
        │   APPLICATION LAYER ENCRYPTION        │
        │   ChaCha20Poly1305 + Kyber512         │
        │   Master Key from UHP + Kyber + Hash  │
        └───────────────────────────────────────┘
                            ↓
        ┌───────────────────────────────────────┐
        │     TRANSPORT LAYER ENCRYPTION        │
        │     TLS 1.3 (QUIC/Quinn)              │
        │     Connection-level security         │
        └───────────────────────────────────────┘
                            ↓
        ┌───────────────────────────────────────┐
        │         NETWORK LAYER                 │
        │         UDP/IPv4 (unencrypted)        │
        │         (Firewall traversal)          │
        └───────────────────────────────────────┘
```

### Layer Responsibilities

**Transport Layer (TLS 1.3):**
- ✅ Protects connection establishment
- ✅ Prevents passive eavesdropping
- ✅ Prevents man-in-the-middle attacks
- ✅ Connection-level authentication via certificates
- ❌ Not quantum-resistant

**Application Layer (ChaCha20+Kyber):**
- ✅ Protects individual messages
- ✅ Quantum-resistant key exchange (Kyber)
- ✅ Cryptographic identity binding (NodeId)
- ✅ Mutual authentication (Dilithium signatures)
- ✅ Replay protection (random nonces)
- ❌ Doesn't protect QUIC metadata (handled by TLS 1.3)

---

## Handshake Overview

### Three Phases

The QUIC handshake with post-quantum cryptography consists of three phases:

```
Phase 1: TLS 1.3 (Handled by Quinn)
  Client ←→ Server  (1 RTT)
  Result: TLS session keys for QUIC encryption
  ├─ ClientHello
  ├─ ServerHello
  ├─ ServerFinished
  └─ ClientFinished

Phase 2: UHP Authentication (Dilithium Signatures)
  Client ←→ Server  (1 RTT)
  Result: UHP session key + verified peer identity
  ├─ ClientHello (NodeId + Dilithium pubkey + signature)
  ├─ ServerHello (NodeId + Dilithium pubkey + signature)
  └─ ClientFinish (Dilithium signature on server nonce)

Phase 3: Kyber Key Exchange (Post-Quantum)
  Client ←→ Server  (1 RTT)
  Result: Shared secret for post-quantum security
  ├─ KyberRequest (Client's Kyber pubkey)
  ├─ KyberResponse (Server's encapsulated ciphertext)
  └─ KyberAck (Confirmation)

Total: ~3 RTTs (~150ms) + both peers compute master_key
```

### Master Key Composition

```
Master Key = HKDF(
    Input 1: UHP Session Key (32 bytes)
      └─ Classical authentication
    || Input 2: Kyber Shared Secret (32 bytes)
      └─ Quantum-resistant key exchange
    || Input 3: UHP Transcript Hash (32 bytes)
      └─ Handshake integrity binding
    || Input 4: Peer NodeId (32 bytes)
      └─ Identity cryptographic binding
)
= 32-byte symmetric key ready for ChaCha20Poly1305
```

**Why four inputs?**
- **UHP key:** Proves peer identity (classical)
- **Kyber secret:** Provides quantum-resistant security
- **Transcript hash:** Binds handshake (prevents splice attacks)
- **NodeId:** Prevents peer impersonation + session hijacking

---

## Message Encryption Flow

### Sending a Message

```
1. Application prepares message (e.g., "Hello, Peer!")

2. Generate random 96-bit nonce
   nonce = random_96_bits()

3. Encrypt with ChaCha20Poly1305
   Input: master_key (32 bytes), nonce (12 bytes), plaintext
   Output: ciphertext + 16-byte Poly1305 authentication tag

4. Construct packet
   packet = [nonce || ciphertext || tag]
   Size: 12 + len(plaintext) + 16 bytes

5. QUIC/TLS 1.3 encrypts entire packet again
   (transparent to application)

6. Send UDP packet over network
   Encrypted twice: TLS 1.3 → ChaCha20 → Network
```

### Receiving a Message

```
1. UDP packet arrives from network

2. QUIC/TLS 1.3 decrypts packet
   (transparent to application)

3. Extract components
   nonce = packet[0:12]
   ciphertext = packet[12:]

4. Decrypt with ChaCha20Poly1305
   Input: master_key (32 bytes), nonce (12 bytes), ciphertext
   Output: plaintext (if authentication tag valid)
   Error: If tag invalid, message is rejected (tampering detected)

5. Process plaintext message
   Guaranteed: Message not modified in transit
```

---

## Key Derivation Deep Dive

### HKDF (HMAC-based Key Derivation Function)

HKDF has two phases: **Extract** and **Expand**

```
Input Material (128 bytes):
  IKM = uhp_session_key || kyber_shared_secret || transcript_hash || node_id
      = 32 + 32 + 32 + 32 = 128 bytes

EXTRACT PHASE (Reduce entropy):
  salt = SHA256("zhtp-quic-mesh")
  prk = HMAC-SHA256(salt, IKM)
      = 32-byte pseudorandom key

EXPAND PHASE (Derive master key):
  master_key = HMAC-SHA256(prk, info="zhtp-quic-master")
             = 32-byte final key ready for encryption
```

### Why HKDF?

| Reason | Benefit |
|--------|---------|
| **Extract phase** | Normalizes entropy from 128 bytes → uniform 32 bytes |
| **HMAC-based** | Resistant to length-extension attacks |
| **Context binding** | Different `info` strings for different purposes |
| **NIST approved** | Used in TLS 1.3, widely analyzed |
| **Proven** | RFC 5869, implemented in major cryptographic libraries |

### What If We Changed One Input?

**Scenario: Remove NodeId from master key**

```
Without NodeId binding:
1. Alice ↔ Bob handshake
   uhp_session_key_AB + kyber_secret_AB + transcript_hash_AB
   → master_key_AB

2. Attacker intercepts, later tries to use same session with Bob
   Attacker ↔ Bob (using same UHP + Kyber secrets)
   → master_key_AB (SAME!)

3. Attacker can decrypt Alice's messages to Bob
   Result: SECURITY BREACH

With NodeId binding:
  master_key = HKDF(... || node_id_alice)
  Attacker's NodeId ≠ Alice's NodeId
  → Different master key → Can't decrypt Alice's messages
  Result: SECURE
```

---

## Security Properties Checklist

### ✅ Confidentiality (Dual-Layer)

| Layer | Cipher | Security |
|-------|--------|----------|
| Transport | TLS 1.3 ChaCha20Poly1305 | Classical (proven) |
| Application | ChaCha20Poly1305 | Classical + Quantum-resistant |
| Combined | Both layers | Extreme: survives breaks in either layer |

**Practical Implication:** Even if TLS 1.3 is broken tomorrow, messages remain encrypted by application layer.

### ✅ Integrity (Dual-Layer)

| Layer | Method | Detection |
|-------|--------|-----------|
| Transport | TLS 1.3 HMAC | Detects tampering at connection level |
| Application | Poly1305 MAC | Detects tampering at message level |
| Combined | Both | Bit-flip in any layer detected |

**Practical Implication:** Modified messages are rejected with high certainty (< 2^-128 false accept rate).

### ✅ Authentication

| Method | Strength | Verified |
|--------|----------|----------|
| Dilithium-3 Signatures | 128-bit security | Both peers verify each other |
| NodeId Binding | Blake3 (256-bit) | Peer identity proven cryptographically |
| Transcript Hash | Blake3 (256-bit) | All handshake messages bound to session |

**Practical Implication:** Peer impersonation is computationally infeasible (2^128 operations).

### ✅ Replay Protection

| Mechanism | Protection |
|-----------|-----------|
| Random nonce per message | Different ciphertext for same message |
| Sequence numbers | Detects duplicate messages |
| Nonce cache | Prevents exact replay |

**Practical Implication:** Attacker recording messages can't replay them.

### ✅ Forward Secrecy

| Layer | Ephemeral | Duration |
|-------|-----------|----------|
| Transport (TLS 1.3) | ECDHE keys | Per connection |
| Application (Kyber) | KEM encapsulation | Per session |
| Keys zeroized after use | Yes | Immediately |

**Practical Implication:** If master_key is stolen, past messages remain encrypted (different nonces).

---

## Performance Implications

### Handshake Overhead

```
Operation               Time        Impact
─────────────────────────────────────────
TLS 1.3 ClientHello     ~50ms       (Quinn handles, ~1 RTT)
UHP Authentication      ~50ms       (Dilithium verification, ~1 RTT)
Kyber Key Exchange      ~50ms       (Encapsulation, ~1 RTT)
Master Key Derivation   ~1ms        (HKDF-SHA256)
Total Handshake         ~150ms      (3 RTTs, one-time cost)
```

**Analysis:** Handshake overhead acceptable (one-time cost per connection).

### Per-Message Overhead

```
Operation               Time        Overhead
─────────────────────────────────────────────
Generate nonce          ~0.1μs      Negligible
ChaCha20 encryption     ~1.0μs      < 0.001% for 1KB message
Poly1305 verification   ~0.5μs      Negligible
Total per message       ~1.6μs      < 0.1ms for realistic messages
```

**Analysis:** Per-message overhead < 1% of typical RTT (50ms).

### Memory Footprint

```
Per Connection:
  TLS 1.3 session key     32 bytes
  Master key              32 bytes
  Nonce state             12 bytes
  Handshake state         ~1KB (temporary, freed after handshake)

Per Peer:
  Dilithium public key    2432 bytes
  Kyber public key        1184 bytes
  NodeId                  32 bytes

Total per 100 peers:    ~367 KB (negligible)
```

**Analysis:** Memory overhead acceptable for mesh network with 100 peers.

---

## Future Upgrade Path

### Post-Quantum Transition (2030+)

When quantum computers become practical:

```
Current (2025):
  TLS 1.3: Classical ECDHE
  App: Kyber512 (128-bit PQC security)

Future Option 1 (Gradual Upgrade):
  TLS 1.3: Hybrid ECDHE + Kyber (RFC 9370)
  App: Kyber768 (192-bit PQC security)

Future Option 2 (Full PQC):
  TLS 1.3: Pure Kyber (after NIST standard proven)
  App: Kyber1024 (256-bit PQC security)
```

**Current advantage:** Defense-in-depth provides grace period for transition.

### Algorithm Agility

The design supports algorithm replacement:

```
Component         Current         Future Alternative
──────────────────────────────────────────────────────
Key Exchange      Kyber512        Kyber768, Kyber1024
Signature         Dilithium-3     Dilithium5, SLH-DSA
Symmetric         ChaCha20        AES-256, AES-GCM
Hash              SHA256          Blake3, SHA3
KDF               HKDF-SHA256     Custom KDF
```

**Mechanism:** Version negotiation in NodeAnnouncement allows peer selection.

---

## Testing Strategy

### Unit Tests (Crypto Layer)

```rust
#[test]
fn test_master_key_derivation() {
    // Verify HKDF produces correct output
    // Use test vectors from RFC 5869
}

#[test]
fn test_chacha20_encryption_deterministic() {
    // Encrypt same plaintext with same key/nonce
    // Verify output matches
}

#[test]
fn test_nonce_randomness() {
    // Generate 1000 nonces
    // Verify no duplicates (statistical test)
}

#[test]
fn test_key_zeroization() {
    // Verify sensitive keys are zeroed after use
}
```

### Integration Tests (Protocol Layer)

```rust
#[tokio::test]
async fn test_complete_handshake_flow() {
    // Client and server handshake
    // Verify both compute same master_key
    // Verify can exchange encrypted messages
}

#[tokio::test]
async fn test_message_encryption_roundtrip() {
    // Encrypt message
    // Decrypt message
    // Verify plaintext matches original
}

#[tokio::test]
async fn test_replay_attack_prevention() {
    // Send message M1 with nonce N1
    // Attacker replays M1 with same N1
    // Verify receiver detects and rejects replay
}
```

### Security Tests (Threat Modeling)

```rust
#[tokio::test]
async fn test_identity_spoofing_prevented() {
    // Attacker tries to use peer B's NodeId
    // Verify handshake fails (Dilithium signature mismatch)
}

#[tokio::test]
async fn test_modified_message_detected() {
    // Attacker modifies ciphertext (single bit flip)
    // Verify receiver detects tampering (tag mismatch)
}

#[tokio::test]
async fn test_classical_cryptanalysis_resilience() {
    // Decrypt all bits individually
    // Verify no patterns or biases
}
```

---

## Troubleshooting

### Issue: Handshake Timeout

**Symptom:** Peers can't establish connection (timeout after 30 seconds)

**Check:**
1. Network connectivity: `ping peer_ip`
2. QUIC port open: `netstat -an | grep 9334`
3. Firewall rules: Allow UDP 9334
4. Logs: Check Dilithium signature verification

**Fix:**
```rust
// Increase handshake timeout if on slow network
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60); // was 30
```

### Issue: Authentication Tag Mismatch

**Symptom:** Received messages show "authentication tag verification failed"

**Causes:**
1. Master key mismatch (handshake didn't complete properly)
2. Network corruption (rare, but UDP not checksummed)
3. Clock skew (nonce generation depends on randomness)

**Debug:**
```rust
// Log master key at both sides
info!("Master key: {:?}", master_key.to_hex());

// Compare in logs - should match
// If not, handshake verification failed somewhere
```

### Issue: High CPU Usage During Handshake

**Symptom:** CPU spikes when many peers connect

**Causes:**
1. Dilithium signature verification is expensive (2KB signature)
2. Kyber encapsulation expensive (lattice operations)
3. HKDF requires multiple HMAC-SHA256 operations

**Mitigation:**
```rust
// Limit concurrent handshakes
const MAX_PENDING_CONNECTIONS: usize = 20;

// Handshake in background to not block message processing
tokio::spawn(async move {
    handshake_handler(peer_connection).await;
});
```

---

## References & Links

### Architecture
- [ADR_QUIC_ENCRYPTION.md](./ADR_QUIC_ENCRYPTION.md) - Design decisions and trade-offs

### Protocol
- [QUIC_ENCRYPTION_PROTOCOL.md](./QUIC_ENCRYPTION_PROTOCOL.md) - Complete protocol specification

### Code
- `lib-network/src/protocols/quic_mesh.rs` - QUIC transport layer
- `lib-network/src/protocols/quic_handshake.rs` - UHP + Kyber handshake
- `lib-crypto/src/symmetric/chacha20.rs` - Encryption primitives

### Standards
- [RFC 8446] - TLS 1.3
- [RFC 9000] - QUIC
- [RFC 5869] - HKDF
- [FIPS 203] - Kyber (2024)
- [FIPS 204] - Dilithium (2024)

### Related Issues
- #492 - Document QUIC encryption architecture
- #161 - Unify encryption across protocols
- #486 - Security audit and fixes

---

**Last Updated:** 2025-12-23
**Status:** Complete
**Audience:** All developers, architects, security reviewers
