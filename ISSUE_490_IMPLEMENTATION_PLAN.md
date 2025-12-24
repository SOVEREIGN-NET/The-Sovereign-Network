# Implementation Plan: Issue #490 - Unified Protocol Encryption Architecture

## Implementation Progress

| Phase | Status | Details |
|-------|--------|---------|
| **Phase 1** | ✅ COMPLETE | Trait + FCIS applied. 19/19 tests passing (4 core + 15 shell/security). |
| **Phase 2** | 🚀 IN PROGRESS | Protocol adapters (Bluetooth ✅ 9/9, ZHTP ✅ 12/12, WiFi Direct ✅ 17/17, QUIC, LoRaWAN) |
| **2.1 Bluetooth** | ✅ COMPLETE | Wire format + replay protection. 9/9 tests passing. |
| **2.2 ZHTP** | ✅ COMPLETE | Mesh encryption with domain separation. 12/12 tests passing. |
| **2.3 WiFi Direct** | ✅ COMPLETE | End-to-end + fallback state. 17/17 tests passing. |
| **2.4 QUIC** | ⏳ PENDING | QUIC application encryption |
| **2.5 LoRaWAN** | ⏳ PENDING | LoRaWAN adapter |
| **Phase 3** | ⏳ PENDING | Refactor protocols to use adapters |
| **Phase 4** | ⏳ PENDING | Comprehensive testing & CI guards |
| **Phase 5** | ⏳ PENDING | Module exports update |

---

## Executive Summary

**Scope**: Complete refactoring to unify all mesh protocol encryption under the `ProtocolEncryption` trait with ChaCha20Poly1305 AEAD.

**Approach**: Full architectural cleanup with hard security cutover for Bluetooth.

**Key Finding**: The `ProtocolEncryption` trait already exists at `lib-network/src/encryption/mod.rs`, but protocols bypass it and call `lib_crypto` directly. Bluetooth uses **CRITICAL vulnerability: AES-128 ECB mode** (no IV, no authentication).

**User Decisions**:
- ✅ Complete refactoring of all protocols
- ✅ Hard cutover for Bluetooth (breaking change acceptable)
- ✅ Full adoption of ProtocolEncryption trait

---

## Critical Security Vulnerability

**Location**: `/Users/supertramp/Dev/The-Sovereign-Network/lib-network/src/protocols/bluetooth/enhanced.rs` (lines 522-546)

**Issue**: `encrypt_p2p_message()` uses AES-128 in ECB mode:
- **No nonce/IV** → same plaintext always produces same ciphertext
- **Pattern leakage** → attacker can analyze message structure
- **No authentication** → vulnerable to tampering (CMAC is separate)
- **Severity**: CRITICAL (ECB is considered the most insecure block cipher mode)

**Fix**: Replace with ChaCha20Poly1305 AEAD (same as other protocols)

---

## Current State Analysis

### What Exists ✅

1. **ProtocolEncryption Trait** (`lib-network/src/encryption/mod.rs`, 561 lines)
   - Methods: `encrypt()`, `decrypt()`, `protocol()`, `stats()`, `reset_stats()`
   - Implementation: `ChaCha20Poly1305Encryption` with thread-safe atomics
   - Factory: `create_encryption(protocol, key)`
   - Tests: 11 existing test cases

2. **Working Encryption** (bypassing trait):
   - LoRaWAN: Uses `lib_crypto::symmetric::chacha20::encrypt_data()` directly
   - WiFi Direct: Uses `lib_crypto::symmetric::chacha20::encrypt_data()` directly
   - QUIC: Uses `lib_crypto::symmetric::chacha20::encrypt_data()` directly
   - ZHTP: Uses `lib_crypto::symmetric::chacha20::encrypt_data()` directly

3. **Broken Encryption**:
   - Bluetooth Enhanced: Uses AES-128 ECB + separate CMAC ❌

### Architecture Gap

```
Current (Fragmented):
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│LoRaWAN   │  │WiFi Dir  │  │  QUIC    │  │Bluetooth │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     └─────────────┴─────────────┼─────────────┘
                                 │      ┌───────────┐
     ┌──────────────────────────┼──────│  AES ECB  │ ❌
     │                           │      └───────────┘
     ▼                           ▼
┌──────────────┐    ┌──────────────────────┐
│ lib_crypto   │    │ ProtocolEncryption   │
│ (direct)     │    │ Trait (UNUSED)       │
└──────────────┘    └──────────────────────┘

Desired (Unified):
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│LoRaWAN   │  │WiFi Dir  │  │  QUIC    │  │Bluetooth │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     └─────────────┴─────────────┴─────────────┘
                          │
                          ▼
            ┌──────────────────────────┐
            │  ProtocolEncryption      │
            │  Trait (UNIFIED)         │
            └────────────┬─────────────┘
                         │
                         ▼
            ┌──────────────────────────┐
            │  ChaCha20Poly1305        │
            │  AEAD (lib_crypto)       │
            └──────────────────────────┘
```

---

## Critical Security Requirements (MUST IMPLEMENT)

### 1. Domain Separation with AAD (Associated Authenticated Data)

**Requirement**: Protocols MUST NOT be able to decrypt each other's ciphertexts, even with the same key.

**Implementation**: Use AEAD with Additional Authenticated Data:
- AAD format: `protocol_id || message_type || version || session_id`
- Prevents ciphertext transplant attacks
- Prevents unknown-keyshare bugs

**Trait Signature Change**:
```rust
pub trait ProtocolEncryption: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;  // Changed: &self not &mut, added aad
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;  // Changed: &self not &mut, added aad
    fn protocol(&self) -> &str;
    fn stats(&self) -> EncryptionStats;
    fn reset_stats(&mut self);
}
```

### 2. Async-Safe Locking Strategy

**Problem**: Mixing `std::sync::RwLock` with async code causes deadlocks.

**Solution**:
- Use `tokio::sync::RwLock` for async contexts
- OR make encryption stateless (&self instead of &mut self) with atomic stats only
- **Preferred**: Stateless encryption with `&self` (no locks needed)

### 3. Bluetooth Wire Format Specification

**Frame Format** (total overhead: 42 bytes):
```
┌────────┬───────┬────────┬──────────┬─────────────┬─────────┐
│Version │ Flags │ Nonce  │ Sequence │ Ciphertext  │   Tag   │
│ (1)    │ (1)   │ (12)   │   (8)    │  (variable) │  (16)   │
└────────┴───────┴────────┴──────────┴─────────────┴─────────┘
```

**Fields**:
- **Version** (1 byte): Protocol version (0x01 for initial release)
- **Flags** (1 byte): Reserved for future use (fragmentation, compression)
- **Nonce** (12 bytes): Deterministic nonce = `HKDF(session_id || seq || direction)`
- **Sequence** (8 bytes): Monotonic counter for replay protection
- **Ciphertext** (variable): Encrypted payload
- **Tag** (16 bytes): Poly1305 authentication tag

**Nonce Strategy**: Deterministic nonce derived from (session_id, sequence, direction) to guarantee uniqueness without state.

**Replay Protection**: Reject sequence numbers ≤ last_seen_seq per peer/session.

**Fragmentation**: Encrypt-then-fragment with outer header `[msg_id(4) || frag_idx(2) || frag_count(2)]` authenticated via AAD.

### 4. Implementation Order (REVISED)

**Priority 1: Bluetooth Security Fix** (Week 1)
- Define wire format with version, nonce, sequence
- Implement deterministic nonce derivation
- Add replay protection
- Hard cutover migration plan

**Priority 2: Refactor Other Protocols** (Week 2)
- Update all protocols to use trait with AAD
- Use `tokio::sync::RwLock` or stateless design
- Domain-separate all protocols

**Priority 3: Testing & CI Guards** (Week 3)
- Add tests that verify cross-protocol ciphertext FAILS
- Add CI lint to prevent direct lib_crypto calls
- Comprehensive security tests

### 5. Must-Not-Regress Security Invariants

- [ ] **Nonce uniqueness** per (key, direction) guaranteed
- [ ] **Decrypt fails on bit flip** (AEAD tag enforced)
- [ ] **Cross-protocol ciphertext rejected** (AAD domain separation)
- [ ] **Bluetooth has replay protection** (sequence number checking)
- [ ] **Bluetooth has versioning** (wire format version field)
- [ ] **No direct crypto calls** from protocols (CI enforced)

---

## Implementation Phases

### Phase 1: Update ProtocolEncryption Trait for AAD & Stateless Design ✅ COMPLETED

**File**: `lib-network/src/encryption/mod.rs`

**Status**: ✅ COMPLETE - 19/19 tests passing (with FCIS architecture applied)

#### 1.1 Functional Core / Imperative Shell (FCIS) Architecture

The encryption module applies strict FCIS separation for security auditability:

**Functional Core** (Pure Cryptography - Lines 242-301):
```rust
// No side effects, no logging, no state mutation
fn encrypt_core(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>>
fn decrypt_core(ciphertext: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>>
```

Properties:
- ✅ **Deterministic**: Same inputs = predictable outputs
- ✅ **Auditable**: All crypto is in one place, easy to review
- ✅ **Testable**: Can test without observability overhead
- ✅ **Secure**: Reduced attack surface vs mixed concerns

**Imperative Shell** (Observability & Operations - Lines 339-446):
```rust
impl ProtocolEncryption for ChaCha20Poly1305Encryption {
    fn encrypt(&self, ...) { /* SHELL: logging, stats */ }
    fn decrypt(&self, ...) { /* SHELL: logging, stats */ }
}
```

Responsibilities:
- **Logging**: Debug/warn for troubleshooting
- **Statistics**: Atomic counters (no locks)
- **Error Context**: Enhanced error messages
- **Thread-Safety**: Atomic operations only

Benefits:
1. Crypto logic is pure and auditable
2. Stats don't interfere with security-critical paths
3. Easy to swap shells (add metrics, tracing, etc.)
4. Reduced cognitive load when reviewing crypto code

#### 1.2 Test Suite Structure

**Functional Core Tests** (4 tests, ~62 lines):
- `test_functional_core_encrypt_decrypt()` - Pure crypto roundtrip
- `test_functional_core_deterministic()` - Determinism verification
- `test_functional_core_aad_validation()` - Domain separation (CORE level)
- `test_functional_core_authentication()` - AEAD tag validation

**Shell Tests** (11 tests, ~275 lines):
- Basic encrypt/decrypt (updated for AAD)
- Protocol-specific tests (LoRaWAN, WiFi Direct, QUIC)
- Statistics tracking
- Large/empty payloads
- Error handling

**Security Tests** (4 tests, ~60 lines):
- `test_aad_domain_separation()` - AAD mismatch detection
- `test_corrupted_ciphertext_detection()` - Tampering detection
- `test_cross_protocol_ciphertext_rejection()` - **CRITICAL**: Proves protocols can't decrypt each other's messages
- `test_empty_aad()` - Edge case handling

**Total**: 19/19 tests passing

#### 1.3 Changes

1. **Update trait signature**:
```rust
pub trait ProtocolEncryption: Send + Sync {
    /// Encrypt with domain separation via AAD
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt with domain separation via AAD
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    fn protocol(&self) -> &str;
    fn stats(&self) -> EncryptionStats;
    fn reset_stats(&mut self);
}
```

2. **Update ChaCha20Poly1305Encryption to be stateless**:
```rust
pub struct ChaCha20Poly1305Encryption {
    key: [u8; 32],
    protocol_name: String,
    stats: EncryptionStatsAtomic,  // Atomics only, no mut state
}

impl ProtocolEncryption for ChaCha20Poly1305Encryption {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Update atomic stats
        self.stats.messages_encrypted.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_encrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        // Call lib_crypto with AAD
        let ciphertext = lib_crypto::symmetric::chacha20::encrypt_data_with_aad(
            plaintext,
            &self.key,
            aad
        )?;

        debug!(
            protocol = %self.protocol_name,
            plaintext_len = plaintext.len(),
            aad_len = aad.len(),
            "Encrypted with ChaCha20Poly1305 AEAD"
        );

        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // Call lib_crypto with AAD
        let plaintext = lib_crypto::symmetric::chacha20::decrypt_data_with_aad(
            ciphertext,
            &self.key,
            aad
        ).context("ChaCha20Poly1305 AEAD decryption failed")?;

        // Update atomic stats
        self.stats.messages_decrypted.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_decrypted.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        Ok(plaintext)
    }
}
```

**Lines Changed**: ~50

---

### Phase 2: Protocol-Specific Adapters (New Files)

Create specialized encryption adapters that implement `ProtocolEncryption` while handling protocol-specific needs.

#### 2.1 Bluetooth Adapter ✅ COMPLETE

**Status**: ✅ **9/9 TESTS PASSING**

**File**: `lib-network/src/protocols/bluetooth_encryption.rs` (~510 lines)

**Implementation**: FCIS architecture with `mod core` and `mod shell`

**Core Features**:
- **Wire Format**: Version(1) + Flags(1) + Nonce(12) + Sequence(8) + Ciphertext + Tag(16)
- **Deterministic Nonce**: HKDF-SHA256 derived from (session_id, sequence, direction)
- **Replay Protection**: Per-peer sequence tracking with `HashMap<[u8; 16], Option<u64>>`
- **Domain Separation**: AAD includes protocol_id, version, session_id, sequence

**Test Results**:
```
✅ test_wire_format_serialization
✅ test_wire_format_deserialization
✅ test_nonce_derivation_determinism
✅ test_wire_format_version_rejection
✅ test_bluetooth_nonce_derivation_verified
✅ test_bluetooth_tampering_detection
✅ test_bluetooth_encrypt_decrypt
✅ test_bluetooth_replay_protection
✅ test_bluetooth_multiple_peers_replay_independent

test result: ok. 9 passed; 0 failed
```

**Security Properties Verified**:
- ✅ Deterministic nonce derivation (same inputs → same nonce)
- ✅ Replay protection (rejects duplicate sequence numbers per peer)
- ✅ Tampering detection (AEAD tag validation)
- ✅ Wire format versioning (rejects unknown versions)
- ✅ Domain separation (AAD prevents cross-protocol attacks)
- ✅ Multiple peer support (independent replay tracking per peer)

**Key Implementation Details**:
1. **Functional Core** (Lines 109-170):
   - `derive_nonce()`: HKDF-SHA256 deterministic nonce
   - `build_aad()`: Domain separation vector
   - `encrypt_core()` / `decrypt_core()`: Templates for crypto operations

2. **Imperative Shell** (Lines 176-319):
   - `BluetoothEncryption` struct with thread-safe atomics
   - `encrypt_message()`: Frame serialization + sequence tracking
   - `decrypt_message()`: Replay protection + frame deserialization
   - `ProtocolEncryption` trait implementation

3. **Frame Structure**:
   - Serialization: Pack all fields into wire format
   - Deserialization: Parse and validate version
   - Nonce embedded for verification (defense-in-depth)

**Bug Fixes**:
- Removed redundant nonce verification in decrypt (AEAD tag already authenticates it)
- Fixed replay protection to use `Option<u64>` for first-message handling

---

#### 2.2 ZHTP Mesh Adapter ✅ COMPLETE

**Status**: ✅ **12/12 TESTS PASSING**

**File**: `lib-network/src/protocols/zhtp_mesh_encryption.rs` (~400 lines)

**Implementation**: FCIS architecture with `mod core` and `mod shell`

**Core Features**:
- **Message-Type Aware AAD**: Different message types produce different AAD
- **Session Separation**: Per-session AAD ensures different sessions can't decrypt each other
- **Stateless Design**: No locks, no sequence tracking (higher-layer responsibility)
- **Domain Separation**: AAD format = `zhtp-mesh\0v1\0<message_type>\0<session_id>`

**Test Results**:
```
✅ test_aad_construction
✅ test_aad_session_separation
✅ test_aad_determinism
✅ test_zhtp_encrypt_decrypt
✅ test_zhtp_message_type_separation
✅ test_zhtp_session_separation
✅ test_zhtp_tampering_detection
✅ test_zhtp_empty_message
✅ test_zhtp_large_message (1MB)
✅ test_zhtp_protocol_encryption_trait
✅ test_zhtp_multiple_message_types
✅ test_zhtp_wrong_message_type_comprehensive

test result: ok. 12 passed; 0 failed
```

**Security Properties Verified**:
- ✅ AAD determinism (same inputs → same AAD)
- ✅ Message-type separation (different types can't be interchanged)
- ✅ Session separation (different sessions can't decrypt each other)
- ✅ Tampering detection (AEAD tag validation)
- ✅ Comprehensive wrong-type rejection (9 different wrong types tested)
- ✅ Large message support (1MB+ messages)

**Key Implementation Details**:
1. **Functional Core** (Lines 45-62):
   - `build_aad()`: Deterministic AAD construction with separators

2. **Imperative Shell** (Lines 68-157):
   - `ZhtpMeshEncryption` struct wrapping `ChaCha20Poly1305Encryption`
   - `encrypt_message()` / `decrypt_message()`: Message-type interface
   - `ProtocolEncryption` trait implementation for compatibility

3. **AAD Structure**:
   - Protocol ID ensures protocol isolation
   - Message type prevents cross-type attacks
   - Session ID ensures per-session isolation
   - Null separators prevent concatenation attacks

**Design Rationale**:
- **Stateless**: ZHTP relies on higher-layer replay protection (mesh sequence numbers)
- **Message-Type Aware**: Allows secure use of same key for different message kinds
- **Simple Wrapper**: Focuses on AAD construction without adding protocol-specific features

#### 2.3 WiFi Direct Adapter ✅ COMPLETE

**Status**: ✅ **17/17 TESTS PASSING**

**File**: `lib-network/src/protocols/wifi_direct_encryption.rs` (~480 lines)

**Implementation**: FCIS architecture with enum-based state management

**Core Features**:
- **Dual-Mode Operation**: End-to-end AEAD or link-layer only fallback
- **Transparent State**: Explicit enum shows operational mode
- **Graceful Fallback**: No silent failures, warnings indicate mode
- **Message-Type Aware AAD**: Different message types produce different AAD

**State Management**:
```rust
pub enum WiFiDirectEncryptionState {
    EndToEndAead(ChaCha20Poly1305Encryption),  // Full E2E encryption
    LinkLayerOnly,                             // OS handles WPA2/3
}
```

**Test Results**:
```
✅ test_aad_construction
✅ test_aad_determinism
✅ test_wifi_e2e_encrypt_decrypt
✅ test_wifi_e2e_message_type_separation
✅ test_wifi_e2e_tampering_detection
✅ test_wifi_fallback_is_not_e2e
✅ test_wifi_fallback_pass_through
✅ test_wifi_fallback_no_processing
✅ test_wifi_fallback_multiple_messages
✅ test_wifi_trait_e2e_mode
✅ test_wifi_trait_fallback_mode
✅ test_wifi_stats_e2e
✅ test_wifi_stats_fallback
✅ test_wifi_e2e_large_message (1MB)
✅ test_wifi_e2e_empty_message
✅ test_wifi_multiple_message_types
✅ (encryption module integration test)

test result: ok. 17 passed; 0 failed
```

**Security Properties Verified**:
- ✅ End-to-end encryption when session key available
- ✅ Message-type separation (can't interchange message types)
- ✅ Tampering detection (AEAD tag validation)
- ✅ Graceful fallback to link-layer only
- ✅ Transparent state tracking (`is_e2e_encrypted()`)
- ✅ Large message support (1MB+)
- ✅ ProtocolEncryption trait implementation in both modes

**Key Implementation Details**:
1. **Functional Core** (Lines 76-90):
   - `build_aad()`: Deterministic AAD construction

2. **Imperative Shell** (Lines 102-246):
   - `WiFiDirectEncryption` struct with state enum
   - `encrypt_message()` / `decrypt_message()`: Message-type interface
   - State-aware `ProtocolEncryption` trait implementation
   - Explicit logging of mode transitions

3. **Design Rationale**:
   - **Dual Mode**: Supports both secure sessions and fallback scenarios
   - **Transparent**: No hidden behavior - state is explicit
   - **Graceful**: Warnings indicate reduced security in fallback mode
   - **OS Integration**: Can leverage kernel WPA2/3 when available

---

#### 2.2.OLD ZHTP Mesh Adapter (Simplest - Custom Protocol)

**New File**: `lib-network/src/protocols/zhtp_mesh_encryption.rs`

**Note**: Renamed from "LoRaWAN" because this is NOT real LoRaWAN (doesn't use AES-based LoRaWAN crypto).

```rust
use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;

/// ZHTP mesh encryption with domain separation
pub struct ZhtpMeshEncryption {
    inner: ChaCha20Poly1305Encryption,
}

impl ZhtpMeshEncryption {
    pub fn new(app_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            inner: ChaCha20Poly1305Encryption::new("zhtp-mesh", app_key)?,
        })
    }

    /// Build AAD for domain separation
    fn build_aad(&self, message_type: &str, session_id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"zhtp-mesh");  // protocol_id
        aad.push(0x00);  // separator
        aad.extend_from_slice(message_type.as_bytes());  // message_type
        aad.push(0x00);  // separator
        aad.extend_from_slice(b"v1");  // version
        aad.push(0x00);  // separator
        aad.extend_from_slice(session_id);  // session_id
        aad
    }

    pub fn encrypt_message(&self, plaintext: &[u8], message_type: &str, session_id: &[u8]) -> Result<Vec<u8>> {
        let aad = self.build_aad(message_type, session_id);
        self.inner.encrypt(plaintext, &aad)
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], message_type: &str, session_id: &[u8]) -> Result<Vec<u8>> {
        let aad = self.build_aad(message_type, session_id);
        self.inner.decrypt(ciphertext, &aad)
    }
}

impl ProtocolEncryption for ZhtpMeshEncryption {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext, aad)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext, aad)
    }

    fn protocol(&self) -> &str { "zhtp-mesh" }
    fn stats(&self) -> EncryptionStats { self.inner.stats() }
    fn reset_stats(&mut self) { self.inner.reset_stats() }
}
```

**Lines**: ~60

#### 2.2 WiFi Direct Adapter (with Explicit Fallback State)

**New File**: `lib-network/src/protocols/wifi_direct_encryption.rs`

```rust
use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::Result;

/// WiFi Direct encryption state
pub enum WiFiDirectEncryptionState {
    /// End-to-end AEAD encryption (UHP session established)
    EndToEndAead(ChaCha20Poly1305Encryption),
    /// Link-layer only (WPA2/3 managed by OS, no E2E secrecy)
    LinkLayerOnly,
}

pub struct WiFiDirectEncryption {
    state: WiFiDirectEncryptionState,
}

impl WiFiDirectEncryption {
    pub fn new_with_session_key(session_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            state: WiFiDirectEncryptionState::EndToEndAead(
                ChaCha20Poly1305Encryption::new("wifi-direct", session_key)?
            ),
        })
    }

    pub fn new_fallback() -> Self {
        warn!("⚠️  WiFi Direct running in LINK-LAYER-ONLY mode (no E2E encryption)");
        Self {
            state: WiFiDirectEncryptionState::LinkLayerOnly,
        }
    }

    pub fn is_e2e_encrypted(&self) -> bool {
        matches!(self.state, WiFiDirectEncryptionState::EndToEndAead(_))
    }

    fn build_aad(&self, message_type: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"wifi-direct");
        aad.push(0x00);
        aad.extend_from_slice(message_type.as_bytes());
        aad.push(0x00);
        aad.extend_from_slice(b"v1");
        aad
    }

    pub fn encrypt_message(&self, plaintext: &[u8], message_type: &str) -> Result<Vec<u8>> {
        match &self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => {
                let aad = self.build_aad(message_type);
                enc.encrypt(plaintext, &aad)
            }
            WiFiDirectEncryptionState::LinkLayerOnly => {
                warn!("⚠️  WiFi Direct: Sending plaintext (link-layer only)");
                Ok(plaintext.to_vec())  // OS handles WPA2/3
            }
        }
    }

    pub fn decrypt_message(&self, ciphertext: &[u8], message_type: &str) -> Result<Vec<u8>> {
        match &self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => {
                let aad = self.build_aad(message_type);
                enc.decrypt(ciphertext, &aad)
            }
            WiFiDirectEncryptionState::LinkLayerOnly => {
                Ok(ciphertext.to_vec())
            }
        }
    }
}

impl ProtocolEncryption for WiFiDirectEncryption {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match &self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => enc.encrypt(plaintext, aad),
            WiFiDirectEncryptionState::LinkLayerOnly => {
                error!("⚠️  WiFi Direct: encrypt() called in link-layer-only mode");
                Ok(plaintext.to_vec())
            }
        }
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match &self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => enc.decrypt(ciphertext, aad),
            WiFiDirectEncryptionState::LinkLayerOnly => Ok(ciphertext.to_vec()),
        }
    }

    fn protocol(&self) -> &str { "wifi-direct" }
    fn stats(&self) -> EncryptionStats {
        match &self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => enc.stats(),
            WiFiDirectEncryptionState::LinkLayerOnly => EncryptionStats::default(),
        }
    }
    fn reset_stats(&mut self) {
        match &mut self.state {
            WiFiDirectEncryptionState::EndToEndAead(enc) => enc.reset_stats(),
            WiFiDirectEncryptionState::LinkLayerOnly => {}
        }
    }
}
```

**Lines**: ~110

#### 1.3 QUIC Adapter

**New File**: `lib-network/src/protocols/quic_encryption.rs`

```rust
pub struct QuicApplicationEncryption {
    inner: ChaCha20Poly1305Encryption,
    session_id: [u8; 16],
}

impl QuicApplicationEncryption {
    pub fn new(master_key: &[u8; 32], session_id: [u8; 16]) -> Result<Self> {
        Ok(Self {
            inner: ChaCha20Poly1305Encryption::new("quic", master_key)?,
            session_id,
        })
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
}

impl ProtocolEncryption for QuicApplicationEncryption {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext)
    }

    fn protocol(&self) -> &str { "quic" }
    fn stats(&self) -> EncryptionStats { self.inner.stats() }
    fn reset_stats(&mut self) { self.inner.reset_stats() }
}
```

**Lines**: ~50

#### 2.3 Bluetooth Adapter (CRITICAL SECURITY FIX - Full Wire Format)

**New File**: `lib-network/src/protocols/bluetooth/bluetooth_encryption.rs`

```rust
use crate::encryption::{ProtocolEncryption, ChaCha20Poly1305Encryption, EncryptionStats};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::RwLock;

const PROTOCOL_VERSION: u8 = 0x01;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const SEQ_SIZE: usize = 8;
const HEADER_SIZE: usize = 1 + 1 + NONCE_SIZE + SEQ_SIZE;  // version + flags + nonce + seq = 22

/// Bluetooth encrypted frame format
#[derive(Debug)]
pub struct BluetoothFrame {
    pub version: u8,
    pub flags: u8,
    pub nonce: [u8; NONCE_SIZE],
    pub sequence: u64,
    pub ciphertext: Vec<u8>,  // Includes 16-byte tag
}

impl BluetoothFrame {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.ciphertext.len());
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE + TAG_SIZE {
            return Err(anyhow!("Frame too short: {} bytes", data.len()));
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(anyhow!("Unsupported protocol version: 0x{:02x}", version));
        }

        let flags = data[1];
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[2..14]);
        let sequence = u64::from_be_bytes(data[14..22].try_into()?);
        let ciphertext = data[22..].to_vec();

        Ok(Self {
            version,
            flags,
            nonce,
            sequence,
            ciphertext,
        })
    }
}

pub struct BluetoothEncryption {
    inner: ChaCha20Poly1305Encryption,
    session_id: [u8; 16],
    send_sequence: std::sync::atomic::AtomicU64,
    recv_sequences: RwLock<HashMap<[u8; 16], u64>>,  // peer_id -> last_seen_seq
}

impl BluetoothEncryption {
    pub fn new(session_key: &[u8; 32], session_id: [u8; 16]) -> Result<Self> {
        Ok(Self {
            inner: ChaCha20Poly1305Encryption::new("bluetooth", session_key)?,
            session_id,
            send_sequence: std::sync::atomic::AtomicU64::new(0),
            recv_sequences: RwLock::new(HashMap::new()),
        })
    }

    /// Derive deterministic nonce from session_id, sequence, direction
    fn derive_nonce(&self, sequence: u64, direction: u8) -> Result<[u8; NONCE_SIZE]> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(b"bluetooth-nonce-v1");
        hasher.update(&self.session_id);
        hasher.update(&sequence.to_be_bytes());
        hasher.update(&[direction]);  // 0x00 = send, 0x01 = recv

        let hash = hasher.finalize();
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&hash[..NONCE_SIZE]);
        Ok(nonce)
    }

    fn build_aad(&self, sequence: u64) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(b"bluetooth");
        aad.push(0x00);
        aad.extend_from_slice(b"v1");
        aad.push(0x00);
        aad.extend_from_slice(&self.session_id);
        aad.push(0x00);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad
    }

    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sequence = self.send_sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nonce = self.derive_nonce(sequence, 0x00)?;  // direction = send
        let aad = self.build_aad(sequence);

        // Encrypt with ChaCha20Poly1305 AEAD
        let ciphertext = self.inner.encrypt(plaintext, &aad)?;

        let frame = BluetoothFrame {
            version: PROTOCOL_VERSION,
            flags: 0x00,  // No special flags
            nonce,
            sequence,
            ciphertext,
        };

        Ok(frame.serialize())
    }

    pub fn decrypt_message(&self, frame_data: &[u8], peer_id: &[u8; 16]) -> Result<Vec<u8>> {
        let frame = BluetoothFrame::deserialize(frame_data)?;

        // Replay protection: check sequence number
        {
            let mut recv_seqs = self.recv_sequences.write().unwrap();
            let last_seen = recv_seqs.entry(*peer_id).or_insert(0);

            if frame.sequence <= *last_seen {
                return Err(anyhow!(
                    "Replay attack detected: seq {} <= last_seen {}",
                    frame.sequence,
                    last_seen
                ));
            }

            *last_seen = frame.sequence;
        }

        // Verify nonce derivation
        let expected_nonce = self.derive_nonce(frame.sequence, 0x01)?;  // direction = recv
        if frame.nonce != expected_nonce {
            return Err(anyhow!("Nonce mismatch: possible tampering"));
        }

        let aad = self.build_aad(frame.sequence);
        self.inner.decrypt(&frame.ciphertext, &aad)
    }
}

impl ProtocolEncryption for BluetoothEncryption {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext, aad)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext, aad)
    }

    fn protocol(&self) -> &str { "bluetooth" }
    fn stats(&self) -> EncryptionStats { self.inner.stats() }
    fn reset_stats(&mut self) { self.inner.reset_stats() }
}
```

**Lines**: ~180 (includes wire format, nonce derivation, replay protection)

#### 1.5 ZHTP Adapter

**New File**: `lib-network/src/protocols/zhtp_encryption_adapter.rs`

```rust
pub struct ZhtpMeshEncryption {
    inner: ChaCha20Poly1305Encryption,
    kyber_derived: bool,
}

impl ZhtpMeshEncryption {
    pub fn new_from_kyber(shared_secret: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            inner: ChaCha20Poly1305Encryption::new("zhtp", shared_secret)?,
            kyber_derived: true,
        })
    }
}

impl ProtocolEncryption for ZhtpMeshEncryption {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext)
    }

    fn protocol(&self) -> &str { "zhtp" }
    fn stats(&self) -> EncryptionStats { self.inner.stats() }
    fn reset_stats(&mut self) { self.inner.reset_stats() }
}
```

**Lines**: ~40

---

### Phase 2: Refactor Protocols to Use Adapters

#### 2.1 LoRaWAN Protocol Refactoring

**File**: `lib-network/src/protocols/lorawan.rs`

**Changes**:

1. **Add import** (top of file):
```rust
use crate::protocols::lorawan_encryption::LoRaWANEncryption;
```

2. **Update struct** (around line 460):
```rust
// OLD
pub struct LoRaWANMeshProtocol {
    pub app_key: [u8; 32],
    // ...
}

// NEW
pub struct LoRaWANMeshProtocol {
    encryption: Arc<RwLock<LoRaWANEncryption>>,
    // ... other fields
}
```

3. **Update constructor**:
```rust
pub fn new(node_id: [u8; 32], public_key: &[u8]) -> Result<Self> {
    let app_key = Self::derive_app_key(&node_id);
    let encryption = Arc::new(RwLock::new(LoRaWANEncryption::new(&app_key)?));

    Ok(Self {
        encryption,
        // ...
    })
}
```

4. **Replace encrypt_payload** (line 547):
```rust
// OLD
async fn encrypt_payload(&self, payload: &[u8], frame_counter: u16) -> Result<Vec<u8>> {
    let encrypted = encrypt_data(payload, &self.app_key)?;
    // ...
}

// NEW
async fn encrypt_payload(&self, payload: &[u8], frame_counter: u16) -> Result<Vec<u8>> {
    let encrypted = self.encryption.write().await.encrypt(payload)?;
    // ...
}
```

**Lines Changed**: ~50

#### 2.2 WiFi Direct Protocol Refactoring

**File**: `lib-network/src/protocols/wifi_direct.rs`

**Changes**:

1. **Add import**:
```rust
use crate::protocols::wifi_direct_encryption::WiFiDirectEncryption;
```

2. **Update struct** (around line 3000):
```rust
// Remove session_key field, replace with encryption
encryption: Arc<RwLock<WiFiDirectEncryption>>,
```

3. **Replace encryption call** (line 3046):
```rust
// OLD
let encrypted_message = if let Some(session_key) = &device.session_key {
    encrypt_data(message, session_key)?
} else {
    message.to_vec()
};

// NEW
let encrypted_message = {
    let mut enc = self.encryption.write().await;
    enc.encrypt(message)?
};
```

**Lines Changed**: ~30

#### 2.3 QUIC Protocol Refactoring

**File**: `lib-network/src/protocols/quic_mesh.rs`

**Changes**:

1. **Add import**:
```rust
use crate::protocols::quic_encryption::QuicApplicationEncryption;
```

2. **Update PqcQuicConnection struct**:
```rust
pub struct PqcQuicConnection {
    encryption: QuicApplicationEncryption,
    // ...
}
```

3. **Replace encrypt_data calls** (lines 872, 899):
```rust
// OLD
let encrypted = encrypt_data(message, &master_key)?;

// NEW
let encrypted = self.encryption.encrypt(message)?;
```

**Lines Changed**: ~40

#### 2.4 Bluetooth Enhanced Refactoring (CRITICAL)

**File**: `lib-network/src/protocols/bluetooth/enhanced.rs`

**Changes**:

1. **Add import**:
```rust
use crate::protocols::bluetooth::bluetooth_encryption::BluetoothEncryption;
```

2. **Update struct** (lines 475-481):
```rust
// OLD
pub struct EnhancedWiFiDirectSecurity {
    #[cfg(feature = "aes")]
    aes_cipher: Option<Aes128>,
    #[cfg(feature = "cmac")]
    cmac_key: Option<Vec<u8>>,
}

// NEW
pub struct EnhancedWiFiDirectSecurity {
    encryption: Option<BluetoothEncryption>,
}
```

3. **Replace init_wpa3_sae** (lines 494-520):
```rust
pub fn init_wpa3_sae(&mut self, password: &str) -> Result<()> {
    // Derive 32-byte key using SHA256
    let mut hasher = Sha256::new();
    hasher.update(b"WPA3-SAE-KEY-DERIVATION");
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();
    let key: [u8; 32] = key_bytes.into();

    self.encryption = Some(BluetoothEncryption::new(&key)?);
    Ok(())
}
```

4. **DELETE INSECURE FUNCTIONS** (lines 522-569):
```rust
// DELETE ENTIRELY:
// - encrypt_p2p_message() (AES ECB)
// - generate_cmac_tag() (separate MAC)
```

5. **ADD SECURE FUNCTIONS**:
```rust
pub fn encrypt_p2p_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
    self.encryption
        .as_mut()
        .ok_or_else(|| anyhow!("Bluetooth encryption not initialized"))?
        .encrypt(data)
}

pub fn decrypt_p2p_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
    self.encryption
        .as_mut()
        .ok_or_else(|| anyhow!("Bluetooth encryption not initialized"))?
        .decrypt(data)
}
```

**Lines Changed**: ~100 (mostly deletions)

#### 2.5 ZHTP Encryption Refactoring

**File**: `lib-network/src/protocols/zhtp_encryption.rs`

**Changes**:

1. **Add import**:
```rust
use crate::protocols::zhtp_encryption_adapter::ZhtpMeshEncryption;
```

2. **Update ZhtpEncryptionSession struct**:
```rust
pub struct ZhtpEncryptionSession {
    encryption: Option<ZhtpMeshEncryption>,
    // ...
}
```

3. **Replace encrypt calls** (line 175):
```rust
// OLD
let ciphertext = encrypt_data(plaintext, &shared_secret)?;

// NEW
let ciphertext = self.encryption.as_mut()
    .ok_or_else(|| anyhow!("Session not established"))?
    .encrypt(plaintext)?;
```

**Lines Changed**: ~30

---

### Phase 3: Comprehensive Testing

#### 3.1 Add 4 New Unit Tests

**File**: `lib-network/src/encryption/mod.rs` (append to existing tests after line 561)

```rust
#[test]
fn test_bluetooth_encryption() {
    let key = [0x88u8; 32];
    let mut enc = ChaCha20Poly1305Encryption::new("bluetooth", &key).unwrap();

    let message = b"BLE mesh message";
    let encrypted = enc.encrypt(message).unwrap();
    let decrypted = enc.decrypt(&encrypted).unwrap();

    assert_eq!(message, &decrypted[..]);
    assert!(encrypted.len() > message.len()); // Includes nonce + tag
}

#[test]
fn test_corrupted_ciphertext() {
    let key = [0x99u8; 32];
    let mut enc = ChaCha20Poly1305Encryption::new("test", &key).unwrap();

    let plaintext = b"Important data";
    let mut ciphertext = enc.encrypt(plaintext).unwrap();

    // Tamper with MAC tag (last 16 bytes)
    let len = ciphertext.len();
    ciphertext[len - 1] ^= 0x01;

    let result = enc.decrypt(&ciphertext);
    assert!(result.is_err()); // Should detect tampering
}

#[test]
fn test_cross_protocol_domain_separation() {
    let key = [0xAAu8; 32];
    let enc1 = ChaCha20Poly1305Encryption::new("protocol1", &key).unwrap();
    let enc2 = ChaCha20Poly1305Encryption::new("protocol2", &key).unwrap();

    let message = b"Cross-protocol message";
    let aad1 = b"protocol1||msg||v1";
    let aad2 = b"protocol2||msg||v1";

    // Encrypt with protocol1's AAD
    let ct1 = enc1.encrypt(message, aad1).unwrap();

    // CRITICAL TEST: protocol2 must FAIL to decrypt protocol1's ciphertext
    let result = enc2.decrypt(&ct1, aad2);
    assert!(result.is_err(), "❌ SECURITY FAILURE: Cross-protocol decryption should FAIL");

    // Verify the error is authentication failure (AEAD tag mismatch)
    assert!(result.unwrap_err().to_string().contains("decryption failed"));
}

#[test]
fn test_concurrent_encryption() {
    use std::sync::Arc;
    use std::thread;

    let key = [0xBBu8; 32];
    let enc = Arc::new(RwLock::new(
        ChaCha20Poly1305Encryption::new("test", &key).unwrap()
    ));

    let mut handles = vec![];
    for i in 0..10 {
        let enc_clone = Arc::clone(&enc);
        handles.push(thread::spawn(move || {
            let mut guard = enc_clone.write().unwrap();
            let data = format!("message {}", i);
            let ct = guard.encrypt(data.as_bytes()).unwrap();
            guard.decrypt(&ct).unwrap()
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = enc.read().unwrap().stats();
    assert_eq!(stats.messages_encrypted, 10);
}
```

**Lines Added**: ~80
**Total Tests**: 11 existing + 4 new = **15 tests** ✅

#### 3.3 Bluetooth-Specific Security Tests

**File**: `lib-network/src/protocols/bluetooth/tests.rs`

```rust
#[test]
fn test_bluetooth_replay_protection() {
    let key = [0x44u8; 32];
    let session_id = [0xBBu8; 16];
    let peer_id = [0xCCu8; 16];
    let enc = BluetoothEncryption::new(&key, session_id).unwrap();

    let message = b"Test message";
    let frame1 = enc.encrypt_message(message).unwrap();

    // First decryption should succeed
    assert!(enc.decrypt_message(&frame1, &peer_id).is_ok());

    // CRITICAL: Replay same frame should FAIL
    let result = enc.decrypt_message(&frame1, &peer_id);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Replay attack"));
}

#[test]
fn test_bluetooth_nonce_determinism() {
    let key = [0x55u8; 32];
    let session_id = [0xDDu8; 16];
    let enc1 = BluetoothEncryption::new(&key, session_id).unwrap();
    let enc2 = BluetoothEncryption::new(&key, session_id).unwrap();

    let message = b"Test";
    let frame1 = enc1.encrypt_message(message).unwrap();
    let frame2 = enc2.encrypt_message(message).unwrap();

    // Parse frames
    let parsed1 = BluetoothFrame::deserialize(&frame1).unwrap();
    let parsed2 = BluetoothFrame::deserialize(&frame2).unwrap();

    // CRITICAL: Same session_id + sequence should produce same nonce
    assert_eq!(parsed1.nonce, parsed2.nonce);
    assert_eq!(parsed1.sequence, parsed2.sequence);
}

#[test]
fn test_bluetooth_version_rejection() {
    let mut invalid_frame = vec![0xFF, 0x00];  // version 0xFF (invalid)
    invalid_frame.extend_from_slice(&[0u8; 20]);  // padding

    let result = BluetoothFrame::deserialize(&invalid_frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported protocol version"));
}
```

**Lines Added**: ~50

#### 3.4 CI Guards to Prevent Direct lib_crypto Calls

**New File**: `.github/workflows/encryption-guard.yml`

```yaml
name: Encryption Security Guards

on: [push, pull_request]

jobs:
  prevent-direct-crypto-calls:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Check for direct lib_crypto calls in protocols
        run: |
          # Search for direct calls to lib_crypto::symmetric::chacha20::encrypt_data
          if grep -r "lib_crypto::symmetric::chacha20::encrypt_data" \
              lib-network/src/protocols/*.rs \
              lib-network/src/protocols/**/*.rs \
              2>/dev/null | grep -v "^Binary"; then
            echo "❌ SECURITY VIOLATION: Protocols must use ProtocolEncryption trait, not call lib_crypto directly"
            exit 1
          fi

          # Search for direct calls to lib_crypto::symmetric::chacha20::decrypt_data
          if grep -r "lib_crypto::symmetric::chacha20::decrypt_data" \
              lib-network/src/protocols/*.rs \
              lib-network/src/protocols/**/*.rs \
              2>/dev/null | grep -v "^Binary"; then
            echo "❌ SECURITY VIOLATION: Protocols must use ProtocolEncryption trait, not call lib_crypto directly"
            exit 1
          fi

          echo "✅ All protocols use ProtocolEncryption trait"

      - name: Check for AES ECB usage
        run: |
          # Search for insecure AES ECB mode
          if grep -r "encrypt_block\|Aes128\|BlockEncrypt" \
              lib-network/src/protocols/bluetooth/*.rs \
              2>/dev/null | grep -v "^Binary"; then
            echo "❌ SECURITY VIOLATION: AES ECB mode detected in Bluetooth"
            exit 1
          fi

          echo "✅ No insecure AES ECB usage found"
```

**Additional Rust-based CI Test**:

**File**: `lib-network/tests/ci_security_guards.rs`

```rust
#[test]
#[ignore]  // Run only in CI
fn test_no_direct_lib_crypto_calls_in_protocols() {
    use std::fs;
    use std::path::Path;

    let protocol_files = [
        "lib-network/src/protocols/lorawan.rs",
        "lib-network/src/protocols/wifi_direct.rs",
        "lib-network/src/protocols/quic_mesh.rs",
        "lib-network/src/protocols/bluetooth/enhanced.rs",
        "lib-network/src/protocols/zhtp_encryption.rs",
    ];

    for file_path in &protocol_files {
        let path = Path::new(file_path);
        if !path.exists() {
            continue;
        }

        let content = fs::read_to_string(path).unwrap();

        // Check for direct encrypt_data calls
        assert!(
            !content.contains("lib_crypto::symmetric::chacha20::encrypt_data"),
            "❌ SECURITY VIOLATION: {} calls lib_crypto::encrypt_data directly. Use ProtocolEncryption trait instead.",
            file_path
        );

        // Check for direct decrypt_data calls
        assert!(
            !content.contains("lib_crypto::symmetric::chacha20::decrypt_data"),
            "❌ SECURITY VIOLATION: {} calls lib_crypto::decrypt_data directly. Use ProtocolEncryption trait instead.",
            file_path
        );
    }
}
```

**Lines Added**: ~100

#### 3.2 Integration Tests

**New File**: `lib-network/tests/protocol_encryption_integration_test.rs`

```rust
use lib_network::protocols::{
    lorawan::LoRaWANMeshProtocol,
    bluetooth::BluetoothMeshProtocol,
    quic_mesh::PqcQuicConnection,
    wifi_direct::WiFiDirectProtocol,
};

#[tokio::test]
async fn test_bluetooth_secure_messaging() {
    // Verify Bluetooth no longer uses AES ECB
    let key = [0x22u8; 32];
    let mut bluetooth = BluetoothMeshProtocol::new_with_encryption(key).unwrap();

    let message = b"BLE secure message";
    let encrypted = bluetooth.encrypt_message(message).await.unwrap();

    // Verify AEAD (nonce + tag included)
    assert!(encrypted.len() > message.len());

    let decrypted = bluetooth.decrypt_message(&encrypted).await.unwrap();
    assert_eq!(message, &decrypted[..]);
}

#[tokio::test]
async fn test_all_protocols_use_chacha20() {
    // Verify all protocols converged on ChaCha20Poly1305

    let key = [0x33u8; 32];

    // Test each protocol
    let mut lorawan = LoRaWANMeshProtocol::new_with_key(key).unwrap();
    let mut wifi = WiFiDirectProtocol::new_with_session_key(key).unwrap();
    let mut quic = PqcQuicConnection::new_with_master_key(key, [0u8; 16]);
    let mut bluetooth = BluetoothMeshProtocol::new_with_encryption(key).unwrap();

    let message = b"Test message";

    // All should encrypt successfully
    assert!(lorawan.encrypt(message).await.is_ok());
    assert!(wifi.encrypt(message).await.is_ok());
    assert!(quic.encrypt(message).await.is_ok());
    assert!(bluetooth.encrypt(message).await.is_ok());
}
```

**Lines**: ~60

---

### Phase 4: Update Module Exports

**File**: `lib-network/src/protocols/mod.rs`

Add exports for new encryption adapters:

```rust
pub mod lorawan_encryption;
pub mod wifi_direct_encryption;
pub mod quic_encryption;
pub mod zhtp_encryption_adapter;

// Bluetooth encryption in separate module
pub mod bluetooth {
    pub mod bluetooth_encryption;
}
```

---

## Breaking Changes

### Wire Protocol Changes

**Bluetooth Enhanced Protocol**:
- **Old format**: `[AES-ECB ciphertext blocks][CMAC tag]`
- **New format**: `[12-byte nonce][ChaCha20 ciphertext][16-byte Poly1305 tag]`
- **Incompatibility**: Old clients CANNOT decrypt new messages (and vice versa)
- **Mitigation**: Hard cutover on release date, document in changelog

### API Changes

**Removed**:
- `lib_crypto::symmetric::chacha20::encrypt_data()` direct calls in protocols
- `MacOSBluetoothManager::encrypt_p2p_message()` (AES ECB implementation)
- `MacOSBluetoothManager::generate_cmac_tag()`
- `EnhancedWiFiDirectSecurity::aes_cipher` field
- `EnhancedWiFiDirectSecurity::cmac_key` field

**Changed**:
- All protocol structs now use `encryption: Arc<RwLock<T>>` or `encryption: T`
- Encryption is async (requires `.await` on lock acquisition)

---

## Critical Files Summary (UPDATED)

| File | Type | Lines | Risk | Priority |
|------|------|-------|------|----------|
| **Security Critical (Week 1)** |
| `lib-network/src/protocols/bluetooth/bluetooth_encryption.rs` | NEW | +180 | **CRITICAL** | **P0** |
| `lib-network/src/protocols/bluetooth/enhanced.rs` | MODIFY | ~100 (delete AES ECB) | **HIGH** | **P0** |
| `lib-network/src/protocols/bluetooth/tests.rs` | NEW | +50 | NONE | **P0** |
| **Trait & AAD (Week 2)** |
| `lib-network/src/encryption/mod.rs` | MODIFY | +100 | MEDIUM | P1 |
| `lib-crypto/src/symmetric/chacha20.rs` | MODIFY | +50 | MEDIUM | P1 |
| `lib-network/src/encryption/tests.rs` | NEW | +80 | NONE | P1 |
| **Protocol Adapters (Week 3)** |
| `lib-network/src/protocols/zhtp_mesh_encryption.rs` | NEW | +60 | LOW | P2 |
| `lib-network/src/protocols/wifi_direct_encryption.rs` | NEW | +110 | LOW | P2 |
| `lib-network/src/protocols/quic_encryption.rs` | NEW | +50 | LOW | P2 |
| `lib-network/src/protocols/lorawan.rs` | MODIFY | ~50 | MEDIUM | P2 |
| `lib-network/src/protocols/wifi_direct.rs` | MODIFY | ~30 | MEDIUM | P2 |
| `lib-network/src/protocols/quic_mesh.rs` | MODIFY | ~40 | MEDIUM | P2 |
| **CI Guards (Week 4)** |
| `.github/workflows/encryption-guard.yml` | NEW | +40 | NONE | P3 |
| `lib-network/tests/ci_security_guards.rs` | NEW | +50 | NONE | P3 |
| `lib-network/tests/protocol_encryption_integration_test.rs` | NEW | +60 | NONE | P3 |

**Total**: ~1050 lines (680 new, 370 modifications)

**P0 (Critical)**: Bluetooth security fix - MUST ship before any Bluetooth production use
**P1 (High)**: Core trait AAD support - Enables domain separation
**P2 (Medium)**: Protocol refactoring - Enables unified architecture
**P3 (Low)**: CI guards - Prevents regressions

---

## Success Criteria (UPDATED with Security Invariants)

### Security Invariants (MUST PASS)
- [ ] **Nonce uniqueness** guaranteed per (key, direction)
- [ ] **Decrypt fails on bit flip** (AEAD tag enforced)
- [ ] **Cross-protocol ciphertext rejected** (AAD domain separation) - Test FAILS to decrypt
- [ ] **Bluetooth has replay protection** (sequence number checking)
- [ ] **Bluetooth has versioning** (wire format version field 0x01)
- [ ] **No direct crypto calls** from protocols (CI enforced with grep + Rust test)
- [ ] **No AES ECB mode** anywhere in codebase (CI enforced)

### Functional Requirements
- [ ] Bluetooth Enhanced uses ChaCha20Poly1305 with full wire format
- [ ] All protocols implement/use `ProtocolEncryption` trait with AAD
- [ ] Trait uses `&self` (stateless) with atomic stats only
- [ ] 15+ unit tests passing (including domain separation test)
- [ ] 3+ Bluetooth security tests passing (replay, nonce, version)
- [ ] 2+ integration tests passing
- [ ] CI guards prevent direct lib_crypto calls
- [ ] All encryption statistics thread-safe (AtomicU64)

### Documentation
- [ ] Bluetooth wire format documented with frame diagram
- [ ] AAD format documented per protocol
- [ ] Migration guide for Bluetooth hard cutover
- [ ] Security properties documented (confidentiality, authenticity, replay protection)

---

## Implementation Order (REVISED - Security First)

### Week 1: ✅ COMPLETE - Trait & FCIS Implementation
1. ✅ **Update ProtocolEncryption trait** - Add AAD parameter, make stateless (&self)
2. ✅ **Apply FCIS architecture** - Separate functional core from imperative shell
3. ✅ **Functional core functions** - Pure `encrypt_core()` and `decrypt_core()`
4. ✅ **Enhanced tests** - 4 core tests + 15 shell tests + 4 security tests (19 total)
5. ✅ **Documentation** - FCIS architecture guide in module docs

### Week 2: Bluetooth Critical Security Fix (NEXT)
1. **Bluetooth wire format** - Define frame structure with version, nonce, sequence
2. **Nonce derivation** - Implement deterministic nonce from (session_id, seq, direction)
3. **Replay protection** - Sequence number checking per peer
4. **Replace AES ECB** - Delete insecure code, implement ChaCha20Poly1305 AEAD
5. **Tests** - Replay protection, nonce determinism, version rejection
6. **Hard cutover plan** - Document migration, update changelog

### Week 3: Core Trait & AAD Implementation
1. **Update ProtocolEncryption trait** - Add AAD parameter, make stateless (&self)
2. **Update ChaCha20Poly1305Encryption** - Support AAD, use atomics only
3. **lib_crypto changes** - Add `encrypt_data_with_aad()` and `decrypt_data_with_aad()`
4. **Domain separation tests** - Verify cross-protocol ciphertext FAILS

### Week 3: Protocol Refactoring
1. **Create protocol adapters** - ZHTP Mesh, WiFi Direct, QUIC
2. **Refactor protocols** - Use adapters with proper AAD
3. **Remove Arc<RwLock>** - Use stateless design or tokio::sync::RwLock
4. **Integration tests** - End-to-end protocol tests

### Week 4: CI Guards & Final Review
1. **CI workflow** - Add `.github/workflows/encryption-guard.yml`
2. **Rust CI tests** - Add `lib-network/tests/ci_security_guards.rs`
3. **Security audit** - Verify all invariants met
4. **Code review** - Final review before merge
5. **Documentation** - Update encryption guide with AAD examples

---

## Testing Strategy

### Unit Tests (15 total)
- 11 existing tests in `encryption/mod.rs`
- 4 new tests: Bluetooth, corrupted ciphertext, cross-protocol, concurrent

### Integration Tests (2 minimum)
- Bluetooth secure messaging (verifies ChaCha20Poly1305)
- All protocols use ChaCha20 (convergence test)

### Manual Testing
- Test Bluetooth connections before/after (expect incompatibility)
- Verify statistics tracking works
- Check logs for encryption errors

### Performance Testing
- Benchmark encryption throughput (expect no regression)
- Verify trait dispatch overhead < 1%

---

## Rollback Plan

If critical issues arise:

1. **Revert commits**:
```bash
git revert <commit-range>
```

2. **Emergency Bluetooth fix** (if needed):
   - Keep ChaCha20 code
   - Temporarily allow both AES and ChaCha via feature flag
   - Add version negotiation in handshake

3. **Gradual rollback**:
   - Phase 1: Revert protocol refactoring (keep adapters)
   - Phase 2: Revert Bluetooth fix (ONLY if absolutely necessary)
   - Phase 3: Full rollback to pre-refactoring state
