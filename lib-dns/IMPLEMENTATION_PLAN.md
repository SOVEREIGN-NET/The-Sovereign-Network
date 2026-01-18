# lib-dns Implementation Plan

> **Status:** IN PROGRESS / PARTIALLY COMPLETE
> **Last Updated:** 2026-01-17
> **Total Source Files:** 85 Rust files (~9,117 lines of code)

---

## Executive Summary

lib-dns is a comprehensive DNS library for the Sovereign Network's ZDNS (Zero Knowledge Domain Name System). While the core DNS protocol implementation is functional, several critical components remain incomplete, particularly around DNSSEC wire format serialization, transaction signing (TSIG), and the journal system for incremental zone transfers.

**Key Metrics:**
- **21 `todo!()` calls** requiring implementation
- **134 `unwrap()` calls** across 37 files needing error handling improvements
- **5 DNSSEC record types** with incomplete wire format implementations
- **1 major subsystem** (Journal) entirely stubbed

---

## Table of Contents

1. [Incomplete Wire Format Implementations](#1-incomplete-wire-format-implementations)
2. [TSIG (Transaction Signing) Completion](#2-tsig-transaction-signing-completion)
3. [Journal System Implementation](#3-journal-system-implementation)
4. [Missing Record Type Support](#4-missing-record-type-support)
5. [Error Handling Overhaul](#5-error-handling-overhaul)
6. [Utility Cleanup](#6-utility-cleanup)
7. [Test Coverage Expansion](#7-test-coverage-expansion)
8. [TCP Chunking Validation](#8-tcp-chunking-validation)
9. [Documentation](#9-documentation)

---

## 1. Incomplete Wire Format Implementations

### Overview

Several DNSSEC-related record types have `from_bytes()` and `to_bytes()` implementations working, but their wire format counterparts (`from_wire_len()` and `to_wire()`) are stubbed with `todo!()`.

### 1.1 DS (Delegation Signer) Record - RFC 4034

**File:** `lib-dns/src/rr_data/ds_rr_data.rs`

**Current State:**
- Lines 88, 95: Both `from_wire_len()` and `to_wire()` return `todo!()`
- `from_bytes()` stub returns empty/default values (line 32-44)
- `to_bytes()` returns empty buffer (line 46-50)

**Required Implementation:**

```rust
// from_wire_len (line 88)
fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
    if len < 4 {
        return Err(WireError::Truncated("DS record too short".into()));
    }
    let key_tag = u16::from_wire(context)?;
    let algorithm = u8::from_wire(context)?;
    let digest_type = u8::from_wire(context)?;
    let digest = context.take((len - 4) as usize)?.to_vec();

    Ok(Self { key_tag, algorithm, digest_type, digest })
}

// to_wire (line 95)
fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
    self.key_tag.to_wire(context)?;
    self.algorithm.to_wire(context)?;
    self.digest_type.to_wire(context)?;
    context.write(&self.digest)
}
```

**Also fix `from_bytes()` and `to_bytes()`** which currently don't parse/serialize data.

**Priority:** HIGH (Required for DNSSEC delegation chain validation)

---

### 1.2 SSHFP (SSH Fingerprint) Record - RFC 4255

**File:** `lib-dns/src/rr_data/sshfp_rr_data.rs`

**Current State:**
- Lines 113, 120: Both wire format methods return `todo!()`
- `from_bytes()` and `to_bytes()` are correctly implemented (lines 32-54)

**Required Implementation:**

```rust
// from_wire_len (line 113)
fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
    if len < 2 {
        return Err(WireError::Truncated("SSHFP record too short".into()));
    }
    let algorithm = u8::from_wire(context)?;
    let fingerprint_type = u8::from_wire(context)?;
    let fingerprint = context.take((len - 2) as usize)?.to_vec();

    Ok(Self { algorithm, fingerprint_type, fingerprint })
}

// to_wire (line 120)
fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
    self.algorithm.to_wire(context)?;
    self.fingerprint_type.to_wire(context)?;
    context.write(&self.fingerprint)
}
```

**Priority:** MEDIUM (Used for SSH host key verification via DNS)

---

### 1.3 NSEC (Next Secure) Record - RFC 4034

**File:** `lib-dns/src/rr_data/nsec_rr_data.rs`

**Current State:**
- Lines 165, 172: Both wire format methods return `todo!()`
- `from_bytes()` and `to_bytes()` are fully implemented (lines 30-109)
- Zone file parsing works correctly

**Required Implementation:**

```rust
// from_wire_len (line 165)
fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
    let start_pos = context.pos();
    let next_domain = context.name()?;
    let name_len = context.pos() - start_pos;

    let mut types = Vec::new();
    let mut remaining = len as usize - name_len;

    while remaining > 0 {
        if remaining < 2 {
            return Err(WireError::Truncated("truncated NSEC window header".into()));
        }
        let window = u8::from_wire(context)?;
        let bitmap_len = u8::from_wire(context)? as usize;
        remaining -= 2;

        if bitmap_len == 0 || bitmap_len > 32 || bitmap_len > remaining {
            return Err(WireError::Format("invalid NSEC bitmap length".into()));
        }

        let bitmap = context.take(bitmap_len)?;
        remaining -= bitmap_len;

        for (i, &byte) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (byte & (1 << (7 - bit))) != 0 {
                    let type_num = (window as u16) * 256 + (i as u16 * 8 + bit as u16);
                    if let Ok(rtype) = RRTypes::try_from(type_num) {
                        types.push(rtype);
                    }
                }
            }
        }
    }

    Ok(Self { next_domain: Some(next_domain), types })
}

// to_wire (line 172) - Reuse logic from to_bytes()
fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
    context.write_name(self.next_domain.as_ref().unwrap_or(&String::new()), true)?;

    // Build and write type bitmap windows (same logic as to_bytes)
    let mut windows: Vec<Vec<u8>> = vec![Vec::new(); 256];
    for rtype in &self.types {
        let code = rtype.code();
        let w = (code >> 8) as usize;
        let low = (code & 0xFF) as u8;
        let byte_i = (low >> 3) as usize;
        let bit_in_byte = 7 - (low & 0x07);

        let bm = &mut windows[w];
        if bm.len() <= byte_i {
            bm.resize(byte_i + 1, 0);
        }
        bm[byte_i] |= 1 << bit_in_byte;
    }

    for (win, bm) in windows.into_iter().enumerate() {
        let mut used = bm.len();
        while used > 0 && bm[used - 1] == 0 {
            used -= 1;
        }
        if used == 0 { continue; }

        (win as u8).to_wire(context)?;
        (used as u8).to_wire(context)?;
        context.write(&bm[..used])?;
    }

    Ok(())
}
```

**Priority:** HIGH (Required for DNSSEC authenticated denial of existence)

---

### 1.4 NSEC3 Record - RFC 5155

**File:** `lib-dns/src/rr_data/nsec3_rr_data.rs`

**Current State:**
- Line 307: `to_wire()` returns `todo!()`
- `from_wire_len()` (lines 247-301) is **partially implemented** - reads basic fields but type bitmap parsing is commented out
- `from_bytes()` and `to_bytes()` are fully implemented

**Required Implementation:**

```rust
// Complete from_wire_len type bitmap parsing (uncomment and fix lines 260-290)
// After reading salt and next_hash, add:
let bitmap_start = 1 + 1 + 2 + 1 + salt_length + 1 + next_hash_length;
let mut remaining = (len as usize).saturating_sub(bitmap_start);

while remaining >= 2 {
    let window = u8::from_wire(context)?;
    let bitmap_len = u8::from_wire(context)? as usize;
    remaining -= 2;

    if bitmap_len == 0 || bitmap_len > 32 || bitmap_len > remaining {
        break;
    }

    let bitmap = context.take(bitmap_len)?;
    remaining -= bitmap_len;

    for (i, &byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if (byte & (1 << (7 - bit))) != 0 {
                let type_num = (window as u16) * 256 + (i as u16 * 8 + bit as u16);
                if let Ok(rtype) = RRTypes::try_from(type_num) {
                    types.push(rtype);
                }
            }
        }
    }
}

// to_wire (line 307)
fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
    self.algorithm.to_wire(context)?;
    self.flags.to_wire(context)?;
    self.iterations.to_wire(context)?;

    (self.salt.len() as u8).to_wire(context)?;
    context.write(&self.salt)?;

    (self.next_hash.len() as u8).to_wire(context)?;
    context.write(&self.next_hash)?;

    // Write type bitmap (same logic as NSEC)
    // ... (reuse window building logic from to_bytes)

    Ok(())
}
```

**Priority:** HIGH (Required for DNSSEC NSEC3 hashed denial of existence)

---

## 2. TSIG (Transaction Signing) Completion

**File:** `lib-dns/src/messages/tsig.rs`

### Current State

- Line 129: `from_wire_len()` returns `todo!()` after building `signed_payload`
- The signed payload construction (lines 93-117) is implemented but the function doesn't return a valid `TSig` struct
- `to_wire()` is fully implemented (lines 133-150)
- `verify()` and `sign()` methods work correctly (lines 61-70)

### Required Implementation

```rust
// from_wire_len (line 129) - Complete the return statement
fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
    let owner = context.name()?;
    let checkpoint = context.pos();

    let rtype = RRTypes::try_from(u16::from_wire(context)?)
        .map_err(|e| WireError::Format(e.to_string()))?;

    let class = u16::from_wire(context)?;
    let cache_flush = (class & 0x8000) != 0;
    let class = RRClasses::try_from(class)
        .map_err(|e| WireError::Format(e.to_string()))?;
    let ttl = u32::from_wire(context)?;

    let len = u16::from_wire(context)?;

    match len {
        0 => Ok(Self {
            owner,
            data: TSigRRData::default(),
            signed_payload: Vec::new()
        }),
        _ => {
            let data = TSigRRData::from_wire_len(context, len)?;

            // Build signed payload for verification
            let mut signed_payload = context.range(0..checkpoint)?.to_vec();
            signed_payload.extend_from_slice(&RRClasses::Any.code().to_be_bytes());
            signed_payload.extend_from_slice(&0u32.to_be_bytes());

            signed_payload.extend_from_slice(&pack_fqdn(&data.algorithm().as_ref()
                .ok_or_else(|| WireError::Format("algorithm param was not set".to_string()))?
                .to_string()));

            signed_payload.extend_from_slice(&[
                ((data.time_signed() >> 40) & 0xFF) as u8,
                ((data.time_signed() >> 32) & 0xFF) as u8,
                ((data.time_signed() >> 24) & 0xFF) as u8,
                ((data.time_signed() >> 16) & 0xFF) as u8,
                ((data.time_signed() >>  8) & 0xFF) as u8,
                ( data.time_signed()        & 0xFF) as u8
            ]);
            signed_payload.extend_from_slice(&data.fudge().to_be_bytes());
            signed_payload.extend_from_slice(&data.error().to_be_bytes());
            signed_payload.extend_from_slice(&(data.data().len() as u16).to_be_bytes());
            signed_payload.extend_from_slice(&data.data());

            Ok(Self {
                owner,
                data,
                signed_payload
            })
        }
    }
}
```

### Additional TSIG Tasks

1. **Test TSIG verification** with real DNS update packets
2. **Validate TCP chunking behavior** - Comment in code (line 45-46) questions whether TCP multi-part messages should repeat query
3. **Add TSIG error response handling** per RFC 2845

**Priority:** HIGH (Required for secure dynamic DNS updates and zone transfers)

---

## 3. Journal System Implementation

### Overview

The journal system for incremental zone transfers (IXFR) is largely stubbed. The reader exists but the main `Journal` struct cannot load transactions.

### 3.1 Journal.open() Implementation

**File:** `lib-dns/src/journal/journal.rs`

**Current State:**
- Line 31: `open()` returns `todo!()`
- Commented-out implementation shows intended design using `IndexMap<u32, Txn>`
- `JournalReader` in `journal_reader.rs` is fully implemented and can parse BIND9 journal files

**Required Implementation:**

```rust
use indexmap::IndexMap;  // Add to Cargo.toml: indexmap = "2.0"

#[derive(Debug, Clone)]
pub struct Journal {
    txns: IndexMap<u32, Txn>
}

impl Journal {
    pub fn new() -> Self {
        Self {
            txns: IndexMap::new()
        }
    }

    pub fn open(file_path: &str) -> io::Result<Self> {
        let mut txns = IndexMap::new();

        let mut reader = JournalReader::open(file_path)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        for txn_result in reader.txns() {
            let txn = txn_result
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            txns.insert(txn.serial_0(), txn);
        }

        Ok(Self { txns })
    }

    pub fn txns(&self) -> &IndexMap<u32, Txn> {
        &self.txns
    }

    pub fn txn(&self, serial: u32) -> Option<&Txn> {
        self.txns.get(&serial)
    }

    pub fn txns_from(&self, start: u32) -> impl Iterator<Item = (&u32, &Txn)> {
        self.txns.range(start..)
    }
}
```

### 3.2 Journal Writer (New)

**Required:** Create `lib-dns/src/journal/journal_writer.rs`

```rust
pub struct JournalWriter {
    file: File,
    header: JournalHeader,
}

impl JournalWriter {
    pub fn create(path: &str, origin: &str) -> io::Result<Self>;
    pub fn append_txn(&mut self, txn: &Txn) -> io::Result<()>;
    pub fn sync(&mut self) -> io::Result<()>;
}
```

### 3.3 Zone Writer (New)

**Required:** Create `lib-dns/src/zone/zone_writer.rs`

Complements the existing `zone_reader.rs` for writing zone files in RFC 1035 format.

**Priority:** MEDIUM (Required for IXFR support and zone persistence)

---

## 4. Missing Record Type Support

### 4.1 SPF Record Type

**Files to modify:**
- `lib-dns/src/zone/inter/zone_rr_data.rs` (line 78-80, commented out)
- `lib-dns/src/rr_data/inter/rr_data.rs` (lines 112-114, 160-162, 208-210)

**Current State:** SPF RRData struct exists (`spf_rr_data.rs`) but is not wired into factory methods.

**Required Changes:**

```rust
// In zone_rr_data.rs, uncomment and fix:
RRTypes::Spf => <SpfRRData as ZoneRRData>::upcast(SpfRRData::default()),

// In rr_data.rs, add to all three factory methods:
RRTypes::Spf => SpfRRData::default().upcast(),
RRTypes::Spf => SpfRRData::from_bytes(buf)?.upcast(),
RRTypes::Spf => SpfRRData::from_wire_len(context, len)?.upcast(),
```

**Priority:** LOW (SPF via TXT records is more common)

---

### 4.2 CAA (Certification Authority Authorization) Record

**Files to modify:**
- `lib-dns/src/zone/inter/zone_rr_data.rs` (lines 84-86, commented out)
- `lib-dns/src/rr_data/inter/rr_data.rs` (lines 118-120, 166-168, 214-216)

**Required:** Create `lib-dns/src/rr_data/caa_rr_data.rs`

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaaRRData {
    flags: u8,
    tag: String,      // "issue", "issuewild", "iodef"
    value: String,
}

impl RRData for CaaRRData {
    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let flags = buf[0];
        let tag_len = buf[1] as usize;
        let tag = String::from_utf8_lossy(&buf[2..2+tag_len]).to_string();
        let value = String::from_utf8_lossy(&buf[2+tag_len..]).to_string();
        Ok(Self { flags, tag, value })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::new();
        buf.push(self.flags);
        buf.push(self.tag.len() as u8);
        buf.extend_from_slice(self.tag.as_bytes());
        buf.extend_from_slice(self.value.as_bytes());
        Ok(buf)
    }
    // ... implement remaining trait methods
}
```

**Priority:** MEDIUM (Important for PKI/TLS certificate issuance control)

---

## 5. Error Handling Overhaul

### Overview

The codebase has **134 `unwrap()` calls across 37 files**. These should be replaced with proper error propagation.

### 5.1 High-Priority Files (by unwrap count)

| File | Count | Notes |
|------|-------|-------|
| `messages/message.rs` | 37 | Core message parsing - critical |
| `journal/journal_reader.rs` | 6 | File I/O operations |
| `utils/time_utils.rs` | 6 | Time parsing |
| `rr_data/hinfo_rr_data.rs` | 6 | String parsing |
| `lib.rs` | 5 | Test code (acceptable) |
| `zone/zone_reader.rs` | 4 | File parsing |
| `utils/trie/trie.rs` | 4 | Data structure |

### 5.2 Custom Error Type

**Create:** `lib-dns/src/error.rs`

```rust
#[derive(Debug, Clone)]
pub enum DnsError {
    Wire(WireError),
    RRData(RRDataError),
    Zone(ZoneReaderError),
    Journal(JournalReaderError),
    Io(String),
    Parse(String),
}

impl std::error::Error for DnsError {}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "Wire error: {}", e),
            Self::RRData(e) => write!(f, "RRData error: {}", e),
            Self::Zone(e) => write!(f, "Zone error: {}", e),
            Self::Journal(e) => write!(f, "Journal error: {}", e),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, DnsError>;
```

### 5.3 Migration Strategy

1. Create unified `DnsError` type
2. Add `From` implementations for existing error types
3. Replace `unwrap()` with `?` operator progressively
4. Start with `message.rs` as it's the most critical

**Priority:** HIGH (Prevents panics in production)

---

## 6. Utility Cleanup

### 6.1 Encoding Utilities

**Files:**
- `lib-dns/src/utils/base64.rs`
- `lib-dns/src/utils/base32.rs`
- `lib-dns/src/utils/hex.rs`
- `lib-dns/src/utils/octal.rs`

**Tasks:**
- Consolidate common patterns
- Add proper error handling (no panics)
- Consider using established crates (base64, hex) or document why custom implementations exist

### 6.2 Coordinate Utilities

**File:** `lib-dns/src/utils/coord_utils.rs`

**Tasks:**
- Clean up LOC record coordinate parsing
- Add input validation
- Document coordinate format (RFC 1876)

### 6.3 FQDN Utilities

**File:** `lib-dns/src/utils/fqdn_utils.rs`

**Tasks:**
- Review `pack_fqdn()` and `unpack_fqdn()` for edge cases
- Add validation for label length limits (63 bytes)
- Add validation for total name length (255 bytes)

**Priority:** LOW (Code quality improvement)

---

## 7. Test Coverage Expansion

### 7.1 Current Test State

**Location:** `lib-dns/src/lib.rs` (lines 15-121)

**Issues:**
- Most test vectors commented out
- Tests use `println!` debugging without assertions
- External file dependency (`/home/brad/Downloads/dns/find9.net.test.zone`)

### 7.2 Required Test Files

Create `lib-dns/tests/` directory with:

```
tests/
├── wire_format_tests.rs      # Round-trip wire encoding tests
├── zone_parsing_tests.rs     # Zone file parsing tests
├── dnssec_tests.rs           # DNSSEC record type tests
├── tsig_tests.rs             # TSIG signing/verification tests
├── fixtures/
│   ├── example.zone          # Sample zone file
│   ├── example.jnl           # Sample journal file
│   └── dns_packets/          # Captured DNS packets
```

### 7.3 Test Categories

1. **Unit Tests:** Each RRData type's `from_bytes()`/`to_bytes()` round-trip
2. **Wire Format Tests:** `from_wire_len()`/`to_wire()` with real DNS packets
3. **Zone Parsing Tests:** Loading and querying zone files
4. **Integration Tests:** Full message parsing and response generation
5. **TSIG Tests:** Signing and verification with known keys

**Priority:** MEDIUM (Quality assurance)

---

## 8. TCP Chunking Validation

### Issue

Comment in `lib.rs` (lines 45-46):
```rust
//APPARENTLY TCP MULTI PART / CHUNK SHOULD NOT REPEAT QUERY EACH MESSAGE...
// IS THIS ACCURATE????
```

### Investigation Required

1. Review RFC 1035 Section 4.2.2 (TCP usage)
2. Review RFC 7766 (DNS Transport over TCP)
3. Implement proper TCP message framing with 2-byte length prefix
4. Validate TSIG handling across TCP chunks (RFC 2845 Section 4.4)

### Implementation

**File:** Consider creating `lib-dns/src/transport/tcp.rs`

```rust
pub struct TcpDnsReader<R: Read> {
    reader: R,
}

impl<R: Read> TcpDnsReader<R> {
    pub fn read_message(&mut self) -> io::Result<Message> {
        let mut len_buf = [0u8; 2];
        self.reader.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; len];
        self.reader.read_exact(&mut msg_buf)?;

        Message::from_bytes(&msg_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}
```

**Priority:** MEDIUM (Required for zone transfers and large responses)

---

## 9. Documentation

### 9.1 Missing Documentation

- No `README.md` in lib-dns directory
- Limited rustdoc comments on public APIs
- No usage examples

### 9.2 Documentation Tasks

1. Create `lib-dns/README.md` with:
   - Overview and purpose
   - Basic usage examples
   - Supported record types
   - Known limitations

2. Add rustdoc to all public items:
   - Module-level documentation
   - Struct and enum documentation
   - Function documentation with examples

3. RFC references (already partially present):
   - Ensure all implementations reference relevant RFCs
   - Add links in documentation

**Priority:** LOW (Documentation improvement)

---

## Implementation Priority Matrix

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| **P0 - Critical** | TSIG from_wire_len completion | Low | Enables secure zone transfers |
| **P0 - Critical** | NSEC wire format | Medium | DNSSEC authenticated denial |
| **P0 - Critical** | NSEC3 wire format | Medium | DNSSEC hashed denial |
| **P1 - High** | DS wire format | Low | DNSSEC delegation chain |
| **P1 - High** | Error handling (message.rs) | High | Production stability |
| **P2 - Medium** | SSHFP wire format | Low | SSH key verification |
| **P2 - Medium** | Journal.open() | Medium | IXFR support |
| **P2 - Medium** | CAA record type | Medium | PKI security |
| **P2 - Medium** | TCP chunking | Medium | Large transfers |
| **P3 - Low** | SPF wiring | Low | Legacy compatibility |
| **P3 - Low** | Test coverage | High | Quality assurance |
| **P3 - Low** | Utility cleanup | Medium | Code quality |
| **P3 - Low** | Documentation | Medium | Developer experience |

---

## Appendix A: File Inventory

### Files with `todo!()` calls

| File | Line(s) | Function |
|------|---------|----------|
| `messages/tsig.rs` | 129 | `from_wire_len()` |
| `rr_data/ds_rr_data.rs` | 88, 95 | `from_wire_len()`, `to_wire()` |
| `rr_data/sshfp_rr_data.rs` | 113, 120 | `from_wire_len()`, `to_wire()` |
| `rr_data/nsec_rr_data.rs` | 165, 172 | `from_wire_len()`, `to_wire()` |
| `rr_data/nsec3_rr_data.rs` | 307 | `to_wire()` |
| `rr_data/inter/rr_data.rs` | 113, 119, 122, 161, 167, 170, 209, 215, 218 | Factory methods (SPF/CAA) |
| `zone/inter/zone_rr_data.rs` | 79, 85, 88 | Factory methods (SPF/CAA) |
| `journal/journal.rs` | 31 | `open()` |

### Compiler Warning Suppressions

Currently suppressed in `lib.rs`:
```rust
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(dead_code)]
#![allow(clippy::mismatched_lifetime_syntaxes)]
```

**Goal:** Remove these suppressions as code quality improves.

---

## Appendix B: Dependencies to Add

```toml
# Cargo.toml additions for full implementation

[dependencies]
indexmap = "2.0"  # For Journal ordered map (optional, can use BTreeMap)

[dev-dependencies]
# For testing
```

Currently lib-dns has **zero external dependencies** which is a strength for embedding. Consider whether to maintain this or add minimal dependencies for specific features.

---

## Appendix C: Related Components

### ZDNS Integration Points

- **lib-protocols:** Uses lib-dns for ZDNS protocol (`/lib-protocols/docs/zdns.md`)
- **ZHTP API:** DNS handler at `/zhtp/src/api/handlers/dns/mod.rs`
- **ZDNS Resolver:** Caching resolver using lib-dns
- **ZDNS Transport:** UDP/TCP transport layer

### External References

- RFC 1035 - Domain Names - Implementation and Specification
- RFC 2845 - Secret Key Transaction Authentication for DNS (TSIG)
- RFC 4034 - Resource Records for DNS Security Extensions (DNSSEC)
- RFC 4035 - Protocol Modifications for DNSSEC
- RFC 4255 - Using DNS to Securely Publish SSH Key Fingerprints
- RFC 5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- RFC 6844 - DNS Certification Authority Authorization (CAA)
- RFC 7766 - DNS Transport over TCP
