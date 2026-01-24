# PoUW Implementation Plan: Mobile Apps & Node Integration

**Status:** Ready for implementation
**Owner:** Mobile team + Backend/Node team
**Last Updated:** 2026-01-23

---

## Executive Summary

This plan consolidates the PoUW (Proof-of-Useful-Work) protocol and its implementations across iOS, Android, and backend nodes. The system enables secure, verifiable content work on mobile with cryptographically signed receipts submitted to network nodes for reward distribution.

**Core invariant:** If Android and iOS receipts differ → rewards break. Cross-platform consistency is non-negotiable.

---

## Part I: Shared Protocol Foundation

### Protocol Encoding (Locked)

**Canonical Format:** Protobuf (proto3) with deterministic serialization
- **Why:** Deterministic bytes guaranteed by prost/protobuf-c, smaller than JSON, faster on mobile, clear forward-compatibility
- **Non-negotiable:** Must use deterministic=true for all serialization
- **Rule:** Never mix encodings. Never sign JSON or envelopes.

### Protobuf Schema (v1)

```protobuf
syntax = "proto3";
package pouw.v1;

message ChallengeToken {
  uint32 version = 1;              // = 1
  bytes node_id = 2;               // 32 bytes
  bytes task_id = 3;               // 16..32 bytes
  bytes challenge_nonce = 4;       // 16..32 bytes
  uint64 issued_at = 5;            // unix seconds
  uint64 expires_at = 6;           // unix seconds
  Policy policy = 7;
  bytes node_signature = 8;        // sig over canonical token
}

message Policy {
  uint32 max_receipts = 1;
  uint64 max_bytes_total = 2;
  uint64 min_bytes_per_receipt = 3;
  repeated ProofType allowed_proof_types = 4;
}

enum ProofType {
  PROOF_HASH = 0;
  PROOF_MERKLE = 1;
  PROOF_SIGNATURE = 2;
}

message Receipt {
  uint32 version = 1;              // = 1
  bytes task_id = 2;
  string client_did = 3;
  bytes client_node_id = 4;
  bytes provider_id = 5;           // optional
  bytes content_id = 6;            // CID or hash
  ProofType proof_type = 7;
  uint64 bytes_verified = 8;
  bool result_ok = 9;
  uint64 started_at = 10;
  uint64 finished_at = 11;
  bytes receipt_nonce = 12;
  bytes challenge_nonce = 13;
  Aux aux = 14;
}

message Aux {
  bytes merkle_root = 1;
  bytes proof_digest = 2;          // hash of proof material
}

message SignedReceipt {
  Receipt receipt = 1;
  string sig_scheme = 2;           // "dilithium5", "ed25519", etc
  bytes signature = 3;             // sig over canonical Receipt bytes
}

message ReceiptBatch {
  uint32 version = 1;              // = 1
  string client_did = 2;
  bytes batch_nonce = 3;
  repeated SignedReceipt receipts = 4;
}
```

### Security Invariants (Protocol Level)

- A receipt must reference a live, non-expired ChallengeToken
- A receipt must be signed once and never mutated
- A receipt must not include content bytes in the message
- A receipt must not include user query strings
- A receipt must not exceed policy caps (enforced by client)
- Replay protection via nonce indexing

---

## Part II: Mobile Architecture (Cross-Platform)

### Shared Module Stack

```
┌─────────────────────────────────────┐
│ React Native Application / UI       │ ← JS layer (trigger only)
└──────────────────┬──────────────────┘
                   │
        ┌──────────▼──────────┐
        │ Native Bridge       │ ← Platform-specific entry
        │ (Swift/Kotlin)      │
        └──────────┬──────────┘
                   │
        ┌──────────▼────────────────┐
        │ PoUWController            │ ← Core orchestration
        └──┬──────────────┬─────────┘
           │              │
      ┌────▼─────┐   ┌────▼──────────┐
      │ Verifier  │   │ ReceiptStore  │ ← Persistent queue
      │ Engine    │   │               │
      └────┬─────┘   └────┬──────────┘
           │              │
           └──────┬───────┘
                  │
          ┌───────▼──────────┐
          │ SubmissionClient │ ← HTTP/QUIC batcher
          └──────────────────┘
```

### React Native Boundary (Strict)

RN sees **only** this minimal interface:

```typescript
interface PoUW {
  verifyContent(
    contentId: Uint8Array,
    bytes: Uint8Array,
    providerId?: Uint8Array
  ): Promise<void>;

  flush(): Promise<void>;
}
```

**Hard rules (enforced):**
- RN never sees keys
- RN never sees receipts or signatures
- RN never serializes protobuf
- RN never performs cryptography
- RN never talks directly to reward endpoints
- RN is a button + lifecycle trigger, nothing more

### Client-Side State Machine

```
IDLE
  ↓ (request challenge)
CHALLENGE_READY
  ↓ (verify content)
VERIFYING
  ↓ (build receipt)
RECEIPT_CREATED
  ↓ (persist to queue)
QUEUED
  ↓ (submit batch)
SUBMITTED
  ↓
ACCEPTED | REJECTED | RETRY_WAIT
     (terminal)    (terminal)    (loop back to SUBMITTED)
```

### Core Controller Behavior

**verifyAndRecord(...)**
1. Fetch or reuse valid, unexpired ChallengeToken
2. Run verification on background thread (never block UI)
3. Build Receipt with all required fields
4. Serialize deterministically
5. Sign with identity key
6. Enqueue into ReceiptStore

**flushReceipts()**
1. Pull up to N pending receipts from store
2. Build ReceiptBatch
3. Submit via SubmissionClient
4. Process accept/reject responses
5. Apply exponential backoff on partial failure
6. Mark accepted nonces, re-queue rejected

---

## Part III: iOS Implementation

### Language & Frameworks

- **Language:** Swift 5.9+
- **Async:** async/await (no callbacks)
- **Storage:** Core Data or encrypted SQLite via FMDB
- **Crypto:** Swift Crypto + Foundation for Ed25519; Dilithium via FFI if needed
- **Protobuf:** swift-protobuf (v1.26+)

### Module Interfaces

#### VerifierEngine (Protocol)

```swift
protocol VerifierEngine {
    func verifyHash(
        contentID: Data,
        bytes: Data
    ) throws -> Bool

    func verifyMerkle(
        leaf: Data,
        proof: [Data],
        root: Data
    ) throws -> Bool
}
```

**Implementation notes:**
- Use `CommonCrypto` or `CryptoKit` for SHA-256
- Hash verification is deterministic and synchronous
- No async needed; dispatch to background queue in controller

#### IdentitySigner (Protocol)

```swift
protocol IdentitySigner {
    func sign(_ bytes: Data) throws -> Data
    func getDid() -> String
    func getNodeId() -> Data
}
```

**Key storage:**
- Use Secure Enclave if available
- Fall back to Keychain for Ed25519
- Export signature only; private key never leaves device

#### ReceiptStore (Protocol)

```swift
protocol ReceiptStore {
    func enqueue(_ receipt: SignedReceipt) async throws
    func pending(limit: Int) async throws -> [SignedReceipt]
    func markAccepted(_ nonces: [Data]) async throws
    func markRejected(_ nonce: Data, reason: String) async throws
}
```

**Storage requirements:**
- Survive app termination
- FIFO ordering with timestamp
- Indexed by nonce for replay detection
- Encrypted at rest

#### SubmissionClient (Protocol)

```swift
protocol SubmissionClient {
    func requestChallenge(
        capabilities: [PoUW_v1_ProofType]
    ) async throws -> PoUW_v1_ChallengeToken

    func submitBatch(
        _ batch: PoUW_v1_ReceiptBatch
    ) async throws -> SubmissionResult
}
```

**Transport:**
- Use existing app QUIC/HTTP stack
- Latency tolerant (retry-safe)
- Timeout on challenge request: 30s
- Timeout on batch submission: 60s

#### PoUWController (Main Entry)

```swift
final class PoUWController {
    init(
        verifier: VerifierEngine,
        signer: IdentitySigner,
        store: ReceiptStore,
        submission: SubmissionClient
    )

    func verifyAndRecord(
        contentID: Data,
        bytes: Data,
        providerID: Data?
    ) async throws

    func flushReceipts() async throws
}
```

---

## Part IV: Android Implementation

### Language & Frameworks

- **Language:** Kotlin 1.9+
- **Async:** Coroutines with suspend functions
- **Storage:** Room DAO + encrypted SQLite
- **Crypto:** Bouncy Castle (Ed25519), Android Keystore for key material
- **Protobuf:** protobuf-kotlin (v3.24+)

### Module Interfaces

#### VerifierEngine (Interface)

```kotlin
interface VerifierEngine {
    fun verifyHash(
        contentId: ByteArray,
        bytes: ByteArray
    ): Boolean

    fun verifyMerkle(
        leaf: ByteArray,
        proof: List<ByteArray>,
        root: ByteArray
    ): Boolean
}
```

**Implementation notes:**
- Use `java.security.MessageDigest.getInstance("SHA-256")`
- No JNI required for basic verification
- Must never touch UI thread (dispatch to IO dispatcher)

#### IdentitySigner (Interface)

```kotlin
interface IdentitySigner {
    fun sign(bytes: ByteArray): ByteArray
    fun getDid(): String
    fun getNodeId(): ByteArray
}
```

**Key storage:**
- Use Android Keystore for key material (AndroidKeyStore)
- Ed25519 native support in Android 11+; fallback to Bouncy Castle
- Dilithium: Use Rust via JNI or prebuilt `.so`
- Export signature only; never leak private key

#### ReceiptStore (Interface)

```kotlin
interface ReceiptStore {
    suspend fun enqueue(receipt: SignedReceipt)
    suspend fun pending(limit: Int): List<SignedReceipt>
    suspend fun markAccepted(nonces: List<ByteArray>)
    suspend fun markRejected(nonce: ByteArray, reason: String)
}
```

**Storage requirements:**
- Room DAO with encryption (Android SQLCipher optional)
- FIFO ordering via timestamp
- Nonce index for replay safety
- Survives app kill/restart

#### SubmissionClient (Interface)

```kotlin
interface SubmissionClient {
    suspend fun requestChallenge(
        capabilities: List<ProofType>
    ): ChallengeToken

    suspend fun submitBatch(
        batch: ReceiptBatch
    ): SubmissionResult
}
```

**Transport:**
- Reuse existing QUIC/HTTP client from app
- Timeout on challenge request: 30s
- Timeout on batch submission: 60s

#### PoUWController (Main Entry)

```kotlin
class PoUWController(
    private val verifier: VerifierEngine,
    private val signer: IdentitySigner,
    private val store: ReceiptStore,
    private val submission: SubmissionClient
) {

    suspend fun verifyAndRecord(
        contentId: ByteArray,
        bytes: ByteArray,
        providerId: ByteArray?
    )

    suspend fun flushReceipts()
}
```

### Cross-Platform Critical Invariants

These **must** be identical on iOS and Android:
- Protobuf schema (v1)
- Deterministic serialization rules
- Receipt field values and order
- Signing key algorithms (Ed25519 or Dilithium)
- Challenge binding logic
- Replay detection (nonce indexing)
- Policy enforcement (max receipts, bytes, etc.)

**Deviation = reward system breaks.**

---

## Part V: Node-Side Integration

### Node Responsibilities

1. **Challenge Generation**
   - Issue ChallengeToken with policy
   - Sign token with node key
   - Expire tokens (< 1 hour)
   - Track issuance for deduplication

2. **Receipt Validation**
   - Verify receipt signature (Ed25519/Dilithium)
   - Validate challenge binding (challenge_nonce match)
   - Enforce policy limits (max receipts, bytes, proof types)
   - Deduplicate by nonce
   - Verify client DID existence

3. **Storage**
   - Persist validated receipts
   - Index by client_did, task_id, nonce
   - Maintain audit trail for disputes

4. **Reward Calculation**
   - Sum bytes_verified across accepted receipts
   - Apply policy multipliers (proof type)
   - Calculate final reward amount
   - Queue for distribution

### Node API Endpoints

#### POST /challenges

**Request:**
```json
{
  "capabilities": ["PROOF_HASH", "PROOF_MERKLE"],
  "client_did": "did:sovereign:...",
  "node_id": "<base64>"
}
```

**Response:**
```json
{
  "token": "<base64 encoded ChallengeToken>",
  "expires_at": 1706000000
}
```

#### POST /receipts/submit

**Request:**
```json
{
  "batch": "<base64 encoded ReceiptBatch>"
}
```

**Response:**
```json
{
  "accepted": [
    {"nonce": "<base64>", "reward_estimate": 100}
  ],
  "rejected": [
    {"nonce": "<base64>", "reason": "policy_violation"}
  ]
}
```

### Node Data Model (Pseudo-schema)

```
ChallengeIssue
├── node_id: bytes(32)
├── challenge_nonce: bytes(32)
├── issued_at: uint64
├── expires_at: uint64
├── client_did: string
├── policy: Policy (embedded)
└── signature: bytes

ValidatedReceipt
├── receipt_nonce: bytes(32)
├── challenge_nonce: bytes(32) [FK → ChallengeIssue]
├── client_did: string
├── task_id: bytes
├── bytes_verified: uint64
├── proof_type: enum
├── result_ok: bool
├── signature_scheme: string
├── signature: bytes
├── validated_at: uint64
└── deleted: bool (soft delete)

Reward
├── client_did: string
├── epoch: uint64
├── total_bytes: uint64
├── total_amount: uint256
├── receipts: [receipt_nonce] (FK)
└── paid_at: uint64 (nullable)
```

### Node Implementation Checklist

- [ ] Challenge generation with deterministic signing
- [ ] Receipt deserialization (protobuf)
- [ ] Signature verification (Ed25519, Dilithium)
- [ ] Policy enforcement (max receipts, bytes, proof types)
- [ ] Nonce deduplication (primary key + unique index)
- [ ] Challenge expiry validation
- [ ] Reward aggregation logic
- [ ] Batch submission success/error handling
- [ ] Metrics/logging for disputes
- [ ] Database backup/recovery for receipts

---

## Part VI: Implementation Roadmap

### Phase 1: Protocol & Foundation (Week 1-2)

**Outcomes:** Shared proto files, iOS/Android scaffolding, unit tests for serialization

- [ ] Lock and publish `pouw.proto` (v1)
- [ ] Generate Swift proto bindings via swift-protobuf
- [ ] Generate Kotlin proto bindings via protobuf-kotlin
- [ ] Unit tests: deterministic serialization on both platforms
- [ ] Unit tests: signature verification (Ed25519)
- [ ] Create sample ChallengeToken and Receipt for cross-platform testing

**Deliverables:** Proto files, proto bindings, serialization tests

### Phase 2: Mobile Core (Week 3-4)

**Outcomes:** PoUWController working end-to-end on iOS and Android (offline)

#### iOS
- [ ] VerifierEngine implementation (hash + merkle)
- [ ] IdentitySigner (Secure Enclave + Ed25519)
- [ ] ReceiptStore (Core Data or FMDB, encrypted)
- [ ] SubmissionClient stub (offline)
- [ ] PoUWController integration
- [ ] State machine tests

#### Android
- [ ] VerifierEngine implementation (hash + merkle, MessageDigest)
- [ ] IdentitySigner (Android Keystore + Bouncy Castle)
- [ ] ReceiptStore (Room DAO, encrypted SQLite)
- [ ] SubmissionClient stub (offline)
- [ ] PoUWController integration
- [ ] State machine tests

**Deliverables:** Working PoUWController, offline end-to-end tests

### Phase 3: Network Integration (Week 5)

**Outcomes:** Mobile apps can request challenges and submit receipts to node

- [ ] Implement SubmissionClient (real HTTP/QUIC)
- [ ] Node endpoint: POST /challenges (issue ChallengeToken)
- [ ] Node endpoint: POST /receipts/submit (validate & accept ReceiptBatch)
- [ ] Integration tests: iOS → Node → response
- [ ] Integration tests: Android → Node → response
- [ ] Retry/backoff logic with exponential backoff

**Deliverables:** Mobile ↔ Node communication, e2e test scripts

### Phase 4: React Native Bridge (Week 6)

**Outcomes:** RN can trigger verification and flush receipts

- [ ] iOS native module exposing PoUW interface
- [ ] Android native module exposing PoUW interface
- [ ] RN TypeScript bindings
- [ ] RN app: call verifyContent(), flush()
- [ ] RN app: handle async/await errors
- [ ] RN tests with mock native modules

**Deliverables:** Working RN app integration, no direct RN→crypto calls

### Phase 5: Node Hardening (Week 7)

**Outcomes:** Node fully validates receipts, prevents fraud, calculates rewards

- [ ] Challenge signature verification
- [ ] Receipt signature verification (both Ed25519 and Dilithium)
- [ ] Policy enforcement (max receipts, bytes, proof types)
- [ ] Nonce deduplication (unique index + soft delete)
- [ ] Challenge expiry checks
- [ ] Client DID validation
- [ ] Reward aggregation query
- [ ] Dispute logging (metrics, traces)

**Deliverables:** Hardened node, audit logs, reward calculation

### Phase 6: Testing & Hardening (Week 8)

**Outcomes:** Production-ready code with security review

- [ ] Security audit: crypto, key storage, serialization
- [ ] Stress test: 10k receipts/minute on node
- [ ] Mobile battery/memory profiling
- [ ] Cross-platform compatibility matrix
- [ ] Failover scenario testing (node down, challenge expired, etc.)
- [ ] Long-soak test (receipts surviving app kill/restart)

**Deliverables:** Security report, performance benchmarks, production checklist

---

## Part VII: Testing Strategy

### Unit Tests (Per Module)

| Module | Coverage | Platform |
|--------|----------|----------|
| VerifierEngine | Hash, merkle, failures | iOS, Android |
| IdentitySigner | Sign, DID format, key rotation | iOS, Android |
| ReceiptStore | Enqueue, pending, dedup, persistence | iOS, Android |
| SubmissionClient | Timeout, retry, backoff | iOS, Android |

### Integration Tests

- Challenge request → receipt submission (end-to-end)
- Receipt batch format validation
- Policy enforcement (max caps)
- Nonce deduplication
- State machine transitions
- Error recovery (network down, expired challenge)

### Cross-Platform Tests

- **Serialization parity:** Same Receipt → same bytes on iOS and Android
- **Signature parity:** Same bytes + key → same signature
- **Challenge binding:** Same challenge → same nonce binding

### Node Tests

- Challenge generation (signature valid, expiry correct)
- Receipt validation (all fields present, format correct)
- Signature verification (rejects tampered receipts)
- Policy enforcement (rejects over-limit batches)
- Reward calculation (sums correctly)

---

## Part VIII: Security Checklist

### Crypto
- [ ] Ed25519 or Dilithium signing in Keystore (never in app memory)
- [ ] Deterministic protobuf serialization (no random padding)
- [ ] No hardcoded keys or test keys in production
- [ ] SHA-256 for hashing (no weaker algorithms)

### Key Storage
- [ ] iOS: Secure Enclave or Keychain
- [ ] Android: AndroidKeyStore with StrongBoxKeyStore if available
- [ ] No key material in user defaults or shared preferences
- [ ] Key rotation mechanism exists

### Transport
- [ ] HTTPS/QUIC only (no plaintext)
- [ ] Certificate pinning recommended
- [ ] Timeouts on all network calls

### Input Validation
- [ ] Protobuf deserialization validates all fields
- [ ] Receipt nonce must be 32 bytes
- [ ] Challenge nonce must match
- [ ] DID format validated before storage

### Replay & Deduplication
- [ ] Nonce index (unique constraint on database)
- [ ] Soft delete for audit trail
- [ ] Challenge expiry enforced
- [ ] Per-challenge receipt limit enforced

---

## Part IX: Marketplace Link

Reference: [PoUW Marketplace](https://bogo-ncw-updigital.web.app/marketplace/games/Rktza4tZXYJ4RVEQr7gA)

---

## Part X: Known Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Cross-platform signature mismatch | Rewards don't distribute | Phase 2 test matrix, locked proto schema |
| Expired challenge accepted | Fraud | Node validates expiry strictly |
| Nonce replay | Double-reward | Unique nonce index on node |
| Key leak from Keystore | Impersonation | Annual key rotation, secure enclave |
| Receipt queue loss | Lost reward | Persistent storage with backup |
| Node downtime | Can't submit | Client queue survives, retry on recovery |
| Policy overflow | Unbounded storage | Policy limits enforced at client + node |

---

## Part XI: Ownership & Contacts

- **Mobile (iOS):** [Team lead TBD]
- **Mobile (Android):** [Team lead TBD]
- **Backend/Node:** [Backend lead TBD]
- **Protocol/Spec:** [Maintainer TBD]

---

## Sign-Off

This plan is complete and ready for implementation.

- **Protocol locked:** ✓ (Addendum A)
- **iOS spec finalized:** ✓ (Part III)
- **Android spec finalized:** ✓ (Part IV)
- **Node integration planned:** ✓ (Part V)
- **Testing strategy defined:** ✓ (Part VII)
- **Security review pending:** → Phase 6

**Next step:** Assign teams and start Phase 1 (proto generation & unit tests).
