# Android PoUW Client Specification v0.1

## High-Level Architecture

Same as iOS:

```
React Native (JS)
        │
        ▼
Android Native Module (Kotlin)
        │
        ▼
PoUWController (Kotlin)
        │
 ┌──────┴────────┐
 ▼               ▼
VerifierEngine   ReceiptStore
        │               │
        └──────┬────────┘
               ▼
        SubmissionClient
```

RN is only a trigger layer.

---

## Android Module Responsibilities

### 1. VerifierEngine (Kotlin)

Runs all cryptographic verification locally.

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
- Use `MessageDigest.getInstance("SHA-256")`
- No JNI required
- Deterministic, synchronous
- Must never touch UI thread

### 2. Identity & Signing

Keys live in Android Keystore.

- **Signing key**: Ed25519 or Dilithium (via native lib)
- **Export signature only**, never private key

```kotlin
interface IdentitySigner {
    fun sign(bytes: ByteArray): ByteArray
    fun getDid(): String
    fun getNodeId(): ByteArray
}
```

**If Dilithium is required:**
- Use Rust via JNI or a prebuilt `.so`
- API surface stays identical to iOS

### 3. ReceiptStore (persistent queue)

Use Room or encrypted SQLite.

```kotlin
interface ReceiptStore {
    fun enqueue(receipt: SignedReceipt)
    fun pending(limit: Int): List<SignedReceipt>
    fun markAccepted(nonces: List<ByteArray>)
    fun markRejected(nonce: ByteArray, reason: String)
}
```

**Requirements:**
- Survives app restarts
- FIFO ordering
- Replay-safe (nonce index)

### 4. SubmissionClient

Uses existing QUIC / HTTP stack (same as rest of app).

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

**Important:**
- This is not consensus traffic
- Latency tolerant
- Retry-safe

### 5. PoUWController (core logic)

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

**Behavior is identical to iOS:**
- Fetch / reuse challenge
- Verify content
- Build protobuf Receipt
- Deterministically serialize
- Sign
- Enqueue
- Batch submit later

---

## React Native Boundary (same on iOS & Android)

RN sees exactly the same API.

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

**Hard rules:**
- RN never sees keys
- RN never sees receipts
- RN never serializes protobuf
- RN never performs crypto
- RN never talks directly to reward endpoints
- RN is a button + lifecycle trigger, nothing more.

---

## Cross-Platform Invariants (critical)

These must be true on both platforms:
- Same protobuf schema
- Deterministic serialization
- Same receipt fields
- Same signing rules
- Same challenge binding
- Same replay rules

**If Android and iOS receipts differ → rewards break.**

---

## What You Do NOT Do on Android

- Do not implement logic in JS
- Do not use WebCrypto
- Do not allow background JS timers to sign receipts
- Do not let RN manage retries or batching

---

## Business Takeaway (for alignment)

From the network's perspective:
- Android phones, iPhones, and future devices are identical contributors
- They produce the same cryptographic receipts
- They earn rewards under the same policy
- Consensus nodes do not care about platform

**This keeps the system scalable and defensible.**
