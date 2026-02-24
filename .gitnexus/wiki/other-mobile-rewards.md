# Other — mobile_rewards

# Mobile Rewards Module Documentation

## Overview

The **mobile_rewards** module is designed to facilitate the Proof of Useful Work (PoUW) mechanism on mobile devices, specifically for Android. It enables clients to perform cryptographic verification of content, generate receipts for that work, and submit those receipts to network nodes for reward settlement. This module is built using Kotlin and integrates with React Native for cross-platform compatibility.

## High-Level Architecture

The architecture of the mobile rewards module mirrors that of the iOS counterpart, with a React Native layer triggering native Android functionality. The core components include:

- **React Native (JS)**: Acts as a trigger layer for the mobile application.
- **Android Native Module (Kotlin)**: Implements the core logic and interfaces.
- **PoUWController**: Orchestrates the verification and receipt generation process.
- **VerifierEngine**: Handles cryptographic verification.
- **ReceiptStore**: Manages the persistent storage of receipts.
- **SubmissionClient**: Facilitates the submission of receipts to the network.

```mermaid
graph TD;
    A[React Native (JS)] --> B[Android Native Module (Kotlin)];
    B --> C[PoUWController (Kotlin)];
    C --> D[VerifierEngine];
    C --> E[ReceiptStore];
    C --> F[SubmissionClient];
```

## Key Components

### 1. PoUWController

The `PoUWController` is the main orchestrator of the mobile rewards module. It coordinates the verification of content and the generation of receipts.

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

#### Responsibilities:
- Fetch and reuse challenge tokens.
- Verify content using the `VerifierEngine`.
- Build and serialize protobuf receipts.
- Sign receipts and enqueue them in the `ReceiptStore`.
- Batch submit receipts later using the `SubmissionClient`.

### 2. VerifierEngine

The `VerifierEngine` is responsible for performing cryptographic verifications locally.

```kotlin
interface VerifierEngine {
    fun verifyHash(contentId: ByteArray, bytes: ByteArray): Boolean
    fun verifyMerkle(leaf: ByteArray, proof: List<ByteArray>, root: ByteArray): Boolean
}
```

#### Implementation Notes:
- Utilizes `MessageDigest.getInstance("SHA-256")` for hash verification.
- Must operate deterministically and synchronously, without blocking the UI thread.

### 3. IdentitySigner

The `IdentitySigner` interface manages the signing of receipts and retrieval of identity information.

```kotlin
interface IdentitySigner {
    fun sign(bytes: ByteArray): ByteArray
    fun getDid(): String
    fun getNodeId(): ByteArray
}
```

#### Key Points:
- Signing keys are stored securely in the Android Keystore.
- Only the signature is exported; private keys are never exposed.

### 4. ReceiptStore

The `ReceiptStore` is a persistent queue that manages the storage and retrieval of receipts.

```kotlin
interface ReceiptStore {
    fun enqueue(receipt: SignedReceipt)
    fun pending(limit: Int): List<SignedReceipt>
    fun markAccepted(nonces: List<ByteArray>)
    fun markRejected(nonce: ByteArray, reason: String)
}
```

#### Requirements:
- Must survive app restarts.
- Implements FIFO ordering and is replay-safe using nonce indexing.

### 5. SubmissionClient

The `SubmissionClient` handles the submission of receipts to the network.

```kotlin
interface SubmissionClient {
    suspend fun requestChallenge(capabilities: List<ProofType>): ChallengeToken
    suspend fun submitBatch(batch: ReceiptBatch): SubmissionResult
}
```

#### Important Considerations:
- This component is designed to be latency tolerant and retry-safe.
- It uses existing QUIC/HTTP stacks for communication.

## React Native Boundary

The React Native interface for the mobile rewards module is consistent across platforms. The API exposes two primary functions:

```typescript
interface PoUW {
  verifyContent(contentId: Uint8Array, bytes: Uint8Array, providerId?: Uint8Array): Promise<void>;
  flush(): Promise<void>;
}
```

### Hard Rules:
- React Native does not handle cryptographic operations, receipt management, or direct communication with reward endpoints.
- It serves solely as a trigger for actions within the native module.

## Cross-Platform Invariants

To ensure consistency across Android and iOS implementations, the following invariants must be maintained:

- Identical protobuf schema.
- Deterministic serialization of receipts.
- Consistent receipt fields and signing rules.
- Uniform challenge binding and replay rules.

## Security Considerations

The mobile rewards module incorporates several security measures:

- Receipts must be bound to a valid challenge.
- Receipt nonces must be generated using a cryptographically secure random number generator (CSPRNG).
- Sensitive data, such as raw content bytes and user query strings, must not be included in receipts.

## Conclusion

The **mobile_rewards** module is a critical component of the PoUW system, enabling mobile clients to perform verification work and earn rewards securely. By adhering to the outlined architecture and component responsibilities, developers can ensure a robust and scalable implementation that aligns with the overall system design.