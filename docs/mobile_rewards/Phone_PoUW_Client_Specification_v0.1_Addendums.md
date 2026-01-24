# Phone PoUW Client Specification v0.1 — Addendums

## Addendum A — Canonical Encoding (Locked)

### A.1 Decision

Use Protobuf (proto3) with deterministic serialization.

**Why this choice (final):**
- Deterministic bytes guaranteed by prost / protobuf-c
- Smaller receipts than JSON
- Faster on mobile (CPU + battery)
- Clear forward-compatibility rules
- Avoids RFC 8785 JSON edge cases across platforms

This is a protocol invariant. Do not mix encodings.

### A.2 Protobuf schema (v1)

**pouw.proto**

```protobuf
syntax = "proto3";
package pouw.v1;

message ChallengeToken {
  uint32 version = 1;              // = 1
  bytes node_id = 2;               // 32 bytes
  bytes task_id = 3;               // 16..32 bytes
  bytes challenge_nonce = 4;       // 16..32 bytes
  uint64 issued_at = 5;             // unix seconds
  uint64 expires_at = 6;            // unix seconds

  Policy policy = 7;

  bytes node_signature = 8;         // sig over canonical token
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
  uint32 version = 1;               // = 1
  bytes task_id = 2;
  string client_did = 3;
  bytes client_node_id = 4;
  bytes provider_id = 5;            // optional
  bytes content_id = 6;             // CID or hash
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
  bytes proof_digest = 2;           // hash of proof material
}

message SignedReceipt {
  Receipt receipt = 1;
  string sig_scheme = 2;             // "dilithium5", etc
  bytes signature = 3;               // sig over canonical Receipt bytes
}

message ReceiptBatch {
  uint32 version = 1;                // = 1
  string client_did = 2;
  bytes batch_nonce = 3;
  repeated SignedReceipt receipts = 4;
}
```

**Canonicalization rule:**
- Serialize with `deterministic=true`
- Sign the serialized Receipt bytes only
- Never sign JSON, never sign envelopes

---

## Addendum B — Client Architecture (Formal)

### B.1 Client Modules (strict separation)

```
┌─────────────────────────────┐
│ Application / UI            │
└─────────────┬───────────────┘
              │
┌─────────────▼───────────────┐
│ PoUWController              │  ← orchestration only
└─────────────┬───────────────┘
              │
┌─────────────▼───────────────┐
│ VerifierEngine              │  ← hash / merkle / sig
└─────────────┬───────────────┘
              │
┌─────────────▼───────────────┐
│ ReceiptStore                │  ← persistent queue
└─────────────┬───────────────┘
              │
┌─────────────▼───────────────┐
│ SubmissionClient            │  ← batching + retry
└─────────────────────────────┘
```

### B.2 Swift Interfaces (authoritative)

#### VerifierEngine

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

#### ReceiptStore

```swift
protocol ReceiptStore {
    func enqueue(_ receipt: SignedReceipt)
    func pending(limit: Int) -> [SignedReceipt]
    func markAccepted(_ nonces: [Data])
    func markRejected(_ nonce: Data, reason: String)
}
```

#### SubmissionClient

```swift
protocol SubmissionClient {
    func requestChallenge(
        capabilities: [ProofType]
    ) async throws -> ChallengeToken

    func submitBatch(
        _ batch: ReceiptBatch
    ) async throws -> SubmissionResult
}
```

#### PoUWController (main entry)

```swift
final class PoUWController {

    func verifyAndRecord(
        contentID: Data,
        bytes: Data,
        providerID: Data?
    ) async

    func flushReceipts() async
}
```

### B.3 Required Controller Behaviour

**verifyAndRecord(...)**
- Ensure valid, unexpired ChallengeToken exists
- Run verification on background queue
- Build Receipt
- Serialize deterministically
- Sign with identity key
- Enqueue into ReceiptStore

**flushReceipts()**
- Pull up to N pending receipts
- Build ReceiptBatch
- Submit
- Process accept/reject
- Apply backoff if partial failure

---

## Addendum C — React Native Boundary

RN must never touch verification or crypto.

### RN-exposed API (minimal)

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

**Rules:**
- RN never passes URLs
- RN never sees receipts
- RN never signs anything
- RN only triggers actions

---

## Addendum D — State Machine (Client-Side)

```
IDLE
  ↓
CHALLENGE_READY
  ↓
VERIFYING
  ↓
RECEIPT_CREATED
  ↓
QUEUED
  ↓
SUBMITTED
  ↓
ACCEPTED | REJECTED | RETRY_WAIT
```

- ACCEPTED and REJECTED are terminal
- RETRY_WAIT re-enters SUBMITTED

---

## Addendum E — Security Invariants (Client)

- A receipt must reference a live challenge
- A receipt must be signed once and never mutated
- A receipt must not include content bytes
- A receipt must not include user query strings
- A receipt must not exceed policy caps (enforced locally)
