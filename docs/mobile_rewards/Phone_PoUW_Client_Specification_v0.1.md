# Phone PoUW Client Specification v0.1

## 1. Scope

This specification defines the client-side behaviour required to:
- perform useful verification work during normal content retrieval,
- produce cryptographically verifiable receipts of that work, and
- submit receipts to network nodes for reward settlement.

This specification is non-consensus. Client proofs do not affect block validity or fork choice.

**Out of scope:**
- node-side verification and payout mechanics
- chain contract interfaces
- provider-side content offer protocols (only referenced as inputs)

## 2. Actors and Trust Model

### 2.1 Actors
- **Client (Phone)**: performs verification work; signs receipts using its ZHTP identity key material.
- **Node (Verifier/Rewards Gateway)**: issues challenge tokens; validates receipts; accounts rewards.
- **Content Provider**: serves content bytes (may be node or separate peer).

### 2.2 Trust assumptions
- Client does not trust providers or the network by default.
- Node is not trusted to be honest, but is trusted to enforce reward policy; client should assume node may be unavailable or adversarial.
- Receipts are only meaningful if they can be independently verified by the node.

## 3. Definitions

- **CID**: content identifier derived from hash (content-addressed).
- **Merkle Root**: commitment to a set of CIDs/chunks.
- **Challenge Token**: node-issued, short-lived authorisation to perform receipt-eligible work.
- **Receipt**: signed proof that client performed verification work on a specific artifact under a specific challenge.

## 4. Client Requirements

### 4.1 Functional requirements
- **F1**: Client MUST obtain a Challenge Token from a node before generating reward-eligible receipts.
- **F2**: Client MUST verify at least one of the defined proof types (hash, merkle, signature) before issuing a receipt.
- **F3**: Client MUST sign receipts using the client's long-term identity signing key (or a derived session key bound to identity).
- **F4**: Client MUST implement replay resistance for receipts (local and protocol-level).
- **F5**: Client MUST batch receipts and submit them with backoff and persistence.
- **F6**: Client MUST not include user query strings or sensitive content in receipts.

### 4.2 Non-functional requirements
- **N1**: Verification MUST be bounded in CPU and battery usage; default max verification per request is policy-controlled.
- **N2**: Receipt generation MUST be deterministic and stable across client versions.
- **N3**: Client MUST be resilient to offline operation; receipts may be queued and submitted later.

## 5. Proof Types Supported

Client MUST implement Hash Verification. Others are optional but recommended.

### 5.1 Hash Verification (mandatory)

**Input:**
- CID (hash algorithm + digest)
- bytes (content or chunk bytes)

**Verification:**
- compute hash(bytes) per CID algorithm
- compare to CID digest

**Output:**
- result = ok | fail

### 5.2 Merkle Inclusion Proof (optional)

**Input:**
- leaf_hash (CID or chunk hash)
- proof_path[]
- merkle_root

**Verification:**
- reconstruct root from proof path
- compare to merkle_root

**Output:**
- result = ok | fail

### 5.3 Provider Signature Verification (optional)

**Input:**
- provider_pubkey
- message (e.g., offer, receipt ack, or content manifest)
- signature

**Verification:**
- verify signature with declared scheme

**Output:**
- result = ok | fail

## 6. Data Models

### 6.1 Challenge Token (node → client)

Binary or JSON; JSON shown for clarity.

```json
{
  "version": 1,
  "node_id": "base64(node_pubkey_or_id)",
  "task_id": "uuid-or-32byte",
  "challenge_nonce": "base64(16..32)",
  "issued_at": 1760000000,
  "expires_at": 1760000030,
  "policy": {
    "max_receipts": 20,
    "max_bytes_total": 10485760,
    "allowed_proof_types": ["hash", "merkle", "sig"],
    "min_bytes_per_receipt": 1024
  },
  "node_signature": "base64(sig_over_all_fields)"
}
```

Client MUST verify node_signature if node identity is known/pinned; if not pinned, client MAY accept token but MUST treat it as reward-policy only (no security impact).

### 6.2 Work Receipt (client → node)

```json
{
  "version": 1,
  "task_id": "uuid-or-32byte",
  "client_did": "did:zhtp:...",
  "client_node_id": "base64(32)",
  "provider_id": "base64-or-did-or-empty",
  "content_id": "cid-or-base64-hash",
  "proof_type": "hash|merkle|sig",
  "bytes_verified": 65536,
  "result": "ok|fail",
  "started_at": 1760000001,
  "finished_at": 1760000001,
  "receipt_nonce": "base64(16..32)",
  "challenge_nonce": "base64(16..32)",
  "aux": {
    "merkle_root": "optional",
    "proof_digest": "optional hash of proof material"
  }
}
```

### 6.3 Receipt Signature Envelope (mandatory)

Receipts MUST be signed. Envelope format:

```json
{
  "receipt": { "...Receipt..." },
  "sig_scheme": "dilithium5|ed25519|...",
  "signature": "base64(sig(hash(canonical_receipt_bytes)))"
}
```

Canonicalisation MUST be deterministic:
- Use canonical JSON (RFC 8785) OR
- Use protobuf with deterministic serialisation

Pick one and freeze it at v1.

## 7. Client Protocol Flows

### 7.1 Normal content retrieval with PoUW (happy path)

1. Client selects node N for challenge issuance (policy: nearest, trusted list, or last successful).
2. Client requests challenge token:
   ```
   GET /pouw/challenge?cap=hash,merkle&budget_hint=...
   ```
3. Node returns Challenge Token.
4. Client retrieves content bytes from provider (existing ZHTP/Web4 path).
5. Client verifies:
   - mandatory: Hash Verification
   - optional: Merkle proof / provider signature
6. Client creates receipt bound to:
   - task_id, challenge_nonce, receipt_nonce
7. Client enqueues receipt into persistent queue.
8. Client submits batch:
   ```
   POST /pouw/submit with N receipts
   ```
9. Node returns acceptance/denial per receipt.
10. Client marks accepted receipts as "settled" and deletes them (or keeps until payout confirmation if required by node policy).

### 7.2 Offline / deferred submission

If POST /pouw/submit fails, client MUST:
- keep receipts in queue
- retry with exponential backoff + jitter
- rotate node after K failures

### 7.3 Failure modes

- **Challenge expired before verification completes**: client MUST discard challenge and request a new one; MAY keep verification results but MUST re-bind receipts to a new challenge.
- **Verification fails (result=fail)**: client MAY submit fail receipts only if policy allows; otherwise discard.
- **Node rejects receipt**: client MUST store reason code; MUST NOT resubmit the exact same receipt nonce.

## 8. Client APIs (Node-facing)

### 8.1 Challenge

- **Method**: GET
- **Path**: `/pouw/challenge`
- **Query params**:
  - cap: comma-separated proof types (at least hash)
  - optional: max_bytes, max_receipts
- **Response**: Challenge Token

### 8.2 Submit

- **Method**: POST
- **Path**: `/pouw/submit`
- **Body**:
```json
{
  "version": 1,
  "client_did": "did:zhtp:...",
  "batch_nonce": "base64(16..32)",
  "receipts": [ { "receipt": "{...}", "sig_scheme": "...", "signature": "..." } ]
}
```
- **Response**:
```json
{
  "accepted": ["receipt_nonce_1", "receipt_nonce_2"],
  "rejected": [
    { "receipt_nonce": "...", "reason": "EXPIRED|REPLAY|POLICY|BAD_SIG|BAD_PROOF" }
  ],
  "server_time": 1760000002
}
```

Transport for these endpoints can be QUIC stream-based or HTTP/3-like; the semantics remain identical.

## 9. State Machine

Each receipt transitions:
```
CREATED → QUEUED → SUBMITTED → (ACCEPTED | REJECTED | RETRY_WAIT) → FINAL
```

**Rules:**
- ACCEPTED and REJECTED are terminal.
- RETRY_WAIT returns to SUBMITTED after backoff.
- Client MUST never mutate a receipt after signing; retries resubmit the same bytes.

## 10. Security and Anti-Abuse Requirements (Client Side)

- **S1**: Receipt must be bound to a node-issued challenge (task_id, challenge_nonce).
- **S2**: Client MUST generate receipt_nonce using a CSPRNG; length ≥ 16 bytes.
- **S3**: Client MUST maintain a local set of recently used receipt_nonce values to avoid accidental duplicates (window ≥ 24h or last N receipts).
- **S4**: Client MUST cap bytes_verified per content retrieval to prevent self-DoS and reward farming (policy default; enforce locally).
- **S5**: Client MUST not include raw content bytes in receipts. If proof material is needed, include only a digest (e.g., proof_digest).
- **S6**: Client MUST separate identity signing keys from session traffic keys; receipts should be signed by identity or an identity-authorised derived key.

## 11. Storage Requirements

- **Persistent queue**: store unsent receipts until accepted/rejected.
- **Metadata index**: by receipt_nonce, task_id, and time.
- **Retention**:
  - Accepted: delete immediately (or keep a compact audit log if required)
  - Rejected: keep reason + minimal record for 7–30 days (debugging/anti-replay)

## 12. Rate Limiting and Performance

Client MUST implement:
- max_receipts_per_minute (local, independent of node policy)
- max_bytes_verified_per_minute
- **backoff schedule for submission failures**:
  - 1s, 2s, 4s, 8s, max 60s + jitter
- **batching policy**:
  - submit when N >= 10 or after T = 10s, whichever first
- **CPU safety**:
  - verification runs on background threads; never on UI thread
  - pause/stop verification when OS indicates thermal/battery constraints (platform-specific)

## 13. Telemetry (Client)

Client MUST log (locally) at least:
- challenge request/response status
- verification time per proof type
- receipts created / accepted / rejected counts
- rejection reasons histogram
- bytes verified totals

Client MUST allow telemetry disablement or minimisation for privacy mode.

## 14. Conformance Tests (Client)

Minimum test suite:
- Hash verification correctness (known vectors).
- Receipt canonicalisation determinism (same input → same bytes).
- Signature verification round-trip (node verifying client signature).
- Replay protection: same receipt submitted twice → second rejected locally before network.
- Expiry handling: expired challenge never used.
- Batching correctness: partial acceptance does not drop remaining.

## 15. Versioning

- version fields are mandatory in Challenge Token and Receipt.
- Client MUST refuse unknown major versions.
- Minor version increments may add optional fields.
