# ADR-0003: ZHTP Proof Suite V1 - Complete Specification

## ADR Number
0003 (supersedes and integrates ADR-0002)

## Date
2025-11-30

## Status
**Proposed** → Pending Review → Accepted

## Context

ZHTP is built on **root-key-anchored identities** (ADR-0004), **sovereign devices**, and a mix of **private peer interactions** and **public DAO-level governance**.

### The Problem

The existing implementation treats `ZeroKnowledgeProof` as an ungoverned catch-all struct with:

- **no versioning** - no `version` field, no way to track format changes
- **no canonical schema** - 6 fields (`proof_system`, `proof_data`, `public_inputs`, `verification_key`, `plonky2_proof`, `proof`) with unclear semantics
- **no registry** - no authoritative list of supported proof types
- **no validation rules** - malformed proofs deserialize silently
- **string-based dispatch** - `match proof.proof_system.as_str()` allows typos, returns `Ok(false)` for unknown types
- **inconsistent usage across modules** - lib-proofs uses `ZkProofType` enum, lib-identity uses free-form strings
- **no binding between identity anchor and operational keys** - without an explicit binding proof, operational keys can drift from the DID anchor without authorization

As a result, proofs are **fragile, unverifiable, incompatible across versions, and unsafe to evolve**.

### The Solution

To make the network verifiable and future-proof, ZHTP needs a **coherent suite of proofs** that cover:

* identity and capabilities
* proximity and device relations
* transport, routing, and storage
* private SID-to-SID transactions
* public DAO transactions and voting
* credentials and selective disclosure

This ADR establishes both the **governance framework** and the **complete proof architecture** for ZHTP V1.

---

## Decision

Adopt **ZHTP Proof Suite V1** as the canonical proof architecture and governance policy, defining:

### Governance Framework
1. **Canonical proof envelope** - strict schema with required fields
2. **Strict proof type governance** - enum-based, not stringly-typed
3. **Versioning rules** - explicit version tracking for migration
4. **Schema validation** - reject malformed proofs early
5. **Rejection of unknown proof types** - error instead of silent failure
6. **Proof Registry** - authoritative list of supported proof formats with validation rules
7. **Canonical binary serialization** - CBOR instead of JSON
8. **Deterministic ownership binding** - cryptographic proof linking DID to PQ signature key
9. **Long-term upgrade and deprecation strategy** - safe evolution path

### Concrete Specifications
1. **13 proof types** covering identity, devices, network, SID economy, and DAO governance
2. **Unified proof envelope** with versioning and type-safe dispatch
3. **Public vs private classification** for each proof type
4. **Clear verification rules** for each proof type
5. **MVP subset definition** - which proofs ship first

---

# ZHTP Proof Suite V1

*A unified specification for all protocol proofs*

## 0. Purpose

ZHTP Proof Suite V1 defines:

* which proof types exist
* what each proof means
* how proofs are encoded
* how they are verified
* which are private and which are public
* how they evolve over time

This is not an implementation document, it is an **architectural contract**.

---

## 1. Core Design Principles

### 1.1 Root-Key-Anchored Identity

* Identity is anchored to a deterministic **Root Signing public key** (Dilithium5).
* Recovery material is used only to derive the Root Secret and Root Signing Key; the DID is not a function of raw seed bytes.
* Operational keys are attached under the DID and are authorized by the Root Signing Key.
* *Reference: ADR-0004 (Root-Key-Anchored DID)*

### 1.2 Capabilities Are Attached by Proofs

* Post-quantum keys, device keys, credentials, voting rights, storage rights, routing responsibilities are all **capabilities**.
* These do not define identity, they **attach to identity through proofs**.

### 1.3 SID-to-SID Transactions Are Private by Default

* They are expressed as proofs and encrypted messages.
* They never appear as raw transactions in a global ledger.

### 1.4 DAO-Level Actions Are Public

* Treasury operations, votes, proposal executions, and state transitions must be publicly auditable.

### 1.5 Every Critical Trust Boundary Has a Proof

* If the system depends on something being true, there must be a corresponding proof type with a defined schema and verification rule.

### 1.6 One Envelope, Many Types

* All proofs share a canonical envelope structure and versioning system.
* Proof types are expressed as **enums, not free-text strings**.

### 1.7 Canonical Serialization

* All proofs use **canonical binary encoding** (e.g., canonical CBOR).
* JSON is allowed only as a human-readable debug form, not as the canonical representation.

---

## 2. Common Proof Envelope

All proofs conform to the same logical envelope.

### 2.1 ProofType Enum

```rust
pub enum ProofType {
    // Identity & Capabilities (§3)
    SignaturePopV1,
    IdentityAttributeZkV1,
    CredentialProofV1,
    DeviceDelegationV1,

    // Proximity & Sessions (§4)
    ProximityHandshakeV1,
    SessionKeyProofV1,

    // Network & Data (§5)
    StorageProofV1,
    RoutingProofV1,
    TransportProofV1,

    // SID Economy - Private (§6)
    SidTransactionV1,

    // DAO & Governance - Public (§7)
    DaoTransactionV1,
    VotingV1,
    StateTransitionV1,
}
```

### 2.2 Proof Envelope Structure

```rust
pub struct ProofEnvelope {
    pub version: String,               // "v1"
    pub proof_type: ProofType,         // enum, not free text
    pub did_version: String,           // "v1" for DID format
    pub circuit_hash: Option<Vec<u8>>, // for ZK or circuit-bound proofs
    pub verification_key: Vec<u8>,     // public key if relevant
    pub public_inputs: Vec<u8>,        // statement being proven
    pub proof_data: Vec<u8>,           // signature, proof bytes, or credential bytes
}
```

### 2.3 Envelope Rules

* `version` is always `"v1"` for this suite.
* `proof_type` selects how to interpret and verify the proof.
* `did_version` binds the proof to the DID generation rules.
* `circuit_hash` is **required** for zero-knowledge proofs and any circuit-bound scheme.
* `verification_key` is **required** for signature-style proofs, optional for others.
* `public_inputs` encodes the statement that is being proven.
* `proof_data` holds the raw proof artifact, such as a signature or a zero-knowledge proof.

Each concrete proof type defines the exact content and layout of `public_inputs` and `proof_data`.

---

## 3. Identity and Capability Proofs

### 3.1 SignaturePopV1

**Purpose**: Bind operational keys and capabilities to the root-key-anchored DID via authorization from the Root Signing Key.

**Scope**:
* SID level
* Mandatory for every identity
* Private, but can be disclosed if needed

**Binding Message**:
```
b"IDENTITY_BIND_V1:" || did_bytes
```

**Envelope**:
* `proof_type = SignaturePopV1`
* `verification_key = public signing key bytes`
* `public_inputs = binding message`
* `proof_data = signature over binding message with the private signing key`
* `circuit_hash = null`

**Verification**:
1. Recompute binding message from DID.
2. Verify signature using `verification_key`.
3. Check DID matches the identity root.

---

### 3.2 IdentityAttributeZkV1

**Purpose**: Prove properties of the identity (age, jurisdiction, etc.) without revealing underlying attributes.

**Scope**:
* SID level
* Private by default, selectively disclosed

**Envelope**:
* `proof_type = IdentityAttributeZkV1`
* `verification_key = verifying key for the circuit`
* `public_inputs = circuit public inputs (e.g., commitment hash, claimed range)`
* `proof_data = zero-knowledge proof bytes`
* `circuit_hash = hash of circuit or proving key`

**Verification**:
1. Resolve circuit or verifying key via `circuit_hash` and `verification_key`.
2. Run the corresponding verifier with provided `public_inputs` and `proof_data`.

---

### 3.3 CredentialProofV1

**Purpose**: Prove that a trusted issuer has made a claim about a DID.

**Scope**:
* SID or DAO level
* May be public or private depending on use case

**Envelope**:
* `proof_type = CredentialProofV1`
* `verification_key = issuer public key`
* `public_inputs = hash of credential body (which must include recipient DID)`
* `proof_data = issuer signature over credential body`
* `circuit_hash = null`

**Verification**:
1. Recompute credential hash from the canonical credential representation.
2. Verify issuer signature over this hash.
3. Confirm recipient DID matches the identity under consideration.

---

### 3.4 DeviceDelegationV1

**Purpose**: Delegate a subset of capabilities from an identity to a device.

**Scope**:
* SID to device
* Useful for multi-device, family, and child devices

**Binding Message**:
```
DEVICE_DELEGATION_V1 || did_bytes || device_id || capability_scope
```

**Envelope**:
* `proof_type = DeviceDelegationV1`
* `verification_key = identity public signing key`
* `public_inputs = encoded message (did, device_id, capability_scope)`
* `proof_data = signature from identity over delegation message`
* `circuit_hash = null`

**Verification**:
1. Decode delegation message.
2. Verify signature with identity public key.
3. Check device and capability scope according to policy.

---

## 4. Proximity and Session Proofs

### 4.1 ProximityHandshakeV1

**Purpose**: Prove that a device physically present and announced over Bluetooth or WiFi Direct is controlled by a specific DID.

**Scope**:
* Device to device, local mesh
* Private, local to participating devices

**Binding Message**:
```
PROXIMITY_HANDSHAKE_V1 || did_bytes || timestamp || ephemeral_public_key
```

**Envelope**:
* `proof_type = ProximityHandshakeV1`
* `verification_key = device public key`
* `public_inputs = binding message`
* `proof_data = signature from device private key over binding message`
* `circuit_hash = null`

**Verification**:
1. Verify signature over the binding message.
2. Check timestamp freshness.
3. Optionally cross-check ephemeral key against further session derivation.

---

### 4.2 SessionKeyProofV1

**Purpose**: Prove that two devices engaged in a key exchange and derived a shared session key correctly.

**Scope**:
* Device to device
* Private, ephemeral

**Model**: Each side signs:
```
SESSION_KEY_V1 || own_ephemeral_pk || peer_ephemeral_pk || session_id
```

**Envelope**:
* `proof_type = SessionKeyProofV1`
* `verification_key = own long-term or delegated key`
* `public_inputs = encoded handshake parameters`
* `proof_data = signature over parameters`
* `circuit_hash = null`

Verification is protocol-specific but follows standard key-exchange authenticity rules.

---

## 5. Network and Data Proofs

### 5.1 StorageProofV1

**Purpose**: Prove that a node stores or has served a particular data chunk for a given epoch.

**Scope**:
* Node level
* May be public or private depending on incentive layer

**Binding Message**:
```
STORAGE_PROOF_V1 || chunk_hash || epoch_id
```

**Envelope**:
* `proof_type = StorageProofV1`
* `verification_key = node public key`
* `public_inputs = encoded (chunk_hash, epoch_id)`
* `proof_data = signature from node key over binding message`
* `circuit_hash = null`

**Verification**:
1. Check signature.
2. Check `chunk_hash` matches data.
3. Check epoch is valid within protocol rules.

---

### 5.2 RoutingProofV1

**Purpose**: Prove that a node forwarded a message during multi-hop routing.

**Scope**:
* Node to node along a route
* Optional but important for accountability or incentives

**Model**: Given previous hop signature `prev_sig` and message hash:
```
ROUTING_PROOF_V1 || message_hash || prev_sig
```

Current hop signs this.

**Envelope**:
* `proof_type = RoutingProofV1`
* `verification_key = current hop public key`
* `public_inputs = encoded (message_hash, prev_sig)`
* `proof_data = current hop signature`
* `circuit_hash = null`

Verification follows the relay chain.

---

### 5.3 TransportProofV1

**Purpose**: Prove end-to-end integrity and authenticity of delivered messages.

**Scope**:
* Sender to receiver
* Often private, but can be disclosed

**Model**:

Sender signs:
```
TRANSPORT_SEND_V1 || message_hash || timestamp
```

Receiver signs:
```
TRANSPORT_RECV_V1 || message_hash || timestamp
```

Each side has its own proof envelope with its own `verification_key` and `proof_data`.

---

## 6. SID Economy Proofs – Private

### 6.1 SidTransactionV1

**Purpose**: Express a private economic action between two sovereign identities without putting a raw transaction on a public ledger.

**Scope**:
* SID to SID
* Always private, backed by proofs

**Examples**:
* Private credits, balances, commitments
* Claims about prior transfers
* Off-chain agreements

**Model**: At minimum, a signed statement from sender over transaction content (which may itself be blinded, encrypted, or represented by a commitment).

**Envelope**:
* `proof_type = SidTransactionV1`
* `verification_key = sender identity key`
* `public_inputs = hash of transaction content (may include recipient DID in clear or in a commitment)`
* `proof_data = sender signature`
* `circuit_hash = optional if zero-knowledge is used`

Verification ensures the sender authorized the transaction content.

---

## 7. DAO and Governance Proofs – Public

### 7.1 DaoTransactionV1

**Purpose**: Record economic actions of DAOs in a public, auditable form.

**Scope**:
* DAO level
* Public, ledger-backed

**Examples**:
* Treasury transfers
* Funding decisions
* Parameter updates

**Envelope**:
* `proof_type = DaoTransactionV1`
* `verification_key = DAO or committee key or multi-signature aggregate`
* `public_inputs = hash of the DAO transaction payload`
* `proof_data = signature or multi-signature`
* `circuit_hash = null or used if rollup logic applies`

---

### 7.2 VotingV1

**Purpose**: Prove that a vote on a proposal comes from an eligible identity and is counted correctly.

**Scope**:
* DAO members or token holders
* Public in basic form, later can be upgraded to a zero-knowledge variant

**Envelope**:
* `proof_type = VotingV1`
* `verification_key = voter key or credential-bound key`
* `public_inputs = encoded (proposal_id, choice, weight)`
* `proof_data = voter signature`
* `circuit_hash = null`

Verification checks voter eligibility and double-voting according to governance rules.

---

### 7.3 StateTransitionV1

**Purpose**: Prove that a state transition on a DAO or shared ledger is valid.

**Scope**:
* DAO or shard level
* Public

**Model**: Sign relation between old root, new root, and applied batch:
```
STATE_TRANSITION_V1 || old_root || new_root || batch_hash
```

**Envelope**:
* `proof_type = StateTransitionV1`
* `verification_key = validator, committee, or rollup prover key`
* `public_inputs = encoded (old_root, new_root, batch_hash)`
* `proof_data = signature or zero-knowledge proof for rollup`
* `circuit_hash = optional for rollup-style proofs`

---

## 8. Proof Registry and Versioning

All proofs must be registered in a **ProofRegistry**:

* **Key**: `(ProofType, version)`
* **Value**: `ProofSpec`, which defines:
  * Required fields
  * Expected key sizes
  * Verification algorithm
  * Whether deprecated

**Rules**:
* Unknown proof types or versions **must cause errors**, not silent false returns.
* New versions create new `ProofType` variants, such as `VotingV2`.
* V1 proofs remain verifiable unless underlying cryptography is deprecated.
* DID version and proof version must both be considered during verification.

**Example Registry Entry**:
```rust
ProofRegistry {
    (ProofType::SignaturePopV1, "v1") => ProofSpec {
        required_fields: ["verification_key", "public_inputs", "proof_data"],
        key_size: 1312,  // Dilithium2 public key size
        verification_algorithm: verify_dilithium2,
        deprecated: false,
    },
    ...
}
```

---

## 9. Public vs Private Classification

### Private by Default:

* `SignaturePopV1` (ownership)
* `IdentityAttributeZkV1`
* `CredentialProofV1` (can be either)
* `DeviceDelegationV1`
* `ProximityHandshakeV1`
* `SessionKeyProofV1`
* `TransportProofV1`
* `SidTransactionV1`

### Public by Design:

* `StorageProofV1` (if tied to incentives)
* `RoutingProofV1` (if tied to incentives or audits)
* `DaoTransactionV1`
* `VotingV1`
* `StateTransitionV1`
* Some `CredentialProofV1` (if DAO or issuer wants public claims)

**Note**: The suite does not hard-force privacy or publicity at the code level, but the protocol and governance documents should.

---

## 10. Minimal Subset for MVP

### Must Have from Day One:

* `SignaturePopV1` - bind DID to PQC key
* `CredentialProofV1` - basic credentials
* `DeviceDelegationV1` - if multi-device support exists
* `StorageProofV1` - if using distributed storage
* `DaoTransactionV1` - DAO treasury operations
* `VotingV1` - DAO governance
* `StateTransitionV1` - DAO state management

### Can Add After MVP:

* `IdentityAttributeZkV1` - privacy-preserving age/jurisdiction proofs
* `ProximityHandshakeV1` - Bluetooth/WiFi mesh
* `SessionKeyProofV1` - session security
* `RoutingProofV1` - incentivized routing
* `TransportProofV1` - end-to-end message integrity
* `SidTransactionV1` - private SID economy

---

## 11. Serialization Requirements

### Canonical Format: CBOR

* All proofs **must** use canonical CBOR (RFC 8949) for deterministic serialization.
* CBOR Canonical rules:
  * Keys in maps sorted by byte encoding
  * Shortest possible encoding for integers
  * Deterministic encoding for floats

### JSON Debug Format

* JSON may be used for **debugging, logging, and human inspection only**.
* JSON **must not** be used for:
  * Hashing proof contents
  * Signature generation/verification
  * Cross-system proof exchange

### Migration Path

1. Implement CBOR serialization for `ProofEnvelope`
2. Implement per-type CBOR encoders for `public_inputs` and `proof_data`
3. Update `from_serialized()` to use CBOR decoder
4. Deprecate JSON-based proof storage (6-month transition)

---

## 12. Security Considerations

### Replay Attacks

* All proofs with temporal significance **must** include timestamps or nonces in `public_inputs`.
* Verifiers **must** check timestamp freshness according to proof type.

### Key Substitution

* DID and signing key binding is enforced via `SignaturePopV1` (mandatory).
* Device delegation requires chain of custody through `DeviceDelegationV1`.

### Cross-Circuit Confusion

* Each proof type has unique binding message prefix.
* `circuit_hash` prevents circuit substitution attacks.

### Malformed Proofs

* Schema validation **must** reject malformed proofs before verification.
* Unknown proof types **must** error (never silently accept).

---

## Consequences

### Positive

* ✅ Complete proof architecture for ZHTP V1
* ✅ Type-safe, enum-based dispatch (no string matching)
* ✅ Clear public/private boundaries
* ✅ Deterministic serialization (CBOR)
* ✅ Versioning and evolution path
* ✅ Security model enforcement
* ✅ MVP vs future work clearly defined

### Negative

* ⚠️ Requires complete rewrite of proof handling
* ⚠️ All 81 references to `ZeroKnowledgeProof` must migrate
* ⚠️ CBOR migration impacts all serialized data
* ⚠️ 13 proof types to implement and test

### Neutral

* 📋 Establishes foundation for Phase 2+ features
* 📋 Enables gradual rollout (MVP proofs first)
* 📋 Compatible with rollup/ZK-EVM future

---

## Alternatives Considered

1. **Continue with ungoverned ZeroKnowledgeProof** (rejected: unsafe, unscalable)
2. **Use Verifiable Credentials standard** (rejected: doesn't cover network/device proofs)
3. **Split into 13 separate ADRs** (rejected: suite coherence more important)
4. **Use JSON with canonicalization** (rejected: CBOR more robust)

---

## References

* ADR-0004: Root-Key-Anchored DID
* ADR-0002: Identity Proof Policy v1 (superseded by this ADR)
* RFC 8949: Concise Binary Object Representation (CBOR)
* NIST SP 800-208: CRYSTALS-Dilithium
* W3C Verifiable Credentials Data Model

---

## Revision History

* **2025-11-30**: Initial version (v1) - complete proof suite specification
