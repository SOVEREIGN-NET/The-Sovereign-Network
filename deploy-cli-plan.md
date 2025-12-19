# ZHTP Phase 5 — React Deployment Pipeline (No-Shortcuts Implementation Plan)

## 1. Scope and Objective

Implement a production-grade `zhtp deploy` CLI command that publishes static Web4 content to a ZHTP node using the native QUIC + UHP transport, stores content in the DHT, and registers a Web4 domain that resolves to the deployed content.

**Non-goals**

* No HTTP gateways
* No unauthenticated or dev-only transports
* No protocol shortcuts or duplicated handler logic

---

## 2. Target Command

```
zhtp deploy <build_dir> --domain <domain.zhtp> [--node <node_addr>] [--identity <key_ref>]
```

---

## 3. Architecture Overview

### 3.1 Components

**CLI**

* Filesystem walker
* Content chunker and hasher
* Manifest builder
* QUIC client
* Web4 client API

**Protocol**

* Binary wire format for `ZhtpRequest` / `ZhtpResponse`
* Authenticated session over QUIC + UHP

**Node**

* QUIC inbound dispatcher
* ZHTP request router
* Existing Web4 handlers (unchanged)

---

## 4. Wire Protocol Definition

### 4.1 Request Envelope (`ZhtpRequestWire`)

Fields (mandatory unless noted):

* `version: u16`
* `request_id: [u8; 16]`
* `timestamp_ms: u64`
* `method: enum { GET, POST }`
* `path: String`
* `headers: Map<String, Bytes>` (optional)
* `body: Bytes`
* `auth_context: AuthContext` (derived from UHP handshake, not user-supplied)

### 4.2 Response Envelope (`ZhtpResponseWire`)

* `request_id: [u8; 16]`
* `status: u16`
* `headers: Map<String, Bytes>` (optional)
* `body: Bytes`
* `error_code: Option<u16>`
* `error_message: Option<String>`

### 4.3 Serialization

* Encoding: CBOR or bincode (single standard, frozen)
* Compression: optional, negotiated per session
* Framing: length-prefixed messages over QUIC streams

---

## 5. Transport Layer (CLI)

### 5.1 QUIC Client

* Reuse `QuicMeshProtocol`
* One connection per deploy invocation
* Multiplex multiple request streams

### 5.2 Identity and Security

* Load deploy identity from local keystore
* Perform UHP handshake:

  * Dilithium signature authentication
  * Kyber KEM key exchange
  * Transcript binding and session key derivation
* Verify remote node identity before proceeding

---

## 6. Node-Side QUIC Dispatch

### 6.1 Inbound Flow

1. QUIC connection accepted
2. UHP handshake completed
3. Incoming stream frames decoded into `ZhtpRequestWire`
4. Convert to internal `ZhtpRequest`
5. Route through existing handler registry
6. Serialize `ZhtpResponse` back to wire format
7. Return response over same stream

### 6.2 Handler Compatibility

* Web4 handlers remain unchanged
* All API access occurs through native ZHTP protocol

---

## 7. Web4 Client API (CLI)

### 7.1 Typed Client Methods

* `put_blob(bytes) -> ContentId`
* `put_manifest(manifest_bytes) -> ContentId`
* `register_domain(domain, manifest_cid)`
* `publish_domain(domain, manifest_cid)`

### 7.2 Internal Mapping

Each method maps to:

* `ZhtpRequest { method, path, body }`
* Example:

  * `POST /api/v1/web4/content/publish`
  * `POST /api/v1/web4/domains/register`

---

## 8. Deploy Pipeline

### 8.1 Filesystem Collection

* Recursive directory walk
* Deterministic path normalization
* Stable sort order

### 8.2 Content Processing

* MIME type detection
* Optional compression
* Content-addressed hashing
* Chunking for large files

### 8.3 Manifest Generation

Manifest fields:

* `domain`
* `root_cid`
* `files[]`:

  * `path`
  * `cid`
  * `size`
  * `mime`
  * `encoding`
  * `etag`
* SPA fallback rules (optional)
* Cache-control hints (optional)

### 8.4 Upload Sequence

1. Upload all blobs (deduplicated by CID)
2. Upload manifest
3. Register domain
4. Publish domain → manifest CID

---

## 9. Authorization Model

* Domain ownership bound to deploy identity
* Node validates:

  * identity is authorized to register domain
  * identity is authorized to publish updates
* Enforced at handler layer

---

## 10. Error Handling and Idempotency

* Content uploads are idempotent (CID-based)
* Manifest upload verified against local hash
* Retries allowed on transport failure
* Partial deploys can resume safely

---

## 11. Testing Strategy

### 11.1 Unit Tests

* Deterministic hashing
* Manifest stability
* Wire encoding/decoding

### 11.2 Integration Tests

* In-process QUIC client ↔ node
* Web4 publish and fetch roundtrip
* Auth failure cases

### 11.3 End-to-End Tests

* Deploy against live node
* Fetch content via Web4 GET API
* Verify domain resolution correctness

---

## 12. Deliverables

* `zhtp deploy` command
* QUIC-based CLI transport
* Frozen ZHTP wire protocol
* Web4 client API
* Full test coverage for deploy path

---

## 13. Completion Criteria

* No HTTP dependencies in deploy path
* All Web4 interactions over authenticated QUIC
* Deterministic, resumable deploys
* Same handlers used by all transports
* Production-ready security posture
