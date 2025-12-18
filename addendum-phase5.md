

# Addendum to Phase 5 Implementation Plan

## Web4 Domain Versioning and Update Semantics

---

## A. New Functional Requirements

1. Web4 domains MUST be **versioned pointers** to immutable manifest CIDs.
2. Domain updates MUST be **atomic, ordered, and authorization-checked**.
3. Historical versions MUST be **cryptographically linked and inspectable**.
4. Rollback MUST be supported without special cases.

---

## B. Protocol Extensions (Mandatory)

### B.1 New API Operations

Add the following ZHTP API paths:

```
POST /api/v1/web4/domains/resolve
POST /api/v1/web4/domains/update
GET  /api/v1/web4/domains/status/{domain}
GET  /api/v1/web4/domains/history/{domain}
```

These are **protocol operations**, not HTTP features.

---

### B.2 Domain Update Request

```
DomainUpdateRequest {
  domain: String
  new_manifest_cid: CID
  expected_previous_manifest_cid: CID
}
```

Rules:

* Update is rejected if `expected_previous_manifest_cid != current`
* Prevents concurrent overwrite
* Enforces linear history

---

## C. Data Model Changes (Node)

### C.1 Domain Record (Replace or Extend)

```
DomainRecord {
  domain: String
  current_manifest_cid: CID
  version: u64
  owner_did: DID
  updated_at: timestamp
}
```

---

### C.2 Manifest Structure (Extend)

```
Manifest {
  domain: String
  version: u64
  previous_manifest: Option<CID>
  build_hash: Hash
  files: [...]
}
```

Validation rules:

* `version == previous.version + 1`
* `previous_manifest` required for version > 1
* Manifest CID must match payload

---

## D. CLI Pipeline Changes

### D.1 Deploy Flow (Revised)

Replace the previous deploy sequence with:

1. Resolve domain record
2. Fetch current manifest CID + version
3. Verify ownership
4. Build new content
5. Generate manifest with:

   * incremented version
   * previous manifest CID
6. Upload blobs
7. Upload manifest
8. Submit domain update request
9. Verify node-returned state

---

### D.2 New CLI Commands

```
zhtp domain status <domain>
zhtp domain history <domain>
zhtp domain rollback <domain> --to-version <n>
```

Rollback = deploy with old manifest CID.

---

## E. Authorization and Safety Guarantees

Must be enforced at handler level:

* Only owner DID can update
* Version monotonicity enforced
* Atomic compare-and-swap on update
* No mutable pointers without signature

---

## F. Testing Additions

### F.1 Unit Tests

* Version increment enforcement
* Manifest chain validation

### F.2 Integration Tests

* Concurrent update rejection
* Rollback correctness

### F.3 E2E

* v1 → v2 → v3 deploy
* rollback v4 → v2 content
* history inspection

---

## G. Documentation Artifacts to Add

* Web4 Versioning Spec (protocol doc)
* Domain lifecycle diagram
* CLI deploy/update/rollback sequence diagrams

---




