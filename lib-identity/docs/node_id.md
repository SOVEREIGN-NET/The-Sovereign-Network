# NodeId

**Canonical 32-byte routing address for the Sovereign Network**

---

## Overview

`NodeId` is the **network identity of a citizen's device** inside the Sovereign Network.
If a DID identifies the **person**, the NodeId identifies the **device**.

Each device (phone, laptop, server, IoT unit) receives a deterministic NodeId derived from:

* the citizen's **DID**
* a human-readable **device name**

This guarantees:

* unique identity per device
* stable identity over time
* valid DHT address (32 bytes)
* compatibility with decentralized routing, storage, and rewards

NodeId underpins the **Sovereign Network's P2P layer**, enabling storage, routing, discovery, and ZHTP infrastructure rewards.

---

## High-Level Diagram

```mermaid
flowchart LR
    Citizen["Citizen DID\n(e.g., did:zhtp:abc123...)"]
    DeviceLabel["Device name\n(e.g., laptop, phone.backup)"]

    subgraph LibIdentity["lib_identity::types::NodeId"]
        A["from_did_device(did, device)"]
        B["Validate + normalize input"]
        C["Hash(\"ZHTP_NODE_V2:\" + did + \":\" + device_norm) - Full 32 bytes"]
        D["NodeId([u8; 32])"]
    end

    subgraph NetworkUsage["Where NodeId is used"]
        R1["DHT routing\nxor_distance()"]
        R2["Storage key\nto_storage_hash()"]
        R3["APIs / logs\nDisplay, to_hex(), from_hex()"]
    end

    Citizen --> A
    DeviceLabel --> A
    A --> B --> C --> D
    D --> R1
    D --> R2
    D --> R3
```

---

## Functional Purpose

### 1. Identity for every device

NodeId allows each user device to join the decentralized network and:

* route messages
* participate in cluster formation
* store or serve data
* earn ZHTP infrastructure rewards
* act as a sovereign network node

### 2. Deterministic and privacy-safe

NodeId links to a DID but exposes **no personal information**.

### 3. Valid for decentralized routing

32 bytes matches the standard size used by Kademlia/BitTorrent, enabling:

* nearest neighbor search
* routing table buckets
* efficient peer discovery

### 4. Strict validation & normalization

Prevents malformed devices or spoofed nodes from entering the network.

### 5. Easy to store, serialize, and display

Supports:

* hex representation
* 32-byte bytes
* 32-byte padded hashes
* serde serialization

---

# Developer Specification

Below is the consolidated, authoritative spec for implementing or using `NodeId`.

---

## 1. Data Type

```rust
pub struct NodeId([u8; 32]);
```

Properties:

* 32-byte fixed binary value
* `Serialize` / `Deserialize`
* Implements `Display` → 64-char lowercase hex

---

## 2. Constructor: `from_did_device`

```rust
pub fn from_did_device(did: &str, device: &str) -> Result<NodeId>;
```

### 2.1 Deterministic

* Same `(did, device)` → same NodeId every time.
* Same DID, different device names → different NodeIds.

---

### 2.2 DID validation

The DID **must**:

* be non-empty
* start with `did:zhtp:`
* anything else (`did:web:...`, bare strings) is rejected

Error messages must mention the expected prefix for clarity.

---

### 2.3 Device name validation

**Normalization:**

* `trim()` spaces
* `to_lowercase()`

**Constraints:**

* non-empty after trim
* maximum length: **64 characters**
* allowed characters:

  ```
  a-z  0-9  .  _  -
  ```
* invalid examples:

  * spaces inside (`"my laptop"`)
  * punctuation (`"phone!"`, `"laptop#1"`)
  * symbols (`"device@home"`)

---

### 2.4 Hashing rule

Canonical preimage:

```
"ZHTP_NODE_V2:" + <did> + ":" + <normalized_device>
```

Hashing:

```
bytes = blake3(preimage)[0..32]
NodeId(bytes)
```

* Domain separated (`ZHTP_NODE_V2:`)
* Stable over time
* Resistant to collisions
* Ensures identity isolation between DID/device pairs

---

## 3. Accessors

```rust
fn as_bytes(&self) -> &[u8; 32];
fn from_bytes(bytes: [u8; 32]) -> NodeId;
```

Round-trip must preserve bit-exact identity.

---

## 4. Hex Conversion

```rust
fn to_hex(&self) -> String;
fn from_hex(hex: &str) -> Result<NodeId>;
```

**Rules:**

* 64 hex chars exactly
* lowercase expected from `Display`
* reject non-hex characters
* reject wrong length

Round-trip must be exact.

---

## 5. Storage Hash Conversion (20 ↔ 32 bytes)

```rust
fn to_storage_hash(&self) -> Hash;      // padded to 32 bytes
fn from_storage_hash(h: &Hash) -> NodeId;
```

**Rules:**

* `to_storage_hash()`:
  - First 32 bytes = NodeId
  - Last 12 bytes = zero padding
* `from_storage_hash()`:
  - Extracts first 32 bytes only
  - **Padding bytes are ignored** (not validated)
  - Allows compatibility with storage systems that don't preserve padding
* Round-trip must return original NodeId

Used for:

* database keys
* systems standardized on 32-byte hashes
* backward compatibility with Hash-based storage

---

## 6. XOR Distance (DHT metric)

```rust
fn xor_distance(&self, other: &NodeId) -> [u8; 32];
```

Rules:

* distance(self, self) = all zeros
* symmetric
* non-zero for different NodeIds

Used in routing, bucket placement, and peer selection.

---

## 7. Display

```rust
impl Display for NodeId {
    // prints 64-char lowercase hex
}
```

This must always be identical to `to_hex()`.

---

# Summary

`NodeId` is the **foundation of device-level identity** in the Sovereign Network:

* deterministic
* validated
* stable
* compatible with decentralized networking
* easy to serialize and recover
* safe from malformed inputs

It enables each citizen device to act as a sovereign, verifiable, privacy-respecting node in the global network.
