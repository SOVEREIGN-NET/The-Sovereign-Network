# lib-dns Architectural Integration
## How ZDNS Fits Into the Sovereign Mesh Network

> **Document Version:** 1.1
> **Last Updated:** 2026-01-17
> **Status:** Reference Architecture

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Sovereign Mesh Architecture](#2-the-sovereign-mesh-architecture)
3. [Plane Separation Principle](#3-plane-separation-principle)
4. [Where lib-dns Fits](#4-where-lib-dns-fits)
5. [ZDNS Record Types for Mesh](#5-zdns-record-types-for-mesh)
6. [Integration with NPU-Accelerated Control Plane](#6-integration-with-npu-accelerated-control-plane)
7. [Offline-First Operation](#7-offline-first-operation)
8. [Data Flow Examples](#8-data-flow-examples)
9. [Implementation Roadmap](#9-implementation-roadmap)
10. [API Surface](#10-api-surface)
11. [**Resolver Invariants & Constraints**](#11-resolver-invariants--constraints) *(Critical)*
12. [**Negative Answers & Partitions**](#12-negative-answers--partitions) *(Critical)*
13. [**Bootstrap Trust Model**](#13-bootstrap-trust-model) *(Critical)*
14. [**Client Resolution Contract**](#14-client-resolution-contract) *(Critical)*
15. [**Forbidden Behaviors**](#15-forbidden-behaviors) *(Critical)*
16. [**Zone Scoping & Federation**](#16-zone-scoping--federation)
17. [**Update Amplification Control**](#17-update-amplification-control)

---

## 1. Executive Summary

lib-dns provides the **naming foundation** for the Sovereign Network's decentralized mesh. It answers the question **"what is this name?"** while leaving **"how do I reach it?"** to the NPU-accelerated control plane.

**Core Principles:**

| Principle | Implementation |
|-----------|----------------|
| DNS stays fast | Aggressive caching, local zone files |
| DNS stays dumb | No per-packet decisions, no AI inference |
| DNS feeds intelligence | Returns multiple endpoints for AI to choose from |
| DNS works offline | Zone files distributed via mesh, no Internet required |
| Blockchain never in hot path | Identity anchored async, cached locally |

**lib-dns is NOT:**
- A routing protocol
- A packet forwarder
- A blockchain query interface
- An AI inference engine

**lib-dns IS:**
- A name-to-identity resolver
- A service discovery mechanism
- A mesh endpoint locator
- A cacheable, offline-capable naming system

---

## 2. The Sovereign Mesh Architecture

### 2.1 Network Planes Overview

The network operates on clearly separated planes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SOVEREIGN MESH NETWORK                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        APPLICATION PLANE                                │ │
│  │                                                                         │ │
│  │   ZHTP Server  │  Wallet Service  │  Local Apps  │  Web4 Content       │ │
│  │                                                                         │ │
│  │   • End-to-end encrypted sessions (QUIC)                               │ │
│  │   • Cryptographic identity above transport                              │ │
│  │   • Peer-to-peer communication                                          │ │
│  │   • Trust established without external authorities                      │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                        │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         NAMING PLANE                                    │ │
│  │                        (lib-dns / ZDNS)                                 │ │
│  │                                                                         │ │
│  │   • Decentralized name resolution                                       │ │
│  │   • Identity binding (name → public key)                                │ │
│  │   • Service endpoint discovery                                          │ │
│  │   • Offline-capable, cacheable, partition-tolerant                     │ │
│  │   • No assumption of global consistency                                 │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                        │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                     INTELLIGENT CONTROL PLANE                           │ │
│  │                    (NPU-Accelerated / NeuroPilot)                       │ │
│  │                                                                         │ │
│  │   • Observes: latency, congestion, peer reputation                     │ │
│  │   • Predicts: failures, optimal paths, pre-warming                     │ │
│  │   • Outputs: policy tables, route preferences                          │ │
│  │   • Coordinates via: LoRa control messages                             │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                        │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          DATA PLANE                                     │ │
│  │                    (802.11s WiFi Mesh + FastPath)                       │ │
│  │                                                                         │ │
│  │   • Pure packet forwarding at line rate                                │ │
│  │   • No identity, trust, naming, or application logic                   │ │
│  │   • Multi-hop frame forwarding without APs or controllers              │ │
│  │   • Mesh nodes are untrusted forwarders of encrypted traffic           │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                     │                                        │
│                                     ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                      LoRa COORDINATION PLANE                            │ │
│  │                    (Infrastructure Nodes Only)                          │ │
│  │                                                                         │ │
│  │   • Presence and liveness beacons                                      │ │
│  │   • Rendezvous hints ("try WiFi channel 6")                            │ │
│  │   • AI-derived mesh health signals                                      │ │
│  │   • Never carries user data or full handshakes                         │ │
│  │   • 2-15km range, ~300bps bandwidth                                    │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    BLOCKCHAIN (Async, Authoritative)                    │ │
│  │                                                                         │ │
│  │   • Node identity anchoring                     Sync: Minutes          │ │
│  │   • Capability issuance                         Never in data path     │ │
│  │   • Economic incentives and settlement          Local cache only       │ │
│  │   • Revocation and slashing                     Signed policy bundles  │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Device Roles

| Device Type | Mesh Participation | lib-dns Role |
|-------------|-------------------|--------------|
| **Infrastructure Node** | Full 802.11s mesh participant | Authoritative ZDNS server, zone hosting |
| **Gateway Node** | Mesh + Client AP bridge | ZDNS resolver, cache |
| **Phone/User Device** | WiFi client only (not mesh) | ZDNS client, local cache |
| **LoRa-enabled Node** | Mesh + LoRa control | ZDNS server + control plane hints |

### 2.3 Internet Independence

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONNECTIVITY MODES                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FULLY ISOLATED (No Internet)                                    │
│  ─────────────────────────────                                   │
│  • lib-dns resolves from local zone files                       │
│  • Zone files distributed via mesh gossip                        │
│  • All services operate normally                                 │
│  • Economic transactions queue for later settlement              │
│                                                                  │
│  PARTIALLY CONNECTED (Some uplinks)                              │
│  ────────────────────────────────                                │
│  • lib-dns can optionally query external resolvers              │
│  • Blockchain syncs when possible                                │
│  • Federation with other mesh networks                           │
│                                                                  │
│  FULLY CONNECTED (Internet available)                            │
│  ───────────────────────────────────                             │
│  • Internet used as external bridge only                         │
│  • Core naming still via lib-dns                                 │
│  • Can resolve traditional DNS for compatibility                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Plane Separation Principle

### 3.1 Time Scale Requirements

The fundamental architecture rule: **Never put slow things in fast paths.**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LATENCY REQUIREMENTS BY PLANE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PLANE              │ LATENCY BUDGET │ OPERATIONS                           │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  DATA PLANE         │ < 1μs          │ Packet forward, frame switch,        │
│  (FastPath/PPE)     │                │ hardware encrypt/decrypt              │
│                     │                │                                       │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  NPU INFERENCE      │ 10-100μs       │ Path scoring, peer classification,   │
│  (NeuroPilot)       │                │ anomaly detection                     │
│                     │                │                                       │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  lib-dns RESOLUTION │ 1-10ms         │ Cache lookup, local zone query       │
│  (Cached)           │                │                                       │
│                     │                │                                       │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  lib-dns RESOLUTION │ 10-100ms       │ Recursive resolution, mesh query     │
│  (Uncached)         │                │                                       │
│                     │                │                                       │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  CONTROL PLANE      │ 100ms-1s       │ Policy computation, route            │
│  (Software)         │                │ recalculation, peer scoring          │
│                     │                │                                       │
│  ────────────────────────────────────────────────────────────────────────── │
│                     │                │                                       │
│  BLOCKCHAIN         │ 1s-60s         │ Identity verification, capability    │
│  (Consensus)        │                │ check, economic settlement           │
│                     │                │                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 What Each Plane Handles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              RESPONSIBILITY MATRIX                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  QUESTION                        │ ANSWERED BY        │ LATENCY              │
│  ────────────────────────────────────────────────────────────────────────── │
│                                  │                    │                      │
│  "What is alice.sovereign?"      │ lib-dns            │ 1-100ms (cached)     │
│  "What key does alice use?"      │ lib-dns (ID record)│ 1-100ms              │
│  "Where can I reach alice?"      │ lib-dns (MESH/SRV) │ 1-100ms              │
│                                  │                    │                      │
│  "Which endpoint is fastest?"    │ NPU Control Plane  │ 10-100μs             │
│  "Is this path congested?"       │ NPU Control Plane  │ 10-100μs             │
│  "Should I pre-warm connection?" │ NPU Control Plane  │ 10-100μs             │
│                                  │                    │                      │
│  "Forward this packet"           │ Data Plane         │ < 1μs                │
│  "Encrypt this frame"            │ Data Plane         │ < 1μs                │
│                                  │                    │                      │
│  "Is this node authorized?"      │ Blockchain Cache   │ Local: μs            │
│  "What capabilities does it have?"│ Blockchain Cache  │ Sync: minutes        │
│  "Settle this transaction"       │ Blockchain         │ Seconds              │
│                                  │                    │                      │
│  "Who is nearby on mesh?"        │ LoRa Control       │ Seconds (async)      │
│  "What channel should I use?"    │ LoRa Control       │ Seconds (async)      │
│                                  │                    │                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 lib-dns Does NOT

| Anti-Pattern | Why It's Wrong | Correct Approach |
|--------------|----------------|------------------|
| Query blockchain per resolution | Adds seconds of latency | Cache blockchain state locally |
| Make routing decisions | Not its job, breaks separation | Return endpoints, let control plane choose |
| Per-packet processing | Far too slow | Resolve once, cache, route many |
| AI inference | Wrong layer | NPU handles intelligent decisions |
| Replace system DNS | Compatibility nightmare | Augment, integrate alongside |

---

## 4. Where lib-dns Fits

### 4.1 Architectural Position

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                            APPLICATION                                       │
│                    ┌─────────────────────────┐                              │
│                    │   "Connect to alice"    │                              │
│                    └───────────┬─────────────┘                              │
│                                │                                             │
│                                ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                          ││
│  │                         lib-dns / ZDNS                                   ││
│  │                                                                          ││
│  │  ┌────────────────────────────────────────────────────────────────────┐ ││
│  │  │                                                                     │ ││
│  │  │   INPUT: "alice.sovereign"                                         │ ││
│  │  │                                                                     │ ││
│  │  │   OUTPUT:                                                          │ ││
│  │  │   {                                                                │ ││
│  │  │     "identity": {                                                  │ ││
│  │  │       "node_id": "0x7f3a8b2c...",                                 │ ││
│  │  │       "public_key": "ed25519:Hx7Kj9...",                          │ ││
│  │  │       "ownership_proof": "zk:abc123..."                           │ ││
│  │  │     },                                                             │ ││
│  │  │     "endpoints": [                                                 │ ││
│  │  │       { "addr": "10.mesh.1.5:9333", "priority": 1 },              │ ││
│  │  │       { "addr": "10.mesh.2.7:9333", "priority": 2 },              │ ││
│  │  │       { "addr": "10.mesh.3.2:9333", "priority": 3 }               │ ││
│  │  │     ],                                                             │ ││
│  │  │     "dht_nodes": ["node1.local", "node2.local"],                  │ ││
│  │  │     "services": {                                                  │ ││
│  │  │       "zhtp": { "port": 9333, "protocol": "quic" },               │ ││
│  │  │       "content": { "port": 8080, "protocol": "http" }             │ ││
│  │  │     },                                                             │ ││
│  │  │     "ttl": 300                                                     │ ││
│  │  │   }                                                                │ ││
│  │  │                                                                     │ ││
│  │  └────────────────────────────────────────────────────────────────────┘ ││
│  │                                                                          ││
│  └──────────────────────────────────┬──────────────────────────────────────┘│
│                                     │                                        │
│                                     │ Multiple endpoints returned            │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                          ││
│  │                    NPU-ACCELERATED CONTROL PLANE                         ││
│  │                                                                          ││
│  │   Receives: 3 possible endpoints for alice.sovereign                    ││
│  │                                                                          ││
│  │   Evaluates:                                                             ││
│  │   • Endpoint 1 (10.mesh.1.5): 15ms latency, 0.1% loss, reputation: 95  ││
│  │   • Endpoint 2 (10.mesh.2.7): 25ms latency, 0.0% loss, reputation: 98  ││
│  │   • Endpoint 3 (10.mesh.3.2): 8ms latency, 2.0% loss, reputation: 87   ││
│  │                                                                          ││
│  │   NPU Inference (50μs):                                                  ││
│  │   • Interactive session → prefer low latency → Endpoint 1               ││
│  │   • Bulk transfer → prefer reliability → Endpoint 2                     ││
│  │   • Fallback if primary fails → Endpoint 3                              ││
│  │                                                                          ││
│  │   Outputs: Policy table update                                           ││
│  │                                                                          ││
│  └──────────────────────────────────┬──────────────────────────────────────┘│
│                                     │                                        │
│                                     │ Pre-computed policy                    │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                          ││
│  │                           DATA PLANE                                     ││
│  │                                                                          ││
│  │   Policy Table Entry:                                                    ││
│  │   alice.sovereign → 10.mesh.1.5:9333 (primary)                          ││
│  │                   → 10.mesh.2.7:9333 (fallback)                         ││
│  │                                                                          ││
│  │   Forwards packets at line rate using pre-computed decision             ││
│  │                                                                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 lib-dns Internal Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                              lib-dns CRATE                                   │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         PUBLIC API (lib.rs)                              ││
│  │                                                                          ││
│  │   pub mod messages;    // DNS wire format, parsing, serialization       ││
│  │   pub mod rr_data;     // Resource record data types                    ││
│  │   pub mod zone;        // Zone file parsing and management              ││
│  │   pub mod keyring;     // DNSSEC key management                         ││
│  │   pub mod journal;     // Incremental zone transfer                     ││
│  │   pub mod utils;       // Encoding, hashing, trie                       ││
│  │                                                                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │    messages/    │  │    rr_data/     │  │     zone/       │             │
│  │                 │  │                 │  │                 │             │
│  │  message.rs     │  │  in_a_rr_data   │  │  zone.rs        │             │
│  │  record.rs      │  │  aaaa_rr_data   │  │  zone_store.rs  │             │
│  │  rr_query.rs    │  │  cname_rr_data  │  │  zone_reader.rs │             │
│  │  wire.rs        │  │  mx_rr_data     │  │  rr_set.rs      │             │
│  │  edns.rs        │  │  srv_rr_data    │  │                 │             │
│  │  tsig.rs        │  │  txt_rr_data    │  │  inter/         │             │
│  │                 │  │  soa_rr_data    │  │   zone_rr_data  │             │
│  │  inter/         │  │  ns_rr_data     │  │                 │             │
│  │   op_codes      │  │  https_rr_data  │  └─────────────────┘             │
│  │   rr_types      │  │  svcb_rr_data   │                                  │
│  │   rr_classes    │  │  dnskey_rr_data │  ┌─────────────────┐             │
│  │   response_codes│  │  rrsig_rr_data  │  │    keyring/     │             │
│  │                 │  │  nsec_rr_data   │  │                 │             │
│  └─────────────────┘  │  nsec3_rr_data  │  │  keyring.rs     │             │
│                       │  ds_rr_data     │  │  key.rs         │             │
│  ┌─────────────────┐  │  tsig_rr_data   │  │  grant.rs       │             │
│  │    journal/     │  │  tkey_rr_data   │  │                 │             │
│  │                 │  │  sshfp_rr_data  │  │  inter/         │             │
│  │  journal.rs     │  │  ...            │  │   algorithms    │             │
│  │  journal_reader │  │                 │  │                 │             │
│  │  txn.rs         │  │  inter/         │  └─────────────────┘             │
│  │                 │  │   rr_data       │                                  │
│  │  inter/         │  │   svc_param     │  ┌─────────────────┐             │
│  │   txn_op_codes  │  │                 │  │     utils/      │             │
│  │                 │  └─────────────────┘  │                 │             │
│  └─────────────────┘                       │  base64.rs      │             │
│                                            │  base32.rs      │             │
│                                            │  hex.rs         │             │
│                                            │  fqdn_utils.rs  │             │
│                                            │  hash/          │             │
│                                            │  trie/          │             │
│                                            │                 │             │
│                                            └─────────────────┘             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Integration Points

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         lib-dns INTEGRATION POINTS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  UPSTREAM (Depends on lib-dns)                                              │
│  ─────────────────────────────                                              │
│                                                                              │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │  lib-protocols  │     │      zhtp       │     │   lib-network   │       │
│  │                 │     │                 │     │                 │       │
│  │  ZDNS module    │     │  DNS handler    │     │  Peer registry  │       │
│  │  uses lib-dns   │     │  API endpoint   │     │  name lookup    │       │
│  │  wire format    │     │  /api/dns/*     │     │                 │       │
│  │                 │     │                 │     │                 │       │
│  └────────┬────────┘     └────────┬────────┘     └────────┬────────┘       │
│           │                       │                       │                 │
│           └───────────────────────┼───────────────────────┘                 │
│                                   │                                         │
│                                   ▼                                         │
│                         ┌─────────────────┐                                 │
│                         │                 │                                 │
│                         │    lib-dns      │                                 │
│                         │                 │                                 │
│                         └─────────────────┘                                 │
│                                   │                                         │
│                                   │                                         │
│  DOWNSTREAM (lib-dns depends on)  │                                         │
│  ───────────────────────────────  │                                         │
│                                   ▼                                         │
│                         ┌─────────────────┐                                 │
│                         │                 │                                 │
│                         │     (none)      │  ← Zero external dependencies   │
│                         │                 │                                 │
│                         └─────────────────┘                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. ZDNS Record Types for Mesh

### 5.1 Standard DNS Records (lib-dns)

These are RFC-compliant DNS record types implemented in lib-dns:

| Type | Purpose in Mesh | Example |
|------|-----------------|---------|
| **A** | IPv4 mesh-local address | `alice.sovereign. 300 IN A 10.42.0.5` |
| **AAAA** | IPv6 mesh-local address | `alice.sovereign. 300 IN AAAA fd00:mesh::5` |
| **CNAME** | Alias to another name | `www.alice.sovereign. CNAME alice.sovereign.` |
| **SRV** | Service location with port/priority | `_zhtp._quic.alice.sovereign. SRV 10 100 9333 node1.mesh.` |
| **TXT** | Arbitrary text data | `alice.sovereign. TXT "pubkey=ed25519:Hx7..."` |
| **MX** | Mail routing | `alice.sovereign. MX 10 mail.alice.sovereign.` |
| **NS** | Nameserver delegation | `sovereign. NS ns1.sovereign.` |
| **SOA** | Zone authority | `sovereign. SOA ns1.sovereign. admin.sovereign. ...` |
| **HTTPS** | HTTPS service binding | `alice.sovereign. HTTPS 1 . alpn="h2,h3"` |
| **SVCB** | Generic service binding | `_api.alice.sovereign. SVCB 1 . port=8443` |

### 5.2 ZDNS Extended Records (lib-protocols)

These are Sovereign Network extensions built on top of lib-dns:

| Type | Purpose | Data Format |
|------|---------|-------------|
| **MESH** | Mesh node endpoint | Node ID + mesh address |
| **ZK** | Zero-knowledge proof | Proof data for ownership verification |
| **ID** | Identity binding | Public key + verification method |
| **DAO** | DAO governance | Governance parameters |
| **ECON** | Economic config | Fee structure, revenue sharing |
| **CONTENT** | Content hash | IPFS/DHT content identifier |
| **MULTISIG** | Multi-signature | Required signers, threshold |
| **PQS** | Post-quantum signature | Dilithium/Kyber signature |
| **WEB4** | Web4 domain registry | Domain metadata |
| **WEB4CONTENT** | Content mapping | Path → content hash |
| **WEB4OWNER** | Ownership verification | ZK proof of ownership |
| **WEB4DHT** | DHT node record | DHT node for content |
| **WEB4MESH** | Mesh endpoint | Mesh service endpoint |

### 5.3 Zone File Example

```dns
; Sovereign Network Zone File
; Zone: sovereign.
; Offline-capable, mesh-distributed

$ORIGIN sovereign.
$TTL 300

; Zone authority
@       IN  SOA     ns1.sovereign. admin.sovereign. (
                    2026011701  ; Serial
                    3600        ; Refresh
                    900         ; Retry
                    604800      ; Expire
                    300         ; Minimum TTL
                    )

; Nameservers (mesh nodes that host this zone)
@       IN  NS      ns1.sovereign.
@       IN  NS      ns2.sovereign.
@       IN  NS      ns3.sovereign.

ns1     IN  A       10.42.0.1
ns2     IN  A       10.42.0.2
ns3     IN  A       10.42.0.3

; User: alice
alice   IN  A       10.42.1.5
alice   IN  AAAA    fd00:mesh:1::5
alice   IN  TXT     "node_id=0x7f3a8b2c..."
alice   IN  TXT     "pubkey=ed25519:Hx7Kj9mNpQrS..."
alice   IN  TXT     "zk_proof=groth16:abc123..."

; Alice's services
_zhtp._quic.alice   IN  SRV     10 100 9333 alice.sovereign.
_zhtp._quic.alice   IN  SRV     20 100 9333 alice-backup.sovereign.
_content._tcp.alice IN  SRV     10 100 8080 alice.sovereign.

; Alice's HTTPS binding (modern service discovery)
alice   IN  HTTPS   1 . alpn="h3,h2" port=9333

; Alice's mesh endpoints (multiple paths)
alice   IN  TXT     "mesh_endpoint=10.42.1.5:9333,priority=1"
alice   IN  TXT     "mesh_endpoint=10.42.2.7:9333,priority=2"
alice   IN  TXT     "mesh_endpoint=10.42.3.2:9333,priority=3"

; Alice's DHT nodes for content
alice   IN  TXT     "dht_node=node1.sovereign"
alice   IN  TXT     "dht_node=node2.sovereign"

; Alice's backup node
alice-backup    IN  A       10.42.2.7
alice-backup    IN  AAAA    fd00:mesh:2::7

; Service: shared-storage
shared-storage  IN  A       10.42.0.10
_dht._udp.shared-storage    IN  SRV     10 100 4001 shared-storage.sovereign.

; Gateway nodes (bridge to client WiFi)
gateway1    IN  A       10.42.0.100
gateway2    IN  A       10.42.0.101
```

### 5.4 Resolution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RESOLUTION FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  App: "I want to connect to alice.sovereign"                                │
│                                                                              │
│  Step 1: ZDNS Query                                                         │
│  ───────────────────                                                        │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Query: alice.sovereign ANY                                          │   │
│  │                                                                      │   │
│  │  Response:                                                           │   │
│  │    alice.sovereign.  300  IN  A      10.42.1.5                      │   │
│  │    alice.sovereign.  300  IN  AAAA   fd00:mesh:1::5                 │   │
│  │    alice.sovereign.  300  IN  TXT    "node_id=0x7f3a8b2c..."        │   │
│  │    alice.sovereign.  300  IN  TXT    "pubkey=ed25519:Hx7Kj9..."     │   │
│  │    alice.sovereign.  300  IN  HTTPS  1 . alpn="h3,h2" port=9333     │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Step 2: Service Discovery Query                                            │
│  ───────────────────────────────                                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Query: _zhtp._quic.alice.sovereign SRV                              │   │
│  │                                                                      │   │
│  │  Response:                                                           │   │
│  │    _zhtp._quic.alice.sovereign.  300  IN  SRV  10 100 9333 alice.   │   │
│  │    _zhtp._quic.alice.sovereign.  300  IN  SRV  20 100 9333 alice-b. │   │
│  │                                                                      │   │
│  │  Additional:                                                         │   │
│  │    alice.sovereign.         300  IN  A     10.42.1.5                │   │
│  │    alice-backup.sovereign.  300  IN  A     10.42.2.7                │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Step 3: App receives structured data                                       │
│  ─────────────────────────────────────                                      │
│                                                                              │
│  {                                                                           │
│    "name": "alice.sovereign",                                               │
│    "identity": {                                                            │
│      "node_id": "0x7f3a8b2c...",                                           │
│      "public_key": "ed25519:Hx7Kj9..."                                     │
│    },                                                                        │
│    "endpoints": [                                                            │
│      { "host": "10.42.1.5", "port": 9333, "priority": 10 },                │
│      { "host": "10.42.2.7", "port": 9333, "priority": 20 }                 │
│    ],                                                                        │
│    "protocols": ["h3", "h2"],                                               │
│    "ttl": 300                                                                │
│  }                                                                           │
│                                                                              │
│  Step 4: NPU selects best endpoint based on current conditions              │
│  ───────────────────────────────────────────────────────────                │
│                                                                              │
│  Step 5: Connection established via QUIC                                    │
│  ─────────────────────────────────────                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Integration with NPU-Accelerated Control Plane

### 6.1 The Handoff

lib-dns and the NPU control plane have a clean interface:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         lib-dns ↔ NPU INTERFACE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  lib-dns PROVIDES:                      NPU CONSUMES:                       │
│  ─────────────────                      ─────────────                       │
│                                                                              │
│  • List of candidate endpoints          • Scores each endpoint              │
│  • Service metadata (ports, protocols)  • Considers current conditions      │
│  • Identity information                 • Applies ML model                  │
│  • TTL (cache validity)                 • Updates policy table              │
│                                                                              │
│  ┌─────────────────────┐               ┌─────────────────────┐             │
│  │                     │               │                     │             │
│  │   ZDNS Resolution   │──────────────▶│   NPU Inference    │             │
│  │                     │               │                     │             │
│  │   "alice.sovereign" │   Endpoints   │   Score & Rank     │             │
│  │        ↓            │   [A, B, C]   │        ↓           │             │
│  │   [A, B, C, ...]    │               │   Best: A          │             │
│  │                     │               │   Fallback: B      │             │
│  │                     │               │                     │             │
│  └─────────────────────┘               └──────────┬──────────┘             │
│                                                   │                         │
│                                                   │ Policy Update           │
│                                                   ▼                         │
│                                        ┌─────────────────────┐             │
│                                        │                     │             │
│                                        │   FastPath/PPE     │             │
│                                        │   Policy Table      │             │
│                                        │                     │             │
│                                        │   alice → A (pri)   │             │
│                                        │        → B (sec)    │             │
│                                        │                     │             │
│                                        └─────────────────────┘             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 NPU Decision Factors

The NPU considers factors that lib-dns cannot know:

| Factor | Source | Update Frequency |
|--------|--------|------------------|
| Endpoint latency | Active probing | Seconds |
| Packet loss rate | Data plane statistics | Seconds |
| Peer reputation | Historical behavior | Minutes |
| Congestion level | Traffic analysis | Seconds |
| Path hop count | Mesh routing table | Seconds |
| Connection age | Session tracking | Real-time |
| Predicted failure | ML model inference | Seconds |

### 6.3 LoRa Hint Distribution

NPU decisions can be distributed via LoRa to coordinate mesh:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LoRa HINT PROTOCOL                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Hint Message Format (fits in LoRa payload, ~20 bytes):                     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Type (1B) │ Node ID (4B) │ Score (1B) │ Hint Data (variable)       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Hint Types:                                                                 │
│  ───────────                                                                │
│                                                                              │
│  0x01  NODE_QUALITY     "Node X has quality score Y"                        │
│  0x02  AVOID_PATH       "Avoid path through node X"                         │
│  0x03  PREFER_PATH      "Prefer path through node X"                        │
│  0x04  NODE_DOWN        "Node X is unreachable"                             │
│  0x05  NODE_UP          "Node X is back online"                             │
│  0x06  CONGESTION       "Congestion on path X→Y"                            │
│  0x07  CHANNEL_HINT     "Use WiFi channel X for rendezvous"                 │
│  0x08  ZDNS_UPDATE      "Zone serial changed, refresh"                      │
│                                                                              │
│  Example Flow:                                                               │
│  ─────────────                                                              │
│                                                                              │
│  1. NPU on Node A detects: "Node B packet loss increasing (40%)"            │
│  2. NPU predicts: "Node B failure likely in ~30 seconds"                    │
│  3. NPU generates hint: { type: AVOID_PATH, node: B, score: 2 }             │
│  4. LoRa broadcasts hint (20 bytes, 2-15km range)                           │
│  5. Other nodes receive, update routing preferences                         │
│  6. When B actually fails, traffic already rerouted                         │
│                                                                              │
│  This is "self-healing" - network adapts before failures complete           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.4 ZDNS Cache Invalidation via LoRa

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ZDNS CACHE COORDINATION                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Scenario: Alice changes her mesh endpoint                                  │
│                                                                              │
│  1. Alice updates her ZDNS record on authoritative server                   │
│                                                                              │
│  2. Server increments zone serial: 2026011701 → 2026011702                  │
│                                                                              │
│  3. Server broadcasts via LoRa:                                             │
│     { type: ZDNS_UPDATE, zone: "sovereign", serial: 2026011702 }            │
│                                                                              │
│  4. Nodes compare serial to cached version                                  │
│                                                                              │
│  5. If stale, nodes can either:                                             │
│     a) Wait for TTL expiry (passive)                                        │
│     b) Query authoritative server via mesh (active)                         │
│     c) Request IXFR (incremental zone transfer) for efficiency              │
│                                                                              │
│  Benefits:                                                                   │
│  ─────────                                                                  │
│  • Sub-second notification of changes (LoRa latency)                        │
│  • Minimal bandwidth (serial number only, ~10 bytes)                        │
│  • Nodes decide when to refresh based on urgency                            │
│  • Works even when mesh is partitioned (LoRa has longer range)             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Offline-First Operation

### 7.1 Zone Distribution

lib-dns zones are distributed through the mesh without Internet:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZONE DISTRIBUTION                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DISTRIBUTION METHODS:                                                       │
│                                                                              │
│  1. MESH GOSSIP                                                             │
│     ─────────────                                                           │
│     • Zones replicated to multiple mesh nodes                               │
│     • Updates propagate via gossip protocol                                 │
│     • Eventually consistent (partition tolerant)                            │
│                                                                              │
│  2. ZONE TRANSFER (AXFR/IXFR)                                               │
│     ─────────────────────────                                               │
│     • Standard DNS zone transfer protocol                                   │
│     • AXFR: Full zone transfer                                              │
│     • IXFR: Incremental (differences only)                                  │
│     • TSIG-authenticated for security                                       │
│                                                                              │
│  3. DHT DISTRIBUTION                                                        │
│     ────────────────                                                        │
│     • Zone chunks stored in DHT                                             │
│     • Content-addressed (hash of zone data)                                 │
│     • Redundant across multiple DHT nodes                                   │
│                                                                              │
│  4. LOCAL ZONE FILES                                                        │
│     ─────────────────                                                       │
│     • Pre-loaded zone files on devices                                      │
│     • Updated via mesh sync when connected                                  │
│     • Work completely offline                                               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │                    ZONE STORAGE HIERARCHY                            │   │
│  │                                                                      │   │
│  │   ┌─────────────┐                                                   │   │
│  │   │   L1 Cache  │  Hot queries, TTL-based expiry                    │   │
│  │   │   (Memory)  │  Access: < 1ms                                    │   │
│  │   └──────┬──────┘                                                   │   │
│  │          │ miss                                                      │   │
│  │          ▼                                                           │   │
│  │   ┌─────────────┐                                                   │   │
│  │   │  L2 Cache   │  Recent zones, larger capacity                    │   │
│  │   │   (Disk)    │  Access: < 10ms                                   │   │
│  │   └──────┬──────┘                                                   │   │
│  │          │ miss                                                      │   │
│  │          ▼                                                           │   │
│  │   ┌─────────────┐                                                   │   │
│  │   │ Local Zones │  Pre-loaded authoritative zones                   │   │
│  │   │   (Disk)    │  Access: < 10ms                                   │   │
│  │   └──────┬──────┘                                                   │   │
│  │          │ miss                                                      │   │
│  │          ▼                                                           │   │
│  │   ┌─────────────┐                                                   │   │
│  │   │ Mesh Query  │  Query other mesh nodes                           │   │
│  │   │  (Network)  │  Access: 10-100ms                                 │   │
│  │   └──────┬──────┘                                                   │   │
│  │          │ miss                                                      │   │
│  │          ▼                                                           │   │
│  │   ┌─────────────┐                                                   │   │
│  │   │  DHT Query  │  Query distributed hash table                     │   │
│  │   │  (Network)  │  Access: 100-500ms                                │   │
│  │   └─────────────┘                                                   │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Partition Tolerance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PARTITION HANDLING                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SCENARIO: Mesh splits into two partitions                                  │
│                                                                              │
│  ┌─────────────────────┐         ┌─────────────────────┐                   │
│  │    Partition A      │         │    Partition B      │                   │
│  │                     │    X    │                     │                   │
│  │  [Node1] [Node2]    │◄───────►│  [Node3] [Node4]    │                   │
│  │  [Node5] [Node6]    │  Lost   │  [Node7] [Node8]    │                   │
│  │                     │         │                     │                   │
│  └─────────────────────┘         └─────────────────────┘                   │
│                                                                              │
│  BEHAVIOR:                                                                   │
│                                                                              │
│  1. Each partition continues operating independently                        │
│                                                                              │
│  2. ZDNS in Partition A:                                                    │
│     • Can resolve names for nodes in A (local zone data)                    │
│     • Can resolve names for nodes in B (cached data, may be stale)          │
│     • New registrations in A don't propagate to B                           │
│                                                                              │
│  3. ZDNS in Partition B:                                                    │
│     • Same behavior, symmetric                                              │
│                                                                              │
│  4. When partition heals:                                                   │
│     • Zone serial numbers compared                                          │
│     • Zones with newer serials propagate                                    │
│     • Conflicting records resolved by timestamp + owner signature           │
│     • Eventually consistent                                                  │
│                                                                              │
│  CONFLICT RESOLUTION:                                                        │
│                                                                              │
│  If alice.sovereign has different records in A and B:                       │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Rule 1: Most recent timestamp wins (if signed by same owner)      │    │
│  │  Rule 2: If different owners claim, verify ownership proof         │    │
│  │  Rule 3: If ownership unclear, both records kept until resolved    │    │
│  │  Rule 4: TTL determines how long stale data persists               │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 No Global Consistency Assumption

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONSISTENCY MODEL                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Traditional DNS: Assumes global consistency                                │
│  ────────────────────────────────────────                                   │
│  • Root servers are authoritative                                           │
│  • Hierarchy ensures single source of truth                                 │
│  • Requires Internet connectivity to roots                                  │
│                                                                              │
│  ZDNS: No global consistency assumption                                     │
│  ───────────────────────────────────────                                    │
│  • Multiple authoritative sources (mesh nodes hosting zone)                 │
│  • Cryptographic ownership (ZK proofs) determines truth                     │
│  • Eventual consistency via gossip                                          │
│  • Works in isolation                                                        │
│                                                                              │
│  IMPLICATIONS:                                                               │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  ✓ Names work offline                                              │    │
│  │  ✓ Partitions don't break naming                                   │    │
│  │  ✓ No dependency on root servers or registrars                     │    │
│  │  ✓ Censorship resistant (no single point of control)               │    │
│  │                                                                     │    │
│  │  ✗ May see stale data during partitions                            │    │
│  │  ✗ Name squatting requires social/economic resolution              │    │
│  │  ✗ No ICANN-style dispute resolution                               │    │
│  │                                                                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  OWNERSHIP PROOF (Solves squatting):                                        │
│                                                                              │
│  Every ZDNS record includes:                                                 │
│  • ownership_proof: ZK proof that owner controls private key                │
│  • pq_signature: Post-quantum signature of record data                      │
│  • dao_fee_proof: Proof of registration fee payment                         │
│                                                                              │
│  This means:                                                                 │
│  • Anyone can verify ownership without trusted third party                  │
│  • Conflicting claims resolved cryptographically                            │
│  • Economic cost (DAO fee) prevents spam registration                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Data Flow Examples

### 8.1 First Contact with New Peer

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLOW: FIRST CONTACT WITH alice.sovereign                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ACTORS:                                                                     │
│  • User Device (Phone connected to gateway)                                 │
│  • Gateway Node (Mesh participant)                                          │
│  • Alice's Node (Target)                                                    │
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │              │   │              │   │              │   │              │ │
│  │    Phone     │   │   Gateway    │   │  Mesh Node   │   │   Alice's    │ │
│  │   (Client)   │   │    Node      │   │    (NS)      │   │    Node      │ │
│  │              │   │              │   │              │   │              │ │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘ │
│         │                  │                  │                  │          │
│         │  1. ZDNS Query   │                  │                  │          │
│         │─────────────────▶│                  │                  │          │
│         │  alice.sovereign │                  │                  │          │
│         │  ANY             │                  │                  │          │
│         │                  │                  │                  │          │
│         │                  │  2. Cache Miss   │                  │          │
│         │                  │  Forward Query   │                  │          │
│         │                  │─────────────────▶│                  │          │
│         │                  │                  │                  │          │
│         │                  │  3. Zone Lookup  │                  │          │
│         │                  │◀─────────────────│                  │          │
│         │                  │  alice.sovereign │                  │          │
│         │                  │  A: 10.42.1.5    │                  │          │
│         │                  │  TXT: pubkey=... │                  │          │
│         │                  │  SRV: ...        │                  │          │
│         │                  │                  │                  │          │
│         │  4. Response     │                  │                  │          │
│         │◀─────────────────│                  │                  │          │
│         │  (Cached)        │                  │                  │          │
│         │                  │                  │                  │          │
│         │  5. NPU Scoring  │                  │                  │          │
│         │  (On Gateway)    │                  │                  │          │
│         │                  │────┐             │                  │          │
│         │                  │    │ Evaluate    │                  │          │
│         │                  │◀───┘ endpoints   │                  │          │
│         │                  │                  │                  │          │
│         │  6. Connect via QUIC               │                  │          │
│         │─────────────────────────────────────────────────────▶│          │
│         │  To: 10.42.1.5:9333                                  │          │
│         │  Identity verified via pubkey from ZDNS              │          │
│         │                  │                  │                  │          │
│         │  7. E2E Encrypted Session          │                  │          │
│         │◀────────────────────────────────────────────────────▶│          │
│         │                  │                  │                  │          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Failover During Partition

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLOW: FAILOVER DURING PARTITION                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INITIAL STATE:                                                              │
│  • Phone connected to alice.sovereign via primary endpoint (10.42.1.5)     │
│  • ZDNS returned 3 endpoints: [10.42.1.5, 10.42.2.7, 10.42.3.2]            │
│  • NPU ranked: primary=1.5, secondary=2.7, tertiary=3.2                    │
│                                                                              │
│  EVENT: Network partition isolates 10.42.1.5                                │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  T+0s: Connection to 10.42.1.5 starts failing                       │    │
│  │        NPU detects: packet loss 50%, latency spike                  │    │
│  │                                                                     │    │
│  │  T+2s: NPU predicts: "Node likely unreachable"                      │    │
│  │        NPU updates policy: demote 10.42.1.5, promote 10.42.2.7     │    │
│  │        LoRa broadcasts: { AVOID_PATH, node=10.42.1.5, score=1 }    │    │
│  │                                                                     │    │
│  │  T+3s: New connection attempt to alice.sovereign                    │    │
│  │        Policy table says: use 10.42.2.7                             │    │
│  │        QUIC connection to backup succeeds                           │    │
│  │                                                                     │    │
│  │  T+5s: Other mesh nodes receive LoRa hint                           │    │
│  │        Update their routing preferences                             │    │
│  │                                                                     │    │
│  │  T+30s: Partition heals, 10.42.1.5 reachable again                 │    │
│  │         NPU detects: connectivity restored                          │    │
│  │         NPU evaluates: 10.42.1.5 has better latency                │    │
│  │         NPU updates policy: 10.42.1.5 primary again                │    │
│  │         LoRa broadcasts: { NODE_UP, node=10.42.1.5, score=9 }      │    │
│  │                                                                     │    │
│  │  T+31s: New connections use 10.42.1.5 again                        │    │
│  │         Existing connections on 10.42.2.7 continue (no disruption) │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  KEY POINTS:                                                                 │
│  • ZDNS provided multiple endpoints upfront                                 │
│  • NPU made real-time failover decision                                     │
│  • LoRa coordinated mesh-wide awareness                                     │
│  • No re-resolution needed (cached endpoints still valid)                   │
│  • Failover happened in ~3 seconds                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Offline Resolution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLOW: COMPLETELY OFFLINE RESOLUTION                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SCENARIO: Isolated mesh network, no Internet, no external connectivity     │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │                    ISOLATED MESH NETWORK                            │    │
│  │                                                                     │    │
│  │   ┌─────────┐     ┌─────────┐     ┌─────────┐                     │    │
│  │   │ Node A  │◄───►│ Node B  │◄───►│ Node C  │                     │    │
│  │   │ (NS)    │     │         │     │ (Phone  │                     │    │
│  │   │         │     │         │     │  Client)│                     │    │
│  │   │ Zone:   │     │ Cache:  │     │ Query:  │                     │    │
│  │   │sovereign│     │ alice   │     │ alice.  │                     │    │
│  │   └─────────┘     └─────────┘     └─────────┘                     │    │
│  │        │               │               │                           │    │
│  │        │               │               │                           │    │
│  │    NO INTERNET CONNECTION                                          │    │
│  │                                                                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  RESOLUTION FLOW:                                                            │
│                                                                              │
│  1. Phone queries local gateway (Node C/B) for alice.sovereign              │
│                                                                              │
│  2. Gateway checks L1 cache → Miss                                          │
│                                                                              │
│  3. Gateway checks L2 cache → Hit! (cached from earlier)                    │
│     Returns: alice.sovereign A 10.42.1.5 (TTL: 250s remaining)             │
│     Resolution complete.                                                     │
│                                                                              │
│  OR if cache miss:                                                           │
│                                                                              │
│  3. Gateway checks local zone files → Miss (not authoritative)              │
│                                                                              │
│  4. Gateway queries mesh for sovereign. NS                                  │
│     → Node A responds (it hosts the zone)                                   │
│                                                                              │
│  5. Gateway queries Node A for alice.sovereign                              │
│     → Node A responds from local zone file                                  │
│                                                                              │
│  6. Gateway caches result, returns to phone                                 │
│                                                                              │
│  RESULT: Full resolution without any Internet connectivity                  │
│                                                                              │
│  REQUIREMENTS:                                                               │
│  • At least one node in mesh hosts the zone                                 │
│  • Zone data pre-distributed via mesh sync                                  │
│  • lib-dns supports standard zone file format                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Implementation Roadmap

### 9.1 Current State Summary

| Component | Status | Blocking Issues |
|-----------|--------|-----------------|
| DNS wire format | Complete | None |
| Basic RR types (A, AAAA, CNAME, etc.) | Complete | None |
| Zone file parsing | Complete | None |
| DNSSEC RR types | Partial | Wire format incomplete |
| TSIG | Partial | `from_wire_len()` incomplete |
| Journal | Stubbed | `open()` not implemented |
| Test coverage | Minimal | Most tests commented out |
| Error handling | Poor | 134 `unwrap()` calls |

### 9.2 Priority 0: Critical Path (Blocks Deployment)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         P0: DEPLOYMENT BLOCKERS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. TSIG from_wire_len() Completion                                         │
│     File: lib-dns/src/messages/tsig.rs:129                                  │
│     Impact: Cannot verify signed zone transfers                             │
│     Effort: Low (code is 90% done, needs return statement)                  │
│                                                                              │
│  2. Error Handling in message.rs                                            │
│     File: lib-dns/src/messages/message.rs                                   │
│     Impact: Production panics on malformed input                            │
│     Effort: Medium (37 unwrap() calls to convert)                           │
│                                                                              │
│  3. NSEC/NSEC3 Wire Format                                                  │
│     Files: nsec_rr_data.rs, nsec3_rr_data.rs                               │
│     Impact: Cannot process DNSSEC authenticated denial                      │
│     Effort: Medium (from_bytes works, wire format similar)                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 Priority 1: Core Functionality

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         P1: CORE FUNCTIONALITY                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  4. DS Wire Format                                                          │
│     File: lib-dns/src/rr_data/ds_rr_data.rs                                │
│     Impact: DNSSEC delegation chain verification                            │
│                                                                              │
│  5. SSHFP Wire Format                                                       │
│     File: lib-dns/src/rr_data/sshfp_rr_data.rs                             │
│     Impact: SSH key verification via DNS                                    │
│                                                                              │
│  6. Journal System                                                          │
│     File: lib-dns/src/journal/journal.rs                                   │
│     Impact: Incremental zone transfer (IXFR)                                │
│     Dependency: Add indexmap to Cargo.toml                                  │
│                                                                              │
│  7. Remaining Error Handling                                                │
│     Files: 36 other files with unwrap()                                    │
│     Impact: Production stability                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.4 Priority 2: Enhanced Features

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         P2: ENHANCED FEATURES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  8. CAA Record Type (New)                                                   │
│     Impact: Certificate authority authorization                             │
│     Effort: Medium (create new file, wire into factories)                   │
│                                                                              │
│  9. SPF Wiring                                                              │
│     Impact: Sender policy framework support                                 │
│     Effort: Low (struct exists, just needs factory wiring)                  │
│                                                                              │
│  10. Zone Writer                                                            │
│      Impact: Generate zone files (not just read)                            │
│      Effort: Medium                                                          │
│                                                                              │
│  11. TCP Framing                                                            │
│      Impact: Large responses, zone transfers                                │
│      Effort: Low-Medium                                                      │
│                                                                              │
│  12. Test Coverage                                                          │
│      Impact: Confidence in correctness                                      │
│      Effort: High (but can be incremental)                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.5 Integration Tasks

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         INTEGRATION TASKS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  A. lib-dns ↔ lib-protocols (ZDNS)                                         │
│     ──────────────────────────────                                          │
│     • ZDNS uses lib-dns wire format                                         │
│     • Add custom record type serialization                                  │
│     • ZK proof embedding in TXT or custom records                           │
│                                                                              │
│  B. lib-dns ↔ lib-network (Peer Registry)                                  │
│     ────────────────────────────────────                                    │
│     • DNS-based peer discovery                                              │
│     • SRV records for service endpoints                                     │
│     • Mesh endpoint resolution                                              │
│                                                                              │
│  C. lib-dns ↔ NPU Control Plane                                            │
│     ───────────────────────────────                                         │
│     • Multi-endpoint response format                                        │
│     • Endpoint metadata for scoring                                         │
│     • Cache invalidation hints                                              │
│                                                                              │
│  D. lib-dns ↔ LoRa Control Plane                                           │
│     ───────────────────────────────                                         │
│     • Zone serial notification format                                       │
│     • Compact hint encoding                                                 │
│     • Cache coordination protocol                                           │
│                                                                              │
│  E. lib-dns ↔ Blockchain (Async)                                           │
│     ────────────────────────────                                            │
│     • Identity anchor verification                                          │
│     • Capability checking                                                   │
│     • Economic state for registration                                       │
│     • All queries via local cache (never sync)                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. API Surface

### 10.1 Core lib-dns API

```rust
// Message parsing and serialization
pub mod messages {
    pub struct Message { ... }
    impl Message {
        pub fn from_bytes(buf: &[u8]) -> Result<Self, WireError>;
        pub fn to_bytes(&self, max_size: usize) -> Vec<u8>;
    }

    pub struct Record { ... }
    pub struct RRQuery { ... }
}

// Resource record data types
pub mod rr_data {
    pub trait RRData {
        fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError>;
        fn to_bytes(&self) -> Result<Vec<u8>, RRDataError>;
    }

    pub struct InARRData { ... }      // A record (IPv4)
    pub struct AaaaRRData { ... }     // AAAA record (IPv6)
    pub struct SrvRRData { ... }      // SRV record (service)
    pub struct TxtRRData { ... }      // TXT record (text)
    pub struct HttpsRRData { ... }    // HTTPS record (service binding)
    // ... 20+ record types
}

// Zone management
pub mod zone {
    pub struct Zone { ... }
    pub struct ZoneStore { ... }
    impl ZoneStore {
        pub fn open(path: &str, origin: &str, class: RRClasses) -> Result<()>;
        pub fn get_zone_exact(&self, name: &str) -> Option<&Zone>;
        pub fn get_deepest_zone(&self, name: &str) -> Option<&Zone>;
    }
}

// DNSSEC key management
pub mod keyring {
    pub struct Keyring { ... }
    pub struct Key { ... }
}

// Zone transfer journaling
pub mod journal {
    pub struct Journal { ... }
    pub struct JournalReader { ... }
}
```

### 10.2 ZDNS Extended API (lib-protocols)

```rust
// ZDNS server and records
pub struct ZdnsServer { ... }
impl ZdnsServer {
    pub async fn process_query(&self, query: ZdnsQuery) -> Result<ZdnsResponse>;
    pub async fn register_record(&self, record: ZdnsRecord) -> Result<()>;
}

pub struct ZdnsRecord {
    pub name: String,
    pub record_type: ZdnsRecordType,
    pub value: String,
    pub ttl: u32,
    pub ownership_proof: String,    // ZK proof
    pub pq_signature: String,       // Post-quantum signature
    pub dao_fee_proof: String,      // Economic proof
    // ...
}

pub enum ZdnsRecordType {
    A, AAAA, CNAME, MX, TXT, SRV,   // Standard DNS
    MESH,                            // Mesh node endpoint
    ZK,                              // Zero-knowledge proof
    ID,                              // Identity binding
    DAO, ECON,                       // Governance/economics
    WEB4, WEB4CONTENT, WEB4DHT,     // Web4 extensions
    // ...
}
```

### 10.3 NPU Integration Interface

```rust
// Interface between ZDNS and NPU control plane
pub struct EndpointCandidate {
    pub address: SocketAddr,
    pub priority: u16,
    pub weight: u16,
    pub metadata: EndpointMetadata,
}

pub struct EndpointMetadata {
    pub node_id: Option<String>,
    pub public_key: Option<String>,
    pub protocols: Vec<String>,
    pub ttl: u32,
}

// ZDNS returns multiple candidates
pub struct ZdnsResolution {
    pub name: String,
    pub identity: Option<IdentityInfo>,
    pub endpoints: Vec<EndpointCandidate>,  // NPU chooses from these
    pub ttl: u32,
}

// NPU adds scoring
pub struct ScoredEndpoint {
    pub candidate: EndpointCandidate,
    pub latency_ms: f32,
    pub packet_loss: f32,
    pub reputation: f32,
    pub overall_score: f32,
}
```

---

## Appendix: Quick Reference

### A. What lib-dns Handles

| Query | lib-dns Response | Cache |
|-------|------------------|-------|
| "What is alice.sovereign?" | IP addresses, identity info | Yes, TTL-based |
| "What services does alice offer?" | SRV/HTTPS records | Yes |
| "Who hosts sovereign. zone?" | NS records | Yes |
| "What's alice's public key?" | TXT record with key | Yes |

### B. What lib-dns Does NOT Handle

| Query | Handled By |
|-------|------------|
| "Which endpoint is fastest?" | NPU control plane |
| "Is this node authorized?" | Blockchain cache |
| "Forward this packet" | Data plane (FastPath) |
| "Who is nearby?" | LoRa + Peer discovery |

### C. Latency Expectations

| Operation | Expected Latency |
|-----------|------------------|
| L1 cache hit | < 100μs |
| L2 cache hit | < 1ms |
| Local zone lookup | < 5ms |
| Mesh query (1 hop) | 10-50ms |
| Mesh query (5 hops) | 50-200ms |
| DHT query | 100-500ms |

### D. File Quick Reference

| Purpose | File |
|---------|------|
| Wire format | `lib-dns/src/messages/wire.rs` |
| Message parsing | `lib-dns/src/messages/message.rs` |
| Record types | `lib-dns/src/rr_data/*.rs` |
| Zone storage | `lib-dns/src/zone/zone_store.rs` |
| Zone parsing | `lib-dns/src/zone/zone_reader.rs` |
| TSIG signing | `lib-dns/src/messages/tsig.rs` |
| ZDNS server | `lib-protocols/src/zdns.rs` |

---

# CRITICAL CONSTRAINTS & INVARIANTS

> **These sections define hard rules that prevent future coupling and ensure correct behavior under partitions. Violations of these constraints are bugs, not design choices.**

---

## 11. Resolver Invariants & Constraints

### 11.1 Authoritative Ambiguity Resolution

When multiple authoritative sources exist (which is the norm in a mesh), the resolver **MUST** follow these deterministic rules:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AUTHORITATIVE CONFLICT RESOLUTION                         │
│                         (Deterministic, Ordered)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SCENARIO: Two authoritative nodes respond with different data              │
│                                                                              │
│  RULE 1: SERIAL NUMBER COMPARISON (Primary)                                 │
│  ─────────────────────────────────────────────                              │
│  • Higher SOA serial wins                                                   │
│  • If serials equal, proceed to Rule 2                                      │
│  • Serial wrap-around: use RFC 1982 serial arithmetic                       │
│                                                                              │
│  RULE 2: SIGNATURE TIMESTAMP (Secondary)                                    │
│  ────────────────────────────────────────                                   │
│  • If same serial, more recent pq_signature timestamp wins                  │
│  • Timestamp must be within signature validity window                       │
│  • Clock skew tolerance: 60 seconds                                         │
│                                                                              │
│  RULE 3: LATENCY TIE-BREAKER (Tertiary)                                    │
│  ──────────────────────────────────────                                     │
│  • If serial and timestamp equal, prefer lower-latency source               │
│  • Latency measured at query time                                           │
│                                                                              │
│  RULE 4: NODE REPUTATION (Quaternary)                                       │
│  ─────────────────────────────────────                                      │
│  • If still tied, prefer higher reputation node                             │
│  • Reputation from NPU control plane                                        │
│                                                                              │
│  RULE 5: DETERMINISTIC FALLBACK                                             │
│  ──────────────────────────────                                             │
│  • If all else equal, prefer lexicographically lower node_id                │
│  • This ensures all resolvers converge to same answer                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 Dual-Valid Answer Handling

When two responses are **both cryptographically valid** but different:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DUAL-VALID HANDLING                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CASE A: Same owner, different data (legitimate update race)                │
│  ─────────────────────────────────────────────────────────                  │
│  • Apply Rule 1-5 above                                                     │
│  • Winner served to clients                                                 │
│  • Loser discarded (will be overwritten on next sync)                       │
│                                                                              │
│  CASE B: Different owners claim same name (ownership dispute)               │
│  ───────────────────────────────────────────────────────────                │
│  • BOTH records MUST be kept in cache                                       │
│  • Response marked with flag: "disputed" or "degraded"                      │
│  • Client receives BOTH answers with dispute flag                           │
│  • Resolution deferred to economic/governance layer                         │
│  • Cache TTL reduced to min(original_ttl, 60 seconds)                       │
│                                                                              │
│  CASE C: One valid signature, one invalid                                   │
│  ─────────────────────────────────────────                                  │
│  • Valid signature wins unconditionally                                     │
│  • Invalid response discarded and logged                                    │
│  • Source node reputation reduced                                           │
│                                                                              │
│  INVARIANT: Resolver NEVER silently drops valid-but-conflicting data       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.3 Soft Failure vs Hard Failure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FAILURE MODE CLASSIFICATION                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SOFT FAILURE (Degraded but usable)                                         │
│  ──────────────────────────────────                                         │
│  • Stale data (TTL expired) with valid signature → SERVE with "stale" flag │
│  • Single authoritative node unreachable → SERVE from others               │
│  • Signature algorithm deprecated → SERVE with "weak-crypto" flag          │
│  • Clock skew detected → SERVE with "time-uncertain" flag                  │
│                                                                              │
│  Action: Return data with degradation flags. Let client decide.             │
│                                                                              │
│  HARD FAILURE (Must not serve)                                              │
│  ─────────────────────────────                                              │
│  • Signature verification failed → SERVFAIL                                 │
│  • All authoritative nodes unreachable AND no cache → SERVFAIL             │
│  • Ownership proof invalid → SERVFAIL                                       │
│  • Zone explicitly revoked → NXDOMAIN                                       │
│                                                                              │
│  Action: Return error. Do not guess or fabricate data.                      │
│                                                                              │
│  CRITICAL RULE:                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Stale data with valid signature is ALWAYS preferable to           │    │
│  │  returning SERVFAIL. The signature proves past correctness.        │    │
│  │                                                                     │    │
│  │  max_stale_serve_time = 7 days (configurable)                      │    │
│  │  After this, transition to SERVFAIL                                │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Negative Answers & Partitions

### 12.1 NXDOMAIN Semantics in Mesh

**Critical Rule: NXDOMAIN is NEVER globally authoritative in a partitioned mesh.**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NEGATIVE ANSWER POLICY                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TRADITIONAL DNS:                                                            │
│  • NXDOMAIN means "name does not exist in the global namespace"             │
│  • Cacheable with normal TTL                                                │
│  • Authoritative from root chain                                            │
│                                                                              │
│  ZDNS IN MESH:                                                               │
│  • NXDOMAIN means "name not found in MY current view"                       │
│  • May exist in another partition                                           │
│  • May have been registered while I was disconnected                        │
│  • MUST be treated as soft, temporary, local opinion                        │
│                                                                              │
│  INVARIANT:                                                                  │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Negative cache TTL MUST be strictly less than positive cache TTL  │    │
│  │                                                                     │    │
│  │  negative_ttl = min(soa_minimum, 60 seconds, positive_ttl / 10)   │    │
│  │                                                                     │    │
│  │  Rationale: A name appearing is more important than confirming     │    │
│  │  continued absence. Asymmetric TTLs ensure quick discovery.        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 Negative Caching Rules

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NEGATIVE CACHING CONSTRAINTS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RULE 1: MAXIMUM NEGATIVE TTL                                               │
│  ────────────────────────────                                               │
│  • negative_ttl_max = 60 seconds (HARD LIMIT)                              │
│  • Even if SOA specifies longer, cap at 60s                                │
│  • Reason: Partition heals should propagate within 1 minute                │
│                                                                              │
│  RULE 2: NEGATIVE CACHE SIZE LIMIT                                          │
│  ─────────────────────────────────                                          │
│  • negative_cache_max_entries = 1000 (per resolver)                        │
│  • LRU eviction when full                                                  │
│  • Reason: Prevent negative cache from consuming all memory                │
│                                                                              │
│  RULE 3: PARTITION-AWARE INVALIDATION                                       │
│  ────────────────────────────────────                                       │
│  • On mesh topology change: flush ALL negative cache                       │
│  • On LoRa ZDNS_UPDATE hint: flush negative cache for that zone            │
│  • On new peer discovery: flush negative cache                             │
│  • Reason: New connectivity may reveal previously unknown names            │
│                                                                              │
│  RULE 4: NXDOMAIN RESPONSE METADATA                                         │
│  ───────────────────────────────────                                        │
│  • Every NXDOMAIN MUST include:                                            │
│    - responding_node_id: which node said "not found"                       │
│    - partition_id: current mesh partition identifier (if known)            │
│    - authority_coverage: % of known zone holders queried                   │
│  • Client can use this to decide whether to retry                          │
│                                                                              │
│  RULE 5: ABSENCE NEVER OVERWRITES PRESENCE                                  │
│  ──────────────────────────────────────────                                 │
│  • If cache has positive record for name                                   │
│  • AND new query returns NXDOMAIN                                          │
│  • DO NOT replace positive with negative                                   │
│  • Instead: mark positive as "contested", reduce TTL, re-query later       │
│  • Reason: Presence is evidence, absence is opinion                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.3 Partition Recovery

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PARTITION RECOVERY PROTOCOL                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  When partition heals (new mesh peers discovered):                          │
│                                                                              │
│  STEP 1: IMMEDIATE (within 1 second)                                        │
│  ─────────────────────────────────────                                      │
│  • Flush entire negative cache                                              │
│  • Log event: "partition_recovery, new_peers=[...]"                        │
│                                                                              │
│  STEP 2: ZONE SERIAL EXCHANGE (within 10 seconds)                           │
│  ────────────────────────────────────────────────                           │
│  • Query new peers for SOA of all locally-cached zones                     │
│  • Compare serials                                                          │
│  • Queue IXFR for zones where remote serial > local serial                 │
│                                                                              │
│  STEP 3: CONFLICT DETECTION (within 30 seconds)                             │
│  ──────────────────────────────────────────────                             │
│  • For each zone with serial conflict, apply Rule 1-5 from 11.1            │
│  • For ownership disputes, mark records as "contested"                     │
│  • Broadcast via LoRa: "partition_merged, zones_updated=[...]"             │
│                                                                              │
│  STEP 4: STEADY STATE (after 30 seconds)                                    │
│  ───────────────────────────────────────                                    │
│  • Resume normal resolution                                                 │
│  • Contested records remain flagged until governance resolves              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 13. Bootstrap Trust Model

### 13.1 First Node Trust Anchor

A mesh must have exactly ONE of these bootstrap mechanisms. Without it, the first node is underspecified and vulnerable.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BOOTSTRAP TRUST OPTIONS                                   │
│                    (Exactly one required per deployment)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  OPTION A: PRELOADED ROOT ZONE HASH                                         │
│  ──────────────────────────────────                                         │
│  • Device ships with: root_zone_hash = SHA256(zone_file)                   │
│  • First zone transfer verified against this hash                          │
│  • Subsequent updates verified via DNSSEC chain                            │
│  • Update mechanism: firmware update or signed manifest                     │
│                                                                              │
│  Use when: Closed deployments, enterprise, single-operator mesh            │
│                                                                              │
│  OPTION B: PRELOADED ZONE AUTHORITY PUBLIC KEY                              │
│  ─────────────────────────────────────────────                              │
│  • Device ships with: zone_authority_pubkey = ed25519:Hx7...               │
│  • Any zone signed by this key is trusted                                  │
│  • Enables zone content updates without firmware change                    │
│  • Key rotation requires firmware update or key-rollover protocol          │
│                                                                              │
│  Use when: Need zone flexibility with trusted operator                      │
│                                                                              │
│  OPTION C: QR/PHYSICAL BOOTSTRAP                                            │
│  ───────────────────────────────                                            │
│  • First node displays QR code containing:                                  │
│    - node_id                                                                │
│    - zone_authority_pubkey                                                  │
│    - bootstrap_token (one-time)                                            │
│  • New node scans QR to establish trust                                    │
│  • Token invalidated after use                                              │
│  • Requires physical presence (security feature)                           │
│                                                                              │
│  Use when: Open deployments, community mesh, high security                  │
│                                                                              │
│  OPTION D: TOFU (Trust On First Use)                                        │
│  ────────────────────────────────────                                       │
│  • First zone encountered is trusted                                        │
│  • Subsequent changes require signature from original key                  │
│  • WARNING: Vulnerable to first-contact attacks                            │
│  • WARNING: Partition during bootstrap can fork trust                       │
│                                                                              │
│  Use when: Low-security, experimental, or when A/B/C impossible            │
│  MUST be accompanied by: "tofu_mode=true" flag visible to users            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 13.2 Trust Chain Verification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TRUST CHAIN REQUIREMENTS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  For any record to be accepted as authoritative:                            │
│                                                                              │
│  1. Zone must chain to bootstrap trust anchor                              │
│     • root.sovereign → *.sovereign (via DS/DNSKEY)                         │
│     • OR zone_authority_pubkey signed the zone                             │
│                                                                              │
│  2. Record must have valid ownership_proof                                  │
│     • ZK proof verifiable without revealing private key                    │
│     • Proof format defined in lib-proofs                                   │
│                                                                              │
│  3. Record must have valid pq_signature                                     │
│     • Dilithium or approved PQ algorithm                                   │
│     • Signature covers: name + type + value + ttl + timestamp              │
│                                                                              │
│  4. Optional: dao_fee_proof for economic validation                        │
│     • Proof that registration fee was paid                                  │
│     • Can be skipped in "free" deployment modes                            │
│                                                                              │
│  FAILURE MODE:                                                               │
│  • Missing trust anchor → SERVFAIL with "no_trust_anchor"                  │
│  • Broken chain → SERVFAIL with "trust_chain_broken"                       │
│  • Invalid proof → SERVFAIL with "proof_invalid"                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Client Resolution Contract

### 14.1 Application Behavior Requirements

Applications using ZDNS **MUST** follow these rules:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CLIENT RESOLUTION CONTRACT                                │
│                    (Binding for all applications)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RULE 1: RESOLUTION FREQUENCY                                               │
│  ────────────────────────────                                               │
│  • Resolve name ONCE per session, not per connection                       │
│  • Session = application lifetime or explicit re-auth                      │
│  • Re-resolve ONLY when:                                                   │
│    - TTL expires                                                           │
│    - All cached endpoints unreachable                                      │
│    - User explicitly requests refresh                                      │
│    - Identity verification fails (key mismatch)                            │
│                                                                              │
│  RULE 2: IDENTITY BINDING PERSISTENCE                                       │
│  ────────────────────────────────────                                       │
│  • Identity (public key) binding survives endpoint changes                 │
│  • If alice.sovereign resolves to new IP but same pubkey → trust continues│
│  • Endpoint mobility is expected; identity mobility is suspicious          │
│                                                                              │
│  RULE 3: TRUST INVALIDATION CONDITIONS                                      │
│  ─────────────────────────────────────                                      │
│  • Re-verify identity ONLY when:                                           │
│    - Public key in resolution differs from cached key                      │
│    - Ownership proof changes                                               │
│    - QUIC handshake fails cryptographic verification                       │
│  • Endpoint change alone does NOT invalidate trust                         │
│                                                                              │
│  RULE 4: GRACEFUL DEGRADATION                                               │
│  ────────────────────────────                                               │
│  • If resolution returns "stale" flag → proceed, warn user                 │
│  • If resolution returns "contested" flag → proceed, require confirmation  │
│  • If resolution returns SERVFAIL → fail open or closed based on app type │
│    - Payments: fail closed (refuse to connect)                             │
│    - Messaging: fail open (try last-known endpoint)                        │
│                                                                              │
│  RULE 5: NO HOT-PATH RESOLUTION                                             │
│  ──────────────────────────────                                             │
│  • NEVER resolve during:                                                   │
│    - Active data transfer                                                  │
│    - Real-time communication (voice/video)                                 │
│    - Time-critical operations                                              │
│  • Pre-resolve or use cached data for these scenarios                      │
│                                                                              │
│  RULE 6: ENDPOINT PREFERENCE DEFERENCE                                      │
│  ─────────────────────────────────────                                      │
│  • Client receives multiple endpoints from ZDNS                            │
│  • Client SHOULD defer to NPU/system preference                            │
│  • Client MAY override only if system preference fails                     │
│  • Client MUST NOT implement own "smart" endpoint selection                │
│    (this creates inconsistent behavior across mesh)                        │
│                                                                              │
│  RULE 7: CACHE RESPECT                                                      │
│  ────────────────────                                                       │
│  • Honor TTL from resolver                                                 │
│  • Do not implement application-level DNS cache                            │
│  • Use system resolver cache (avoids duplication, ensures consistency)     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 14.2 Resolution API Contract

```rust
/// Client-facing resolution API contract
pub trait ZdnsClient {
    /// Resolve a name. Call ONCE per session.
    /// Returns multiple endpoints; let system choose.
    async fn resolve(&self, name: &str) -> Result<Resolution, ResolveError>;

    /// Check if cached resolution is still valid.
    /// Returns true if TTL not expired AND identity unchanged.
    fn is_cached_valid(&self, name: &str) -> bool;

    /// Force re-resolution. Use sparingly.
    /// Only when: all endpoints failed, or identity mismatch.
    async fn force_refresh(&self, name: &str) -> Result<Resolution, ResolveError>;
}

pub struct Resolution {
    pub name: String,
    pub identity: Identity,              // Stable across endpoint changes
    pub endpoints: Vec<Endpoint>,        // May change frequently
    pub ttl: Duration,
    pub flags: ResolutionFlags,          // stale, contested, etc.
}

pub struct ResolutionFlags {
    pub stale: bool,                     // TTL expired but signature valid
    pub contested: bool,                 // Ownership dispute detected
    pub degraded: bool,                  // Some validation skipped
    pub tofu: bool,                      // Trust-on-first-use mode
}
```

---

## 15. Forbidden Behaviors

### 15.1 lib-dns Invariants (MUST NEVER)

These are hard invariants. Violation is a bug requiring immediate fix.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FORBIDDEN BEHAVIORS                                       │
│                    (Invariants - violations are bugs)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INVARIANT 1: NO BLOCKING CONNECTION ESTABLISHMENT                          │
│  ─────────────────────────────────────────────────                          │
│  lib-dns MUST NEVER block or delay connection establishment.                │
│                                                                              │
│  • Resolution happens BEFORE connection attempt                             │
│  • Connection uses pre-resolved, cached data                                │
│  • If cache miss at connection time → use fallback, resolve async          │
│  • NEVER: resolve() called in connect() hot path                           │
│                                                                              │
│  INVARIANT 2: NO PACKET FORWARDING DEPENDENCY                               │
│  ────────────────────────────────────────────                               │
│  lib-dns MUST NEVER be required for packet forwarding.                      │
│                                                                              │
│  • Data plane operates on IP addresses, not names                          │
│  • Once connection established, DNS not consulted                          │
│  • Packet forward path: NIC → Policy Table → NIC (no DNS)                  │
│  • NEVER: DNS lookup in forwarding loop                                    │
│                                                                              │
│  INVARIANT 3: NO PER-PACKET QUERIES                                         │
│  ──────────────────────────────────                                         │
│  lib-dns MUST NEVER be queried per packet.                                  │
│                                                                              │
│  • Query count should be O(sessions), not O(packets)                       │
│  • One resolution serves entire session (minutes to hours)                 │
│  • If query rate > 10/second for same name → bug or attack                 │
│  • NEVER: resolve() in packet receive/send handler                         │
│                                                                              │
│  INVARIANT 4: NO SYNCHRONOUS BLOCKCHAIN                                     │
│  ───────────────────────────────────                                        │
│  lib-dns MUST NEVER synchronously query blockchain.                         │
│                                                                              │
│  • Blockchain state accessed via local cache only                          │
│  • Cache populated by background sync process                              │
│  • Cache miss → use stale or fail, NEVER block for sync                   │
│  • NEVER: await blockchain.query() in resolution path                      │
│                                                                              │
│  INVARIANT 5: NO AI/ML IN RESOLUTION                                        │
│  ───────────────────────────────────                                        │
│  lib-dns MUST NEVER perform AI/ML inference.                                │
│                                                                              │
│  • Returns raw endpoints; NPU layer does scoring                           │
│  • No "smart" endpoint selection in DNS                                    │
│  • No prediction or learning in resolution path                            │
│  • NEVER: model.infer() in resolution path                                 │
│                                                                              │
│  INVARIANT 6: NO NETWORK I/O IN CACHE HIT                                   │
│  ────────────────────────────────────────                                   │
│  lib-dns cache hit MUST NOT perform any network I/O.                        │
│                                                                              │
│  • Cache hit returns immediately from memory                               │
│  • No "refresh while serving" on cache hit                                 │
│  • Background refresh is separate, async process                           │
│  • NEVER: network call when cache.get() returns Some                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 15.2 Enforcement Mechanisms

```rust
/// Runtime checks for invariant enforcement
/// These should be compiled in for debug builds

#[cfg(debug_assertions)]
mod invariant_checks {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static QUERIES_THIS_SECOND: AtomicU64 = AtomicU64::new(0);
    static LAST_RESET: AtomicU64 = AtomicU64::new(0);

    /// Call on every resolution. Panics if rate too high.
    pub fn check_query_rate(name: &str) {
        let now = Instant::now().elapsed().as_secs();
        let last = LAST_RESET.load(Ordering::Relaxed);

        if now > last {
            LAST_RESET.store(now, Ordering::Relaxed);
            QUERIES_THIS_SECOND.store(0, Ordering::Relaxed);
        }

        let count = QUERIES_THIS_SECOND.fetch_add(1, Ordering::Relaxed);

        if count > 10 {
            panic!(
                "INVARIANT VIOLATION: Query rate > 10/sec for '{}'. \
                 This indicates per-packet or hot-path resolution.",
                name
            );
        }
    }

    /// Call at start of resolution. Panics if in packet handler.
    pub fn check_not_in_packet_handler() {
        if is_packet_handler_context() {
            panic!(
                "INVARIANT VIOLATION: DNS resolution called from packet handler. \
                 Resolution must happen before connection, not during data transfer."
            );
        }
    }

    /// Call before any cache access. Panics if blocking I/O detected.
    pub fn check_no_blocking_io() {
        if is_in_async_block() && would_block() {
            panic!(
                "INVARIANT VIOLATION: Blocking I/O in resolution path. \
                 Use async I/O or cache-only access."
            );
        }
    }
}
```

---

## 16. Zone Scoping & Federation

### 16.1 Zone Classification

Not all zones are equal. Resolution policy depends on zone classification.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ZONE SCOPING                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CLASS A: LOCAL-ONLY ZONES                                                  │
│  ─────────────────────────                                                  │
│  Pattern: *.local.sovereign, *.venue.sovereign                              │
│                                                                              │
│  Policy:                                                                     │
│  • Resolution MUST NOT leave local mesh partition                           │
│  • MUST NOT federate with other meshes                                      │
│  • MUST NOT query external DNS                                              │
│  • Negative answers authoritative within partition                          │
│                                                                              │
│  Use case: Venue-specific services, local infrastructure                    │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  CLASS B: FEDERATED ZONES                                                   │
│  ────────────────────────                                                   │
│  Pattern: *.sovereign (default), *.fed.sovereign                            │
│                                                                              │
│  Policy:                                                                     │
│  • Resolution MAY query federated mesh peers                               │
│  • Federation requires mutual trust establishment                           │
│  • Cross-mesh queries MUST be signed                                        │
│  • Results MUST be re-verified locally                                      │
│                                                                              │
│  Use case: Inter-mesh communication, roaming users                          │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  CLASS C: EXTERNAL-BRIDGE ZONES                                             │
│  ──────────────────────────────                                             │
│  Pattern: *.bridge.sovereign, *.clearnet.sovereign                          │
│                                                                              │
│  Policy:                                                                     │
│  • Resolution MAY use Internet DNS (when available)                         │
│  • Results MUST be marked as "external"                                    │
│  • MUST fail gracefully when Internet unavailable                          │
│  • MUST NOT be cached as authoritative for mesh                            │
│                                                                              │
│  Use case: Accessing Internet services via mesh gateway                     │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  ZONE CLASSIFICATION RECORD                                                  │
│  ──────────────────────────                                                 │
│  Each zone MUST have a _scope TXT record:                                   │
│                                                                              │
│  _scope.venue.sovereign.  TXT "class=local"                                │
│  _scope.sovereign.        TXT "class=federated"                            │
│  _scope.bridge.sovereign. TXT "class=external"                             │
│                                                                              │
│  Resolver MUST check _scope before forwarding queries.                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 16.2 Federation Protocol

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FEDERATION TRUST ESTABLISHMENT                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Before two meshes can federate ZDNS:                                       │
│                                                                              │
│  1. KEY EXCHANGE                                                            │
│     • Mesh A publishes: _federation.sovereign. TXT "pubkey=..."            │
│     • Mesh B publishes: _federation.sovereign. TXT "pubkey=..."            │
│     • Keys exchanged via out-of-band or mutual introduction                │
│                                                                              │
│  2. TRUST RECORD                                                            │
│     • Mesh A adds: _trust.meshB.sovereign. TXT "key=...,since=...,scope=..."│
│     • Mesh B adds: _trust.meshA.sovereign. TXT "key=...,since=...,scope=..."│
│     • Scope defines which zones can be queried cross-mesh                  │
│                                                                              │
│  3. QUERY SIGNING                                                           │
│     • All federated queries MUST include requesting mesh signature         │
│     • All federated responses MUST include responding mesh signature       │
│     • Unsigned cross-mesh queries → reject                                 │
│                                                                              │
│  4. RESULT VALIDATION                                                       │
│     • Federated results re-verified against known trust anchors            │
│     • Results marked with "federated_from=meshB"                           │
│     • Client can see provenance                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. Update Amplification Control

### 17.1 LoRa Hint Rate Limiting

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UPDATE AMPLIFICATION CONTROL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PROBLEM: Zone flapping can cause mesh-wide LoRa storms                     │
│                                                                              │
│  Scenario:                                                                   │
│  • Zone serial increments rapidly (buggy updater)                          │
│  • Each increment triggers ZDNS_UPDATE on LoRa                             │
│  • All nodes attempt refresh simultaneously                                │
│  • LoRa channel saturated, mesh coordination breaks                        │
│                                                                              │
│  SOLUTION: Rate limiting at multiple levels                                 │
│                                                                              │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  LEVEL 1: SENDER RATE LIMIT                                                 │
│  ──────────────────────────                                                 │
│  • Max ZDNS_UPDATE broadcasts: 1 per zone per 30 seconds                   │
│  • If serial changes faster: batch into single update                      │
│  • Coalesce window: 5 seconds (wait for more changes)                      │
│                                                                              │
│  LEVEL 2: RECEIVER DEDUPLICATION                                            │
│  ───────────────────────────────                                            │
│  • Track (zone, serial) tuples seen in last 60 seconds                     │
│  • Ignore duplicate ZDNS_UPDATE for same (zone, serial)                    │
│  • Prevents amplification from multiple senders                            │
│                                                                              │
│  LEVEL 3: REFRESH BACKOFF                                                   │
│  ────────────────────────                                                   │
│  • On ZDNS_UPDATE received, don't refresh immediately                      │
│  • Add random jitter: 0-10 seconds                                         │
│  • Prevents thundering herd                                                 │
│                                                                              │
│  LEVEL 4: AUTHORITATIVE UNREACHABLE BACKOFF                                 │
│  ──────────────────────────────────────────                                 │
│  • If zone refresh fails: exponential backoff                              │
│  • Initial: 30 seconds                                                     │
│  • Max: 1 hour                                                              │
│  • Reset on successful refresh                                              │
│                                                                              │
│  LEVEL 5: STORM DETECTION                                                   │
│  ────────────────────────                                                   │
│  • If > 10 ZDNS_UPDATE seen in 60 seconds: enter storm mode               │
│  • Storm mode: ignore all ZDNS_UPDATE for 5 minutes                        │
│  • Fall back to TTL-based refresh only                                     │
│  • Log: "zdns_update_storm_detected, suppressing"                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 17.2 Configuration Parameters

```rust
/// Update amplification control configuration
pub struct UpdateControlConfig {
    // Sender limits
    pub min_broadcast_interval: Duration,     // Default: 30s
    pub coalesce_window: Duration,            // Default: 5s

    // Receiver limits
    pub dedup_window: Duration,               // Default: 60s
    pub refresh_jitter_max: Duration,         // Default: 10s

    // Backoff
    pub initial_backoff: Duration,            // Default: 30s
    pub max_backoff: Duration,                // Default: 1h
    pub backoff_multiplier: f32,              // Default: 2.0

    // Storm detection
    pub storm_threshold: u32,                 // Default: 10 updates
    pub storm_window: Duration,               // Default: 60s
    pub storm_suppression: Duration,          // Default: 5m
}

impl Default for UpdateControlConfig {
    fn default() -> Self {
        Self {
            min_broadcast_interval: Duration::from_secs(30),
            coalesce_window: Duration::from_secs(5),
            dedup_window: Duration::from_secs(60),
            refresh_jitter_max: Duration::from_secs(10),
            initial_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            backoff_multiplier: 2.0,
            storm_threshold: 10,
            storm_window: Duration::from_secs(60),
            storm_suppression: Duration::from_secs(300),
        }
    }
}
```

---

## Summary: Critical Constraints Checklist

Before deploying lib-dns in production, verify:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PRE-DEPLOYMENT CHECKLIST                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  RESOLVER BEHAVIOR                                                           │
│  □ Authoritative conflict resolution follows Rule 1-5 deterministically    │
│  □ Dual-valid answers handled without silent data loss                     │
│  □ Stale-but-signed data served with appropriate flags                     │
│                                                                              │
│  NEGATIVE CACHING                                                            │
│  □ Negative TTL capped at 60 seconds                                       │
│  □ Negative cache flushed on topology change                               │
│  □ Absence never overwrites presence                                        │
│                                                                              │
│  BOOTSTRAP                                                                   │
│  □ Trust anchor mechanism chosen (A, B, C, or D)                           │
│  □ First-node bootstrap documented for operators                           │
│  □ Trust chain verification implemented                                     │
│                                                                              │
│  CLIENT CONTRACT                                                             │
│  □ SDK enforces once-per-session resolution                                │
│  □ Identity binding survives endpoint changes                              │
│  □ No application-level DNS cache                                          │
│                                                                              │
│  FORBIDDEN BEHAVIORS                                                         │
│  □ No resolution in packet handler (verified by audit)                     │
│  □ No synchronous blockchain queries (verified by audit)                   │
│  □ Query rate limiting in place                                            │
│                                                                              │
│  ZONE SCOPING                                                                │
│  □ _scope records defined for all zones                                    │
│  □ Local zones cannot leak to federation                                   │
│  □ External zones marked and fail gracefully                               │
│                                                                              │
│  UPDATE CONTROL                                                              │
│  □ LoRa rate limiting configured                                           │
│  □ Storm detection enabled                                                 │
│  □ Backoff parameters tuned for deployment                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```
