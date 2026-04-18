# Sovereign Network — System Architecture

How the crates in this monorepo compose into a running network node.

## Layer Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    zhtp (Orchestrator)                   │
│   RuntimeOrchestrator · EventBus · ServiceContainer     │
├────────────┬────────────┬───────────┬───────────────────┤
│ Blockchain │  Identity  │  Storage  │     Protocol      │
│  Handler   │  Handler   │  Handler  │     Handler       │
├────────────┴────────────┴───────────┴───────────────────┤
│               lib-network (P2P Mesh)                    │
│  QUIC · mDNS · LoRaWAN · UHP v2 Handshake · PeerReg    │
├─────────────────────────────────────────────────────────┤
│  lib-consensus  │  lib-blockchain  │  lib-mempool       │
│  PoS+BFT+PoUW   │  Blocks, UTXO    │  Tx pool           │
├─────────────────┴──────────────────┴────────────────────┤
│                  lib-neural-mesh                        │
│  RlRouter · AnomalySentry · PredictivePrefetcher        │
│  NeuroCompressor · AdaptiveCodecLearner                 │
│  DistributedTrainingCoordinator (FedAvg + DP + BLAKE3)  │
├─────────────────────────────────────────────────────────┤
│               lib-compression                           │
│  SovereignCodec (SFC0–SFC9) · CDC Chunking · Shards    │
│  PatternMiner · ZK-Witness · ShardTransport             │
├──────────┬──────────────┬───────────────────────────────┤
│lib-proofs│  lib-crypto   │  lib-identity                │
│ Plonky2  │  BLAKE3       │  ZK-DID                      │
│Bulletprfs│  Dilithium5   │  Social Recovery              │
│          │  Kyber1024    │  Citizenship                  │
├──────────┴──────────────┴───────────────────────────────┤
│  lib-dht  │  lib-dns  │  lib-economy  │  lib-fees       │
│  lib-storage │ lib-tokens │ lib-utxo │ lib-governance   │
└─────────────────────────────────────────────────────────┘
```

## Data Flow: Transaction Lifecycle

```
Client submits Tx
  → lib-mempool validates & queues
  → lib-consensus proposes block (BFT round)
  → lib-proofs generates ZK proof (Plonky2 circuit)
  → lib-blockchain commits block (sled storage)
  → lib-network broadcasts to mesh peers
  → lib-compression deduplicates & stores shards
  → lib-neural-mesh optimizes routing for next round
```

## Data Flow: Neural Compression Pipeline

```
Raw data arrives
  → ContentProfile::analyze() → 8-D state vector
  → AdaptiveCodecLearner::predict_params() → CodecParams
  → SovereignCodec::encode_with_params() → compressed bytes
  → CompressionFeedback fed back to learner
  → DistributedTrainingCoordinator syncs model weights
  → Federated average (with DP noise) improves all nodes
```

## Crate Reference

### Core Infrastructure

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `zhtp` | Orchestrator node binary | `ZhtpServer`, `RuntimeOrchestrator`, `NodeConfig` |
| `zhtp-cli` | CLI client | Command-line interface |
| `zhtp-daemon` | Systemd daemon wrapper | Service management |
| `lib-network` | P2P mesh networking | `ZhtpMeshServer`, `PeerRegistry`, `UnifiedPeerId` |
| `lib-consensus` | Multi-layer consensus (PoS + BFT + PoUW) | `ConsensusEngine`, `Validator`, `ChainEvaluator` |
| `lib-blockchain` | Chain state & blocks | `Block`, `Transaction`, `Blockchain`, `Mempool` |
| `lib-mempool` | Transaction pool | Mempool management |

### Cryptography & Proofs

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `lib-crypto` | Post-quantum cryptography | `KeyPair`, `Signature`, `PostQuantumSignature`, `Hash` |
| `lib-proofs` | Zero-knowledge proofs | `ProofBackend`, `Plonky2Backend`, `ZkRangeProof` |

**Proof backends**: `Plonky2Backend` (production) generates real circuits for transaction validity, identity attestation, and storage access. `ZkRangeProof` uses Bulletproofs for efficient range proofs. The `fake-proofs` feature flag swaps in a mock backend for testing.

### Identity & Access

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `lib-identity` | ZK-anchored identity system | `ZhtpIdentity`, `IdentityManager`, `DidDocument` |
| `lib-identity-core` | Shared identity primitives | Core types |
| `lib-access-control` | Permission management | Access control logic |

**Identity model**: A single seed derives the DID, node IDs, and all cryptographic keys. Social recovery via guardian networks. Selective-disclosure ZK credentials for privacy-preserving KYC.

### Compression & Neural Intelligence

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `lib-compression` | Lossless codec + network dedup | `SovereignCodec`, `CodecParams`, `ContentChunker` |
| `lib-neural-mesh` | On-device AI subsystems | `RlRouter`, `AnomalySentry`, `AdaptiveCodecLearner` |

**Self-optimizing loop**: The neural mesh observes compression results and tunes codec parameters. Models are shared across the network via federated learning with (ε,δ)-differential privacy and BLAKE3 authenticated encryption. The more data the network processes, the better every node compresses.

### Economy & Governance

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `lib-economy` | SOV token economics | Token distribution, UBI |
| `lib-fees` | Fee calculation | Dynamic fee model |
| `lib-tokens` | Token management | Multi-token support |
| `lib-utxo` | UTXO set management | Unspent output tracking |
| `lib-governance` | On-chain governance | DAO, proposals, voting |

### Storage & Discovery

| Crate | Purpose | Key Types |
|-------|---------|-----------|
| `lib-storage` | Distributed storage | sled-backed persistence |
| `lib-dht` | Distributed hash table | Peer discovery |
| `lib-dns` | DNS resolution | Name resolution |
| `lib-protocols` | Protocol definitions | ZHTP protocol handlers |
| `lib-client` | Client SDK (FFI) | UniFFI + React Native bindings |

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | QUIC + Kyber1024 KEM + UHP v2 handshake |
| Identity | ZK-DID + Dilithium5 PQ signatures |
| Consensus | BFT finality + slashing + jail/ban |
| Neural sync | (ε,δ)-DP noise + BLAKE3 authenticated encryption |
| Data | ZK-Witness proofs of possession |
| Proofs | Plonky2 circuits (tx, identity, storage) + Bulletproofs ranges |

## Test Suite

```bash
cargo test --workspace                          # All 365 tests
cargo test -p lib-compression --lib             # 85 compression tests
cargo test -p lib-neural-mesh --lib             # 76 neural mesh tests
cargo test -p lib-proofs --lib                  # 185 proof tests
cargo test --test test_full_stack_e2e           # 8 end-to-end tests
cargo test --test test_neural_mesh_integration  # 7 neural mesh integration
cargo test --test test_orchestrator_integration # 4 orchestrator tests
```

## Directory Layout

```
├── zhtp/                   Main orchestrator node
├── zhtp-cli/               CLI client
├── zhtp-daemon/            Systemd daemon
├── lib-blockchain/         Chain state, blocks, transactions
├── lib-compression/        SovereignCodec + network dedup
├── lib-consensus/          Multi-layer BFT consensus
├── lib-crypto/             Post-quantum cryptography
├── lib-dht/                Distributed hash table
├── lib-dns/                DNS resolution
├── lib-economy/            SOV tokenomics
├── lib-fees/               Fee calculation
├── lib-governance/         On-chain governance
├── lib-identity/           ZK identity + DID
├── lib-identity-core/      Shared identity primitives
├── lib-mempool/            Transaction pool
├── lib-network/            P2P mesh networking
├── lib-neural-mesh/        AI subsystems (routing, anomaly, compression)
├── lib-proofs/             ZK proofs (Plonky2 + Bulletproofs)
├── lib-protocols/          Protocol definitions
├── lib-storage/            Distributed storage
├── lib-tokens/             Token management
├── lib-utxo/               UTXO management
├── lib-access-control/     Permission system
├── lib-client/             Client SDK (UniFFI)
├── explorer/               Block explorer (Trunk/WASM)
├── browser-extension/      Browser extension
├── tools/                  Operator utilities
├── tests/                  Integration tests
├── docs/                   Documentation
└── scripts/                Build & test scripts
```
