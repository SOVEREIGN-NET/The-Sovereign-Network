# The Sovereign Network - Technical Reference

## Table of Contents

1. [Overview](#overview)
2. [Blockchain Architecture](#blockchain-architecture)
3. [Consensus Mechanism](#consensus-mechanism)
4. [Network Protocol](#network-protocol)
5. [Cryptography](#cryptography)
6. [Identity System](#identity-system)
7. [Economic Model](#economic-model)

---

## Overview

The Sovereign Network is a post-quantum secure, privacy-preserving decentralized network that implements:

- **ZHTP Protocol**: Zero-knowledge Hypertext Transfer Protocol for secure mesh communication
- **BFT Consensus**: Tendermint-style Byzantine Fault Tolerant consensus
- **UTXO Model**: Unspent Transaction Output model with zero-knowledge proofs
- **Post-Quantum Security**: Dilithium5 signatures and Kyber1024 key encapsulation

---

## Blockchain Architecture

### Block Structure

Location: `lib-blockchain/src/block.rs`

```rust
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub validator_signatures: Vec<ValidatorSignature>,
}

pub struct BlockHeader {
    pub version: u32,                    // Protocol version
    pub height: u64,                     // Block height (sequential)
    pub previous_hash: Hash,             // Hash of previous block
    pub merkle_root: Hash,               // Merkle root of transactions
    pub state_root: Hash,                // State trie root hash
    pub timestamp: u64,                  // Unix timestamp
    pub proposer: IdentityId,            // Validator who proposed block
    pub consensus_round: u32,            // BFT round number
}
```

### Transaction Types

Location: `lib-blockchain/src/transaction.rs`

| Type | Description | Fields |
|------|-------------|--------|
| `Transfer` | Move tokens between addresses | inputs, outputs, fee |
| `CreateIdentity` | Register new identity | public_key, metadata, stake |
| `UpdateIdentity` | Modify identity metadata | identity_id, new_metadata |
| `RegisterValidator` | Join validator set | identity_id, consensus_key, stake |
| `UnregisterValidator` | Leave validator set | identity_id |
| `Stake` | Lock tokens for staking | identity_id, amount |
| `Unstake` | Begin unstaking period | identity_id, amount |
| `ClaimRewards` | Claim staking rewards | identity_id |

### UTXO Model

Location: `lib-blockchain/src/utxo.rs`

The network uses an Unspent Transaction Output (UTXO) model:

```rust
pub struct Utxo {
    pub id: UtxoId,                      // Unique identifier
    pub owner: Address,                   // Owner's address
    pub amount: u64,                      // Token amount
    pub asset_type: AssetType,           // Native or custom token
    pub created_at_height: u64,          // Block height when created
    pub spent: bool,                      // Spending status
    pub commitment: Option<Hash>,        // ZK commitment (privacy)
}

pub struct UtxoId {
    pub tx_hash: Hash,                   // Transaction hash
    pub output_index: u32,               // Output index within tx
}
```

### Genesis Block

Location: `lib-blockchain/src/genesis.rs`

Genesis configuration includes:
- **Initial token distribution**: Pre-allocated UTXOs
- **Bootstrap validators**: Initial validator set
- **Protocol parameters**: Block time, max block size, etc.
- **Treasury allocation**: Initial treasury fund

```rust
pub struct GenesisConfig {
    pub chain_id: String,
    pub timestamp: u64,
    pub initial_validators: Vec<ValidatorConfig>,
    pub initial_allocations: Vec<Allocation>,
    pub protocol_params: ProtocolParams,
}
```

### State Management

Location: `lib-blockchain/src/state.rs`

The blockchain maintains several state components:

| State | Description | Storage |
|-------|-------------|---------|
| UTXO Set | All unspent outputs | Merkle Patricia Trie |
| Identity Registry | Registered identities | Key-value store |
| Validator Set | Active validators | Sorted by stake |
| Wallet Balances | Account balances (derived) | Computed from UTXOs |

---

## Consensus Mechanism

### Tendermint-style BFT

Location: `lib-consensus/src/engines/consensus_engine/`

The consensus engine implements a Tendermint-style BFT protocol with the following phases:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Propose   │────▶│   PreVote   │────▶│  PreCommit  │────▶│   Commit    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
      │  timeout          │  2f+1 votes       │  2f+1 votes       │  block finalized
      ▼                   ▼                   ▼                   ▼
```

### Consensus Steps

```rust
pub enum ConsensusStep {
    Propose,      // Proposer broadcasts block proposal
    PreVote,      // Validators vote on proposal validity
    PreCommit,    // Validators commit to accepted proposal
    Commit,       // Block is finalized and added to chain
}
```

### BFT Requirements

**Minimum Validators**: ≥4 validators required for BFT mode

The Byzantine fault tolerance formula: `f < n/3`

| Validators (n) | Tolerated Faults (f) | Quorum (2f+1) |
|----------------|---------------------|---------------|
| 4 | 1 | 3 |
| 7 | 2 | 5 |
| 10 | 3 | 7 |
| 13 | 4 | 9 |

### Bootstrap Mode vs BFT Mode

Location: `lib-consensus/src/types.rs`

```rust
pub const MIN_BFT_VALIDATORS: usize = 4;
```

| Mode | Validators | Block Production | Security |
|------|------------|------------------|----------|
| Bootstrap | < 4 | Mining loop (single proposer) | Centralized trust |
| BFT | ≥ 4 | Consensus rounds | Byzantine fault tolerant |

**Mode Transition Events**:
- `ModeTransitionToBft`: When validator count reaches 4
- `ModeTransitionToBootstrap`: When validator count drops below 4

### Vote Types

```rust
pub enum VoteType {
    PreVote,      // First-round vote on proposal
    PreCommit,    // Second-round commitment vote
    Commit,       // Final commit acknowledgment
    Against,      // Explicit rejection
}

pub struct Vote {
    pub id: VoteId,
    pub voter: IdentityId,
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    pub block_hash: Option<Hash>,
    pub timestamp: u64,
    pub signature: Signature,
}
```

### Proposer Selection

Location: `lib-consensus/src/engines/consensus_engine/proposer.rs`

Proposer selection uses weighted round-robin based on stake:

```rust
pub fn select_proposer(
    validators: &[ValidatorInfo],
    height: u64,
    round: u32,
) -> &ValidatorInfo {
    // Deterministic selection based on stake weight
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let selection_point = (height + round as u64) % total_stake;

    let mut cumulative = 0u64;
    for validator in validators {
        cumulative += validator.stake;
        if cumulative > selection_point {
            return validator;
        }
    }
    &validators[0]
}
```

### Round Timer

Location: `lib-consensus/src/timer.rs`

Timeouts increase exponentially with round number:

```rust
pub struct RoundTimer {
    pub base_timeout: Duration,      // 3 seconds default
    pub timeout_delta: Duration,     // 500ms increment per round
}

impl RoundTimer {
    pub fn timeout_for_round(&self, round: u32) -> Duration {
        self.base_timeout + self.timeout_delta * round
    }
}
```

### Liveness Monitoring

Location: `lib-consensus/src/liveness.rs`

The liveness monitor tracks validator responsiveness:

```rust
pub struct LivenessMonitor {
    pub total_validators: u32,
    pub stall_threshold: u32,        // Validators needed for quorum
    pub timeout_duration: Duration,   // 30 seconds default
}
```

**Events Emitted**:
- `ConsensusStalled`: Quorum impossible due to timeouts
- `ConsensusRecovered`: Sufficient validators responsive again
- `ValidatorTimeout`: Individual validator unresponsive

### Byzantine Detection

Location: `lib-consensus/src/byzantine.rs`

Detects malicious validator behavior:

| Detection | Description |
|-----------|-------------|
| Double Vote | Same validator votes twice in same round |
| Equivocation | Different votes for same height/round |
| Replay Attack | Duplicate message submission |
| Network Partition | Subset of validators unreachable |

```rust
pub struct ByzantineDetector {
    pub replay_window: Duration,
    pub message_cache: HashMap<Hash, ForensicRecord>,
}
```

---

## Network Protocol

### QUIC Mesh Architecture

Location: `lib-network/src/mesh/`

The network uses QUIC for reliable, encrypted peer-to-peer communication:

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  Consensus Messages │ Block Sync │ DHT │ Validator Discovery │
├─────────────────────────────────────────────────────────────┤
│                    Message Framing Layer                     │
│              (Length-prefixed, versioned messages)           │
├─────────────────────────────────────────────────────────────┤
│                   Encryption Layer (UHP)                     │
│           (ChaCha20-Poly1305 after key exchange)            │
├─────────────────────────────────────────────────────────────┤
│                    QUIC Transport Layer                      │
│              (Connection management, streams)                │
├─────────────────────────────────────────────────────────────┤
│                      TLS 1.3 Layer                          │
│              (Certificate pinning, SPKI)                    │
└─────────────────────────────────────────────────────────────┘
```

### Unified Handshake Protocol (UHP)

Location: `lib-network/src/handshake/`

UHP v2 provides mutual authentication:

```rust
pub const UHP_VERSION: u16 = 2;

// Handshake flow
enum HandshakeMessage {
    ClientHello {
        version: u16,
        capabilities: HandshakeCapabilities,
        public_key: PublicKey,
        nonce: [u8; 32],
    },
    ServerHello {
        version: u16,
        capabilities: NegotiatedCapabilities,
        public_key: PublicKey,
        nonce: [u8; 32],
        challenge: [u8; 32],
    },
    ClientFinish {
        challenge_response: ChallengeProof,
        signature: Signature,
    },
}
```

### Message Types

Location: `lib-network/src/types/mesh_message.rs`

```rust
pub enum ZhtpMeshMessage {
    // Peer discovery
    Ping { timestamp: u64 },
    Pong { timestamp: u64, peer_count: u32 },

    // DHT operations
    DhtStore { key: Vec<u8>, value: Vec<u8>, ttl: u64 },
    DhtFindValue { key: Vec<u8>, max_hops: u8 },
    DhtFindValueResponse { found: bool, value: Option<Vec<u8>> },

    // Block synchronization
    BlockSyncRequest { start_height: u64, end_height: u64 },
    BlockSyncResponse { blocks: Vec<Block> },
    BlockAnnouncement { height: u64, hash: Hash },

    // Consensus (encrypted separately)
    ConsensusMessage { encrypted_payload: Vec<u8> },

    // Validator discovery
    ValidatorAnnouncement { announcement: ValidatorAnnouncement },
}
```

### Peer Registry

Location: `lib-network/src/peer_registry.rs`

Centralized peer state management:

```rust
pub struct PeerEntry {
    pub peer_id: UnifiedPeerId,
    pub authenticated: bool,
    pub endpoints: Vec<PeerEndpoint>,
    pub capabilities: NodeCapabilities,
    pub connection_metrics: ConnectionMetrics,
    pub reputation_score: f64,
    pub last_seen: u64,
    pub tier: PeerTier,
}

pub enum PeerTier {
    Bootstrap,    // Hardcoded bootstrap nodes
    Validator,    // Active validators
    FullNode,     // Full nodes
    LightClient,  // Light clients
}
```

### Block Synchronization

Location: `lib-network/src/mesh/block_sync.rs`

Block sync protocol for catching up:

```rust
pub struct BlockSyncManager {
    pub chunk_size: usize,           // Blocks per request (default: 100)
    pub max_concurrent: usize,       // Parallel requests (default: 4)
    pub timeout: Duration,           // Request timeout (default: 30s)
}
```

**Sync Process**:
1. Query peers for their chain height
2. Identify height gap
3. Request blocks in chunks
4. Validate and apply blocks sequentially
5. Verify state roots match

### Validator Discovery

Location: `lib-network/src/validator_discovery_transport.rs`

Validators announce themselves via DHT gossip:

```rust
pub struct ValidatorAnnouncement {
    pub identity_id: IdentityId,
    pub consensus_key: PublicKey,
    pub stake: u64,
    pub storage_provided: u64,
    pub commission_rate: u16,        // Basis points (500 = 5%)
    pub endpoints: Vec<ValidatorEndpoint>,
    pub status: ValidatorStatus,
    pub last_updated: u64,
    pub signature: Signature,
}

// DHT key format: "validator:{identity_hash_hex}"
const VALIDATOR_KEY_PREFIX: &str = "validator:";
const DHT_ENTRY_TTL: u64 = 86400;   // 24 hours
```

### Bootstrap Nodes

Location: `lib-network/src/bootstrap.rs`

Bootstrap configuration with certificate pinning:

```rust
pub struct BootstrapConfig {
    pub nodes: Vec<BootstrapNode>,
    pub require_pinned_certs: bool,  // SPKI pinning required in release
}

pub struct BootstrapNode {
    pub address: SocketAddr,
    pub public_key: PublicKey,
    pub spki_fingerprint: [u8; 32],  // TLS certificate pin
}
```

---

## Cryptography

### Post-Quantum Signatures (Dilithium5)

Location: `lib-crypto/src/dilithium.rs`

NIST PQC standard for digital signatures:

| Parameter | Value |
|-----------|-------|
| Security Level | NIST Level 5 (256-bit classical) |
| Public Key Size | 2,592 bytes |
| Secret Key Size | 4,864 bytes |
| Signature Size | 4,627 bytes |

```rust
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

impl DilithiumKeyPair {
    pub fn generate() -> Self;
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature;
    pub fn verify(
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> bool;
}
```

### Post-Quantum Key Exchange (Kyber1024)

Location: `lib-crypto/src/kyber.rs`

NIST PQC standard for key encapsulation:

| Parameter | Value |
|-----------|-------|
| Security Level | NIST Level 5 |
| Public Key Size | 1,568 bytes |
| Ciphertext Size | 1,568 bytes |
| Shared Secret | 32 bytes |

```rust
pub struct KyberKeyPair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

impl KyberKeyPair {
    pub fn encapsulate(
        public_key: &KyberPublicKey,
    ) -> (KyberCiphertext, SharedSecret);

    pub fn decapsulate(
        secret_key: &KyberSecretKey,
        ciphertext: &KyberCiphertext,
    ) -> SharedSecret;
}
```

### Hashing

Location: `lib-crypto/src/hash.rs`

| Algorithm | Use Case | Output Size |
|-----------|----------|-------------|
| BLAKE3 | General hashing, Merkle trees | 32 bytes |
| SHA3-256 | Address derivation | 32 bytes |
| Keccak256 | Ethereum compatibility | 32 bytes |

```rust
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn from_bytes(bytes: &[u8]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
}

pub fn hash_blake3(data: &[u8]) -> [u8; 32];
pub fn hash_sha3_256(data: &[u8]) -> [u8; 32];
```

### Symmetric Encryption

Location: `lib-network/src/encryption.rs`

ChaCha20-Poly1305 AEAD for message encryption:

```rust
pub trait ProtocolEncryption: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn rekey(&mut self) -> Result<()>;
}

pub struct ChaCha20Poly1305Encryption {
    key: [u8; 32],
    nonce_counter: u64,
}
```

### Consensus Message Encryption

Location: `lib-network/src/consensus_encryption.rs`

Role-based encryption for consensus messages:

```rust
pub struct ConsensusAead {
    pub proposer_key: [u8; 32],
    pub validator_key: [u8; 32],
}

pub enum RoleDirection {
    ProposerToValidator,
    ValidatorToProposer,
    ValidatorToValidator,
}
```

---

## Identity System

### Identity Structure

Location: `lib-identity/src/identity.rs`

```rust
pub struct ZhtpIdentity {
    pub id: IdentityId,
    pub public_key: PublicKey,
    pub dilithium_pk: DilithiumPublicKey,
    pub kyber_pk: KyberPublicKey,
    pub metadata: IdentityMetadata,
    pub created_at: u64,
    pub updated_at: u64,
}

pub struct IdentityMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub avatar_hash: Option<Hash>,
    pub custom_fields: HashMap<String, String>,
}
```

### Identity ID Derivation

```rust
pub type IdentityId = Hash;

impl ZhtpIdentity {
    pub fn derive_id(public_key: &PublicKey) -> IdentityId {
        Hash::from_bytes(&hash_blake3(public_key.as_bytes()))
    }
}
```

### Address Derivation

Location: `lib-blockchain/src/address.rs`

```rust
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let hash = hash_sha3_256(pk.as_bytes());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        Address(addr)
    }
}
```

---

## Economic Model

### Fee Distribution

Location: `lib-economy/src/fee_distribution.rs`

Transaction fees are distributed as follows:

| Recipient | Percentage | Purpose |
|-----------|------------|---------|
| UBI Fund | 45% | Universal Basic Income distribution |
| Consensus Pool | 30% | Validator rewards |
| Governance Treasury | 15% | Network governance |
| Protocol Treasury | 10% | Development fund |

```rust
pub struct FeeDistribution {
    pub ubi_share: u16,          // 4500 (45.00%)
    pub consensus_share: u16,    // 3000 (30.00%)
    pub governance_share: u16,   // 1500 (15.00%)
    pub treasury_share: u16,     // 1000 (10.00%)
}
```

### Staking

Location: `lib-economy/src/staking.rs`

Validators must stake tokens to participate:

```rust
pub struct StakingConfig {
    pub min_stake: u64,              // Minimum to become validator
    pub unbonding_period: u64,       // Blocks before unstake completes
    pub slash_fraction: u16,         // Penalty for misbehavior (basis points)
    pub max_validators: usize,       // Active validator set size
}
```

### Slashing Conditions

| Offense | Penalty | Evidence Required |
|---------|---------|-------------------|
| Double Vote | 5% stake | Conflicting signed votes |
| Equivocation | 10% stake | Different blocks at same height |
| Extended Downtime | 0.1% stake | Missing 1000+ blocks |
| Invalid Proposal | 1% stake | Malformed block proposal |

---

## Configuration Reference

### Protocol Parameters

```rust
pub struct ProtocolParams {
    // Block parameters
    pub block_time_ms: u64,          // Target: 5000 (5 seconds)
    pub max_block_size: usize,       // Default: 1MB
    pub max_transactions: usize,     // Default: 10000

    // Consensus parameters
    pub min_validators: usize,       // BFT minimum: 4
    pub max_validators: usize,       // Default: 100
    pub consensus_timeout_ms: u64,   // Default: 3000

    // Network parameters
    pub max_peers: usize,            // Default: 50
    pub peer_ttl_secs: u64,          // Default: 3600
    pub heartbeat_interval_ms: u64,  // Default: 5000
}
```

### Default Ports

| Service | Port | Protocol |
|---------|------|----------|
| ZHTP Mesh & Block Sync | 9334 | QUIC/UDP |
| Multicast Peer Discovery | 37775 | UDP Multicast |
| RPC API (if enabled) | Configurable | HTTP/JSON-RPC |
| Metrics | 9335 | HTTP/Prometheus |

---

## Appendix: Message Flow Diagrams

### Block Production (BFT Mode)

```
Proposer                    Validators (3+)
    │                            │
    │──── Propose(Block) ───────▶│
    │                            │
    │◀─── PreVote(Hash) ─────────│  (wait for 2f+1)
    │                            │
    │──── PreVote(Hash) ────────▶│
    │                            │
    │◀─── PreCommit(Hash) ───────│  (wait for 2f+1)
    │                            │
    │──── PreCommit(Hash) ──────▶│
    │                            │
    │◀─── Commit ────────────────│
    │                            │
    ▼                            ▼
         Block Finalized
```

### Validator Discovery Flow

```
New Validator                 Network (DHT)
    │                              │
    │─── ValidatorAnnouncement ───▶│
    │       (signed, with stake)   │
    │                              │
    │                         ┌────┴────┐
    │                         │ Gossip  │
    │                         │ to peers│
    │                         └────┬────┘
    │                              │
    │◀── Acknowledgment ───────────│
    │                              │
    ▼                              ▼
    Added to validator discovery cache
```

---

*Document Version: 1.0*
*Generated: 2026-01-29*
*Based on: feat/853-treasury-kernel-m3-vesting-time-locks branch*
