# lib-compression - Pied Piper Lossless Compression Layer

## Overview

`lib-compression` implements a revolutionary **Network-as-a-Disk** architecture where files are transformed from local bit-storage to global shard possession. Through content-defined chunking, Zero-Knowledge proofs, and the existing ZHTP mesh, this module achieves compression ratios that scale with network size rather than individual file characteristics.

**Core Concept**: Files don't shrink—they disappear into the mesh and become mathematically reconstructible via ZK-Witness metadata.

## Architecture Philosophy

Traditional compression reduces file size. **Network compression eliminates redundancy globally**. When 1 million users possess the same file, the Sovereign Network stores it once (with healthy redundancy), but 1 million users can reconstruct it via their ZK-Witnesses.

### The "Pied Piper" Effect

- **Local Storage**: 50GB file → 50KB ZK-Witness file
- **Network Storage**: Deduplicated shards with N-way redundancy
- **Retrieval Speed**: Parallel QUIC streams from nearest nodes (potentially faster than local SSD)
- **Security**: Post-quantum encrypted shards + ZK proof of ownership

## Technical Components

### 1. Content-Defined Chunking (CDC)

**Module**: `lib-compression/src/chunking/`

```rust
pub struct ContentChunker {
    algorithm: ChunkingAlgorithm,  // Rabin, FastCDC, or Gear
    min_size: usize,                // Default: 2KB
    avg_size: usize,                // Default: 8KB
    max_size: usize,                // Default: 64KB
}

pub struct Shard {
    pub id: [u8; 32],              // BLAKE3 hash (content-addressed)
    pub data: Vec<u8>,             // Encrypted shard data
    pub size: usize,
    pub encryption_key: [u8; 32],  // Derived from shard hash (convergent encryption)
}
```

**Why Variable-Size Chunks?**
- Identical content produces identical shard IDs across different files
- Single-byte modifications don't invalidate the entire file
- Enables cross-file deduplication naturally

**Implementation Strategy:**
- Use **FastCDC** algorithm (faster than Rabin, better boundary detection)
- Rolling hash window for boundary detection
- Content-aware chunking preserves semantic boundaries

### 2. ZK-Witness System

**Module**: `lib-compression/src/witness/`

```rust
pub struct ZkWitness {
    pub root_hash: Hash,               // BLAKE3 final file identifier
    pub shard_ids: Vec<Hash>,          // Ordered DHT pointers
    pub merkle_root: Hash,             // Merkle tree of shard_ids
    pub zk_proof: ZkProof,             // Plonky2 proof of correct assembly
    pub metadata: FileMetadata,        // Original filename, size, MIME type
    pub created_at: u64,
}

pub struct FileMetadata {
    pub filename: String,
    pub original_size: u64,
    pub mime_type: String,
    pub permissions: u32,
    pub timestamps: FileTimestamps,
}
```

**ZK Circuit Logic**:
```
Prove: ∀i ∈ [0..N], BLAKE3(shard[i]) == shard_ids[i]
       AND MerkleRoot(shard_ids) == merkle_root
       AND Concatenate(shards) → BLAKE3 == root_hash
```

**Integration with lib-proofs:**
- Uses existing Plonky2 recursive SNARK infrastructure
- Leverages `lib-proofs::verifiers::RecursiveProofAggregator`
- Compatible with `lib-proofs::merkle` module

### 3. Shard Distribution & DHT Integration

**Module**: `lib-compression/src/distribution/`

```rust
pub struct ShardManager {
    dht: Arc<DhtManager>,              // From lib-storage
    local_cache: LruCache<Hash, Shard>,
    network: Arc<ZhtpMeshServer>,      // From lib-network
    reputation: Arc<ReputationSystem>, // From lib-economy
}

impl ShardManager {
    /// Distribute unique shards to the mesh
    pub async fn distribute_shards(
        &self,
        shards: Vec<Shard>,
        redundancy: usize,  // N-way replication
    ) -> Result<ShardDistributionReport>;
    
    /// Retrieve shards in parallel from nearest nodes
    pub async fn fetch_shards(
        &self,
        shard_ids: Vec<Hash>,
        witness: &ZkWitness,
    ) -> Result<Vec<Shard>>;
}
```

**DHT Integration Points**:
- Extends `lib-storage::dht::DhtProtocol` with `SHARD_REQUEST` and `SHARD_RESPONSE` messages
- Uses `lib-storage::economic::ReputationSystem` for peer selection
- Leverages `lib-network::protocols` for multi-protocol transport (BLE, WiFi, LoRaWAN)

### 4. Just-In-Time (JIT) Reassembly

**Module**: `lib-compression/src/reassembly/`

```rust
pub struct JitAssembler {
    buffer: MemoryMappedFile,          // Virtual file buffer
    shard_bitmap: BitVec,              // Track received shards
    verifier: Arc<ZkVerifier>,         // From lib-proofs
}

impl JitAssembler {
    /// Assemble file shards as they arrive (streaming)
    pub async fn assemble_streaming(
        &mut self,
        witness: &ZkWitness,
        shard_stream: ShardStream,
    ) -> Result<ReconstructedFile>;
    
    /// Verify integrity after assembly
    pub fn verify_integrity(&self, witness: &ZkWitness) -> Result<bool>;
}
```

**Key Features**:
- **Memory-mapped I/O**: Write shards directly to virtual file
- **Parallel Verification**: Verify shards as they arrive using ZK proofs
- **Streaming Support**: Start using file before complete download (video playback, level loading)
- **Self-Healing**: Automatically fetch replacement shards if verification fails

### 5. ZHTP Protocol Extensions

**Module**: `lib-compression/src/protocol/`

**New Message Types** (extends `lib-network` ZHTP protocol):

```rust
pub enum CompressionMessage {
    ShardRequest {
        shard_ids: Vec<Hash>,
        witness_proof: ZkProof,      // Prove ownership
        priority: RequestPriority,
        requester_id: NodeId,
    },
    
    ShardResponse {
        shard_id: Hash,
        data: Vec<u8>,                // Encrypted shard
        signature: PostQuantumSignature,  // From lib-crypto
    },
    
    ShardAvailability {
        shard_ids: Vec<Hash>,
        node_id: NodeId,
        health_score: f64,
    },
    
    ShardMigrationRequest {
        shard_id: Hash,
        target_region: GeographicRegion,
        reason: MigrationReason,
    },
}
```

**Performance Optimizations**:
- **Batch Requests**: Request up to 1000 shards in single DHT query
- **Proximity Routing**: Prioritize nodes within same geographic region
- **Parallel Streams**: Open 10-50 concurrent QUIC streams
- **Adaptive Fetch**: Dynamically adjust fetch parallelism based on bandwidth

## Integration with Existing Infrastructure

### Dependencies

```toml
[dependencies]
lib-crypto = { path = "../lib-crypto" }        # Post-quantum encryption
lib-proofs = { path = "../lib-proofs" }        # ZK circuits
lib-storage = { path = "../lib-storage" }      # DHT and persistence
lib-network = { path = "../lib-network" }      # ZHTP mesh transport
lib-economy = { path = "../lib-economy" }      # Reputation and rewards
lib-identity = { path = "../lib-identity" }    # Proof of ownership

fastcdc = "3.1"           # Content-defined chunking
blake3 = "1.5"            # Fast cryptographic hashing
memmap2 = "0.9"           # Memory-mapped file I/O
bitvec = "1.0"            # Efficient bitmap for shard tracking
lru = "0.12"              # LRU cache for local shards
```

### Existing Infrastructure Leverage

| Existing Module | Usage in lib-compression |
|----------------|--------------------------|
| **lib-crypto** | Kyber-1024 shard encryption, Dilithium5 signatures |
| **lib-proofs** | Plonky2 ZK circuits for reconstruction proofs |
| **lib-storage** | DHT for shard discovery, Sled backend for witness storage |
| **lib-network** | QUIC parallel streaming, mesh peer discovery |
| **lib-economy** | Reputation scoring, shard hosting rewards |
| **lib-consensus** | BFT verification of shard integrity |
| **lib-identity** | ZK proof of file ownership without revealing content |

## Performance Characteristics

### Compression Ratios

**Global Deduplication Efficiency:**
```
Scenario: 1 million users with identical OS image (5GB)
- Traditional: 5GB × 1M = 5 PB total storage
- Sovereign: 5GB × redundancy(10x) = 50GB total storage
- Compression Ratio: 100,000:1
```

**Per-User Footprint:**
```
Local File:    5GB → 5KB ZK-Witness (1,000,000:1)
Network Cost:  50GB / 1M users = 50KB per user
```

### Retrieval Speed

**The Network Flywheel Effect:**
```
Speed = Σ (bandwidth_of_nearest_N_nodes)

Example with 50 nearby nodes:
- Traditional download: 100 Mbps (single server)
- Sovereign parallel: 50 nodes × 100 Mbps = 5 Gbps effective
- Result: 50GB file downloads in 80 seconds (faster than local SSD)
```

**Latency Characteristics:**
- **First Byte**: 10-50ms (DHT lookup + first shard)
- **Streaming Start**: 100-500ms (enough shards for playback)
- **Full Reconstruction**: Scales with file size and mesh density

### Security Model

**Post-Quantum Protection Layers:**
1. **Shard Encryption**: Kyber-1024 KEM (quantum-resistant)
2. **Ownership Proof**: Dilithium5 signatures on ZK-Witness
3. **Convergent Encryption**: Key = Hash(shard), enables dedup without privacy loss
4. **BFT Verification**: Consensus on shard integrity prevents tampering

**Attack Resistance:**
- ❌ **Shard Interception**: Useless without ZK-Witness and encryption keys
- ❌ **DHT Poisoning**: BFT consensus rejects invalid shards
- ❌ **Replay Attacks**: Dilithium5 signatures with timestamps
- ❌ **Sybil Attacks**: Reputation system + economic staking

## Implementation Phases

### Phase I: Core Chunking & Deduplication (Weeks 1-3)
- [ ] Implement FastCDC chunker
- [ ] BLAKE3-based content addressing
- [ ] Convergent encryption with Kyber
- [ ] Local shard cache management
- [ ] Integration tests with lib-storage

### Phase II: ZK-Witness System (Weeks 4-6)
- [ ] Design Plonky2 circuit for file reconstruction
- [ ] Implement ZkWitness metadata structure
- [ ] Merkle tree construction for shard verification
- [ ] Integration with lib-proofs
- [ ] Benchmark proof generation/verification times

### Phase III: DHT Distribution (Weeks 7-9)
- [ ] Extend ZHTP protocol with shard messages
- [ ] Implement ShardManager with DHT integration
- [ ] Geographic shard placement strategies
- [ ] N-way redundancy logic
- [ ] Health monitoring and auto-repair

### Phase IV: JIT Reassembly (Weeks 10-12)
- [ ] Memory-mapped file buffer implementation
- [ ] Parallel shard fetching over QUIC
- [ ] Streaming reassembly logic
- [ ] Integrity verification pipeline
- [ ] Self-healing on corruption detection

### Phase V: Economic Integration (Weeks 13-14)
- [ ] Shard hosting rewards in lib-economy
- [ ] Bandwidth contribution tracking
- [ ] "Rare shard" incentive bonuses
- [ ] Storage contract SLAs
- [ ] Reputation scoring for shard providers

### Phase VI: Optimization & Polish (Weeks 15-16)
- [ ] Adaptive fetch parallelism
- [ ] Predictive caching (frequently accessed shards)
- [ ] Cross-file delta compression
- [ ] Batch operations and pipelining
- [ ] Comprehensive benchmarking suite

## Usage Examples

### Basic Compression & Distribution

```rust
use lib_compression::{ContentChunker, ShardManager, ZkWitness};

// Initialize compression system
let chunker = ContentChunker::new(ChunkingAlgorithm::FastCDC);
let shard_manager = ShardManager::new(dht, network, economy).await?;

// Compress file into shards
let file_data = tokio::fs::read("large_video.mp4").await?;
let shards = chunker.chunk_content(&file_data)?;

// Distribute unique shards to mesh
let distribution = shard_manager.distribute_shards(
    shards,
    10,  // 10-way redundancy
).await?;

// Generate ZK-Witness (the "compressed" file)
let witness = ZkWitness::generate(
    &file_data,
    &distribution.shard_ids,
    identity,
)?;

// Save witness (replaces original file)
witness.save("large_video.mp4.zkw").await?;

// Original file can now be deleted
tokio::fs::remove_file("large_video.mp4").await?;

println!("Compression: {} → {} (ratio: {}:1)",
    file_data.len(),
    witness.size(),
    file_data.len() / witness.size()
);
```

### Parallel Reconstruction

```rust
use lib_compression::{JitAssembler, ShardManager};

// Load ZK-Witness
let witness = ZkWitness::load("large_video.mp4.zkw").await?;

// Create JIT assembler
let mut assembler = JitAssembler::new(witness.original_size)?;

// Fetch shards in parallel from mesh
let shard_stream = shard_manager.fetch_shards_streaming(
    &witness.shard_ids,
    50,  // Fetch from 50 nodes concurrently
).await?;

// Reassemble with streaming support
let reconstructed = assembler.assemble_streaming(
    &witness,
    shard_stream,
).await?;

// Verify integrity
assert!(assembler.verify_integrity(&witness)?);

println!("File reconstructed and verified!");
```

### Gaming Use Case: Instant-Play Streaming

```rust
use lib_compression::{GameStreamingManager, ZkWitness};

// Game studio publishes game as ZK-Witness
let game_witness = ZkWitness::load("cyberpunk_2087.zkw").await?;

// Player requests game
let streaming_mgr = GameStreamingManager::new(shard_manager);

// Start streaming essential shards first (main menu, first level)
let priority_shards = game_witness.get_priority_shards()?;
streaming_mgr.prefetch_priority(priority_shards).await?;

// Game launches while remaining shards download in background
println!("Game ready to play! Remaining: {}%", 
    streaming_mgr.completion_percentage()
);

// As player progresses, predict and prefetch next level shards
streaming_mgr.enable_predictive_prefetch(true);
```

## Benefits Summary

### For Users
- **Infinite Storage**: Your device stores mathematical proofs, not data
- **Faster Access**: Parallel retrieval often exceeds local disk speeds
- **Privacy**: Files encrypted + ZK ownership proofs
- **Resilience**: Data survives device loss (mesh redundancy)

### For Network
- **Efficiency**: Global deduplication scales compression with network size
- **Speed**: More nodes = faster retrieval (inverse of traditional networks)
- **Incentives**: Nodes earn SOV for hosting shards
- **Sustainability**: Storage requirements scale with unique data, not user count

### For Developers
- **Zero Install**: Games/apps stream instantly
- **Version Control**: Only deltas need distribution
- **Anti-Piracy**: ZK proofs for ownership without DRM
- **Global CDN**: Free, decentralized content delivery

## Security Considerations

### Threat Model

**Protected Against:**
- ✅ Quantum computer attacks (Kyber/Dilithium)
- ✅ Shard tampering (BFT consensus verification)
- ✅ Privacy invasion (convergent encryption + ZK proofs)
- ✅ Data loss (N-way redundancy across mesh)
- ✅ Unauthorized access (ZK proof of ownership required)

**Attack Vectors to Monitor:**
- ⚠️ **Sybil Attacks on DHT**: Mitigated by reputation + economic staking
- ⚠️ **Targeted Shard Deletion**: Auto-repair from redundant nodes
- ⚠️ **Timing Attacks on ZK**: Use constant-time operations
- ⚠️ **Eclipse Attacks**: Multiple DHT bootstrap nodes

## Future Enhancements

### Planned Features
- [ ] **Cross-file delta compression**: Find similarities between semantically different files
- [ ] **Predictive prefetching**: ML-based (see lib-neural-mesh integration)
- [ ] **Hierarchical sharding**: Variable shard sizes based on content importance
- [ ] **Erasure coding**: Reed-Solomon for even better redundancy ratios
- [ ] **Mobile optimizations**: Low-power shard caching strategies

### Integration Points
- **lib-neural-mesh**: Semantic chunking, predictive prefetch
- **Web4 contracts**: Decentralized websites use compression automatically
- **Gaming SDK**: Native game engine plugins for streaming assets

## License

MIT OR Apache-2.0

---

**Status**: 🟡 Proposed - Ready for Implementation

**Maintainers**: Sovereign Network Core Team

**Related Modules**:
- [lib-neural-mesh](../lib-neural-mesh/README.md) - ML optimization layer
- [lib-storage](../lib-storage/README.md) - DHT and persistence
- [lib-proofs](../lib-proofs/README.md) - ZK proof system
- [lib-network](../lib-network/README.md) - ZHTP mesh transport
