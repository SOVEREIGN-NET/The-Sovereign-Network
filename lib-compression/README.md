# lib-compression — Sovereign Codec & Network Compression

Lossless compression engine for the Sovereign Network. Provides the **SovereignCodec** (SFC format family), content-defined chunking, global shard deduplication, and ZK-witnessed reconstruction.

## Core Idea

Traditional compression shrinks individual files. Sovereign compression eliminates redundancy **across the entire network**. When many nodes hold the same data, it's stored once (with N-way redundancy) and every holder reconstructs it from a ZK-Witness — a tiny proof of ownership.

The codec itself is tunable by a neural network (lib-neural-mesh's `AdaptiveCodecLearner`) that learns optimal compression parameters for each content type.

## SovereignCodec

The primary compression API. Stateless, lossless, format-versioned.

```rust
use lib_compression::SovereignCodec;

// Standard compression (SFC7 — BWT + MTF + RLE + Adaptive O1 Range)
let compressed = SovereignCodec::encode(&data);
let restored = SovereignCodec::decode(&compressed).unwrap();
assert_eq!(data, restored);

// Neural-tuned compression (SFC9 — content-adaptive parameters)
use lib_compression::CodecParams;
let params = CodecParams {
    rescale_limit: 32768,  // Frequency model reset threshold
    freq_step: 4,          // Symbol frequency increment
    init_freq_zero: 64,    // Initial zero-symbol frequency
};
let compressed = SovereignCodec::encode_with_params(&data, &params);
let restored = SovereignCodec::decode(&compressed).unwrap();
assert_eq!(data, restored);
```

### SFC Format Versions

| Format | Magic | Pipeline | Use Case |
|--------|-------|----------|----------|
| SFC0 | `SFC0` | Stored (passthrough) | Incompressible data |
| SFC1 | `SFC1` | Huffman | Legacy |
| SFC2 | `SFC2` | BWT → MTF → RLE → Huffman | Legacy |
| SFC3 | `SFC3` | BWT → MTF → RLE → Range coder | Legacy |
| SFC4 | `SFC4` | LZ77 + dual Huffman (DEFLATE-like) | Legacy |
| SFC5 | `SFC5` | BWT → MTF → RLE → Order-1 Range | Legacy |
| SFC6 | `SFC6` | BWT → MTF → Adaptive O1 Range | Legacy |
| **SFC7** | `SFC7` | BWT → MTF → RLE → Adaptive O1 Range | **Default** (`encode()`) |
| SFC8 | `SFC8` | Blocked sub-encoding (large files) | Auto for files > MAX_BWT_SIZE |
| **SFC9** | `SFC9` | Parametric adaptive (neural-tuned) | **`encode_with_params()`** |

All formats decode through a single `SovereignCodec::decode()` entry point.

### CodecParams

Three parameters that control the adaptive arithmetic coder:

| Field | Type | Range | Default | Effect |
|-------|------|-------|---------|--------|
| `rescale_limit` | `u32` | 1024–262140 (×4) | 65536 | How often frequency model rescales. Lower = more adaptive, higher = more stable |
| `freq_step` | `u8` | 1–16 | 2 | Frequency increment per seen symbol. Higher = faster adaptation |
| `init_freq_zero` | `u8` | 1–255 | 128 | Initial frequency for null byte. Affects binary vs text performance |

When `CodecParams` match defaults, `encode_with_params` falls through to standard SFC7.

## Network Compression Stack

Beyond the codec, lib-compression provides the full network deduplication pipeline:

```
Raw Data
  ↓  ContentChunker (CDC — Rabin/FastCDC/Gear)
Shards (content-addressed, BLAKE3-hashed)
  ↓  ZkcCompressor (per-shard SovereignCodec)
CompressedShards
  ↓  PatternMiner + PatternDictionary (cross-shard learning)
Global Pattern Library
  ↓  ShardTransport (QUIC mesh distribution)
DHT-stored encrypted shards
  ↓  ZkWitness (proof of data possession)
Reconstruction metadata (~50KB per file)
```

### Key Types

| Type | Module | Purpose |
|------|--------|---------|
| `ContentChunker` | `chunker` | Content-defined chunking with configurable algorithm |
| `Shard` / `ShardId` / `ShardManager` | `shard` | Content-addressed shard management |
| `ZkcCompressor` / `CompressedShard` | `zkc_compressor` | Per-shard compression with SovereignCodec |
| `ZkcDecompressor` | `zkc_decompressor` | Shard decompression |
| `PatternMiner` / `PatternDictionary` | `patterns`, `pattern_dict` | Cross-file pattern learning |
| `GLOBAL_PATTERN_DICT` | `pattern_dict` | Singleton global pattern dictionary |
| `ShardTransport` / `TransportConfig` | `transport` | QUIC mesh shard distribution |
| `ZkWitness` | `witness` | ZK proof of data possession |
| `JitAssembler` | `assembler` | JIT shard reassembly |

### Constants

```rust
pub const AVG_SHARD_SIZE: usize = 1_048_576;   // 1 MB
pub const MIN_SHARD_SIZE: usize = 262_144;      // 256 KB
pub const MAX_SHARD_SIZE: usize = 4_194_304;    // 4 MB
pub const DEFAULT_REDUNDANCY: usize = 3;
```

## Neural Integration

lib-compression is designed to be driven by lib-neural-mesh's `AdaptiveCodecLearner`:

1. **Content profiling** — `ContentProfile::analyze(data)` produces an 8-dimensional state vector (content type, entropy, text ratio, size)
2. **Parameter prediction** — The RL agent maps the state vector to `CodecParams`
3. **Compression** — `SovereignCodec::encode_with_params(data, &params)`
4. **Feedback** — `CompressionFeedback` (ratio, throughput, integrity) feeds reward back to the agent

This creates a closed learning loop: the more data the network compresses, the better it gets at choosing parameters for each content type.

## Tests

```bash
cargo test -p lib-compression --lib    # 85 unit tests
```

## See Also

- [ZKC-COMPRESSION.md](ZKC-COMPRESSION.md) — Design spec for the zero-knowledge compression algorithm
- `lib-neural-mesh` — AdaptiveCodecLearner, NeuroCompressor, semantic deduplication
