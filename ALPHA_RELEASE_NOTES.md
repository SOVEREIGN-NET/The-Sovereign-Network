# Alpha Release Notes - v0.1.0-alpha.1

## Overview

This is the first alpha release of The Sovereign Network. This release establishes the core identity and networking infrastructure required for deterministic node identification across mesh networks.

## Alpha Goals

1. **Deterministic NodeId** - Nodes derive their identity from a seed, ensuring the same NodeId across restarts
2. **Seed-Anchored Identity** - All identity components (DID, NodeId, keys) derive from a single seed
3. **Network Integration** - Mesh networking components use deterministic NodeIds

## What's New

### Identity System (ADR-0001, ADR-0004)

- **Seed-Anchored Identity**: All identity components derive from a single seed via a deterministic root signing key
- **Deterministic Root Key (ADR-0004)**: DID is anchored to the deterministic root signing public key derived from the seed
- **NodeId Derivation**:
  - **Legacy deterministic method** (`NodeId::from_did_device()`): Uses format `Blake3("ZHTP_NODE_V2:network={network}:version={version}:{DID}:{normalized_device}")` where device is normalized (trimmed, lowercase, validated). This method is kept for backward compatibility but is vulnerable to rainbow table attacks.
  - **Recommended secure method** (`NodeId::from_identity_components()`): Uses domain separation prefix `"ZHTP_NODE_ID_V2"` with additional entropy sources including network genesis binding, cryptographic random nonce (256 bits), and timestamp binding. This non-deterministic approach prevents rainbow table attacks and cross-chain replay while enforcing minimum device ID entropy (8+ chars, 4+ unique characters).
  - **Security tradeoff**: Legacy method provides deterministic reconstruction (same inputs = same NodeId) but is less secure. New method provides strong security guarantees but requires storing the generated NodeId and its metadata (nonce, network genesis) for verification.
- **Unified Constructor**: `ZhtpIdentity::new_unified(type, age, jurisdiction, device, seed?)` derives the root key, DID, and per-device keys
- **Multi-Device Support**: Same seed = same root signing key and DID; per-device NodeIds and operational keys are distinct and rotatable

### Network Layer

- **Mesh Networking**: ZhtpMeshServer now uses lib_identity::NodeId
- **Deterministic Connections**: NodeId verified during handshake
- **DHT Integration**: Distributed hash table uses deterministic NodeIds

### Proof System (ADR-0003)

- **Ownership Proof Placeholder**: SignaturePopV1 deferred to Phase 3
- **Future-Proofing**: Proof envelope versioning planned for v1

## Alpha Limitations

- Proof versioning not yet enforced (v0 envelope planned)
- Bootstrap nodes not deployed
- Binary builds for Linux/macOS only (Windows pending)
- No production testnet

## Known Issues

1. **Pre-existing test failures**: 3 test failures in lib-consensus and lib-network (unrelated to alpha features)
2. **Documentation**: Some API docs need updates
3. **Examples**: Legacy examples need cleanup (deferred to post-alpha)

## Migration Guide

### For Developers

If you have existing code using the old `[u8; 32]` NodeId type:

```rust
// OLD
let legacy_node_id: [u8; 32] = hash_blake3(b"some-input");

// NEW (wrap existing bytes without changing the underlying value)
use lib_identity::types::NodeId;
let node_id = NodeId::from_bytes(legacy_node_id);

// For NEW code deriving from DID + device (recommended going forward):
let node_id_from_did = NodeId::from_did_device("did:zhtp:...", "device-name");
```

### For Node Operators

1. **New Nodes**: Use `ZhtpIdentity::new_unified()` to create deterministic identity
2. **Existing Nodes**: Backup your seed phrase - same seed = same NodeId on restart

## Alpha Roadmap

### Phase 1 (This Release)
- ✅ Seed-anchored identity
- ✅ Deterministic NodeId
- ✅ Mesh networking integration
- ⏳ Documentation & release

### Phase 2 (Planned)
- Proof versioning v0 implementation
- Production testnet
- Full binary releases

### Phase 3 (Future)
- SignaturePopV1 ownership proofs
- Enhanced proof validation

## Contributing

See [README.md](./README.md) for development guidelines and contribution workflow.

## Support

- Issues: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues
- Discussions: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/discussions
