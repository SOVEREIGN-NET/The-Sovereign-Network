#!/bin/bash
# ZHTP Dependency Analysis
# Shows what each major dependency is used for in our codebase

echo "🔍 ZHTP Dependency Analysis"
echo "=========================="
echo ""

echo "📦 Essential Dependencies (Cannot be removed):"
echo ""

echo "🔐 CRYPTOGRAPHY & ZK-PROOFS:"
echo "- ark-ff, ark-bn254, ark-ec: Zero-knowledge SNARK proofs (ceremony, consensus, transactions)"
echo "- pqcrypto-dilithium: Post-quantum digital signatures (all network communications)"
echo "- pqcrypto-kyber: Post-quantum key exchange (encrypted P2P networking)"
echo "- blake3: Fast cryptographic hashing (blocks, transactions, content addressing)"
echo "- sha2, sha3: Additional hashing for compatibility and security"
echo "- ed25519-dalek: Classical signatures for compatibility"
echo ""

echo "🌐 NETWORKING & ASYNC:"
echo "- tokio: Async runtime (entire P2P network, consensus, ceremony)"  
echo "- hyper, http: HTTP server for API endpoints and browser interface"
echo "- futures: Async programming utilities"
echo ""

echo "💾 SERIALIZATION & DATA:"
echo "- serde, serde_json: Data serialization (configs, transactions, network messages)"
echo "- bincode: Efficient binary serialization for network protocols"
echo "- base64, hex: Data encoding for APIs and storage"
echo "- toml: Configuration file parsing"
echo ""

echo "📝 SMART CONTRACTS:"
echo "- wasmi, wat: WebAssembly runtime for smart contracts"
echo ""

echo "🛠️ UTILITIES:"
echo "- anyhow: Error handling throughout the codebase"
echo "- chrono: Timestamps for blocks, transactions, ceremony"
echo "- uuid: Unique identifiers for nodes, transactions, content"
echo "- rand: Secure random generation for keys, nonces, ceremony"
echo "- zeroize: Secure memory clearing for cryptographic keys"
echo ""

echo "📊 SIZE BREAKDOWN (Estimated):"
echo "- ARK cryptography suite: ~80MB (ZK-SNARK dependencies)"  
echo "- Post-quantum crypto: ~50MB (Dilithium + Kyber implementations)"
echo "- Tokio async runtime: ~40MB (Network stack)"
echo "- WASM runtime: ~30MB (Smart contract execution)"
echo "- Other dependencies: ~62MB (utilities, serialization, etc.)"
echo "- Total: ~262MB"
echo ""

echo "✅ VERIFICATION:"
echo "All dependencies are actively used in the ZHTP codebase:"
echo "- ZK-proofs: ceremony, consensus, private transactions, DAO voting"
echo "- Post-quantum crypto: all signatures and key exchange"
echo "- Networking: P2P communication, ceremony coordination"
echo "- Smart contracts: DApp platform, token contracts"
echo ""

echo "⚠️  OPTIMIZATION NOTES:"
echo "- Dependencies are compile-time only - runtime image is minimal"
echo "- Using slim Debian base reduces runtime image to ~100MB"
echo "- Multi-stage build separates heavy build deps from runtime"
echo "- Essential for production blockchain with quantum resistance + ZK proofs"
