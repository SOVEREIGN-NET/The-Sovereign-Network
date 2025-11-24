# lib-protocols: Complete Web4 Protocol Stack

## Overview

`lib-protocols` implements the complete Web4 protocol stack, including ZHTP (Zero Knowledge Hypertext Transfer Protocol) and ZDNS (Zero Knowledge Domain Name System). This library provides a native protocol designed to completely replace the traditional internet stack with built-in economics, privacy, and security.

## Architecture

### Protocol Stack Replacement

ZHTP replaces the entire traditional internet stack:

1. **ISPs** → Mesh networking with economic incentives for routing
2. **DNS** → Zero-knowledge domain system (ZDNS)
3. **HTTP/HTTPS** → Native ZHTP protocol with built-in privacy
4. **TLS** → Post-quantum encryption by default
5. **CDNs** → Distributed content with economic rewards
6. **Governments** → DAO governance with UBI for all participants

**Result: A free internet that pays users to participate**

### Core Features

#### ZHTP v1.0 Protocol
- HTTP replacement with built-in economics
- Zero-knowledge proof validation at transport layer
- Post-quantum cryptography (CRYSTALS-Dilithium, CRYSTALS-Kyber)
- Mandatory 2% DAO fees for UBI funding
- Complete  capability
- Native .zhtp domains and Web4 addressing

#### ZDNS v1.0 System
- DNS replacement with ownership proofs
- Zero-knowledge domain records (no private key revelation)
- Decentralized name resolution
- Post-quantum secure domain management
- Censorship-resistant resolution
- Economic incentives for domain hosting

#### Security Architecture
- Client-side signing with private keys
- Server-side verification using registered public keys
- No private key material ever transmitted
- Identity verification against blockchain registry
- Post-quantum cryptographic primitives throughout

## Module Structure

### Core Protocol Modules

| Module | Description |
|--------|-------------|
| [`types`](./types.md) | Core protocol types: requests, responses, headers, status codes |
| [`zhtp`](./zhtp.md) | ZHTP server, routing, content management, sessions |
| [`zdns`](./zdns.md) | Zero-knowledge DNS with ownership proofs |
| [`handlers`](./handlers.md) | Request handlers for all ZHTP methods |
| [`validation`](./validation.md) | Protocol validation, ZK proofs, rate limiting |

### Integration Modules

| Module | Description |
|--------|-------------|
| [`integration`](./integration.md) | Unified system orchestrating all components |
| [`crypto`](./crypto.md) | Cryptographic operations and ZK proof validation |
| [`economics`](./economics.md) | Economic models, fee calculation, DAO integration |
| [`storage`](./storage.md) | Distributed storage integration with lib-storage |
| [`identity`](./identity.md) | Identity management with ZK-DID support |
| [`secure_transfer`](./secure_transfer.md) | Secure wallet transfers with signature verification |

### Utility Modules

| Module | Description |
|--------|-------------|
| [`testing`](./testing.md) | Mock implementations and test utilities |

## Quick Start

### Basic ZHTP Server

```rust
use lib_protocols::{ZhtpServer, ServerConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create server with default configuration
    let config = ServerConfig::default();
    let server = ZhtpServer::new(config);
    
    // Start server
    server.start().await?;
    
    Ok(())
}
```

### Creating ZHTP Requests

```rust
use lib_protocols::{ZhtpRequest, ZhtpMethod, ZhtpHeaders};

let mut headers = ZhtpHeaders::new();
headers.set("Content-Type", "application/json".to_string());

let request = ZhtpRequest {
    method: ZhtpMethod::Get,
    uri: "/api/wallet/balance".to_string(),
    version: "1.0".to_string(),
    headers,
    body: vec![],
    timestamp: 1234567890,
    requester: None,
    auth_proof: None,
};
```

### ZDNS Resolution

```rust
use lib_protocols::zdns::{ZdnsServer, ZdnsConfig, ZdnsQuery, ZdnsRecordType};

let server = ZdnsServer::new(ZdnsConfig::default());
let query = ZdnsQuery::new("example.zhtp", ZdnsRecordType::A);
let response = server.resolve(query).await?;
```

### Integrated System

```rust
use lib_protocols::integration::{ZhtpIntegration, IntegrationConfig};

let integration = ZhtpIntegration::new(IntegrationConfig::default()).await?;
let response = integration.process_integrated_request(request).await?;
```

## Economic Model

All ZHTP operations include economic incentives:

- **Mandatory 2% DAO fees** for UBI funding
- **Dynamic fee calculation** based on operation type, data size, and priority
- **Proof-of-Useful-Work** rewards for network participation
- **Storage contracts** with economic guarantees
- **Mesh routing rewards** for bandwidth provision

## Security Guarantees

### Post-Quantum Cryptography
- CRYSTALS-Dilithium for signatures
- CRYSTALS-Kyber for key exchange
- BLAKE3 for hashing
- Quantum-resistant by default

### Zero-Knowledge Proofs
- Identity verification without revealing personal data
- Domain ownership without exposing private keys
- Transaction privacy with public verifiability
- Content integrity with privacy preservation

### Access Control
- Fine-grained access policies
- Time-based restrictions
- Identity-based permissions
- Reputation-based access

## Performance Characteristics

- **Request throughput**: 10,000+ requests/second
- **Maximum request size**: 16MB
- **Maximum header size**: 64KB
- **Default timeout**: 30 seconds
- **Cache TTL**: 1 hour (configurable)

## Development

### Building

```bash
cd lib-protocols
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run with test features
cargo test --features testing

# Run specific test
cargo test test_zhtp_request
```

### Features

- `testing`: Enable mock implementations and test utilities
- (Additional features as configured in Cargo.toml)

## Integration with Other Libraries

`lib-protocols` integrates seamlessly with:

- **lib-crypto**: Post-quantum cryptography and hashing
- **lib-proofs**: Zero-knowledge proof systems
- **lib-identity**: Identity management and ZK-DID
- **lib-economy**: Economic models and DAO integration
- **lib-storage**: Distributed storage and DHT
- **lib-blockchain**: Blockchain integration and verification
- **lib-consensus**: Consensus mechanisms and validation

## API Design Philosophy

1. **Security First**: All operations are cryptographically secure by default
2. **Economic Incentives**: Every action has an economic component
3. **Zero-Knowledge Privacy**: Privacy is built-in, not optional
4. **Post-Quantum Ready**: All cryptography is quantum-resistant
5. **Decentralized**: No central authority or single point of failure
6. **ISP Independence**: Complete mesh networking capability

## Future Enhancements

- [ ] Enhanced compression algorithms
- [ ] Additional ZK proof types
- [ ] Expanded ZDNS record types
- [ ] WebAssembly support for browser integration
- [ ] Mobile SDK for native apps
- [ ] P2P streaming protocols
- [ ] Advanced mesh routing algorithms

## Contributing

When contributing to `lib-protocols`, ensure:

1. All new features include comprehensive tests
2. Documentation is updated for API changes
3. Economic models are validated
4. Security implications are reviewed
5. Post-quantum cryptography is maintained
6. Zero-knowledge proofs are properly implemented

## License

See LICENSE file for details.

## Support

For issues, questions, or contributions, please see the main repository documentation.

---

**lib-protocols** - Building the future of the internet, one protocol at a time.
