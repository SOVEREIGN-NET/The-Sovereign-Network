# Sovereign Network Protocols Library (`lib-protocols`)

**Complete Web4 Protocol Stack - Internet Replacement**

This documentation provides comprehensive coverage of the `lib-protocols` library, which implements ZHTP (Zero Knowledge Hypertext Transfer Protocol) and ZDNS (Zero Knowledge Domain Name System) - the foundation of Web4.

## 📚 Documentation Structure

- **[OVERVIEW](./OVERVIEW.md)** - Complete architecture and design philosophy
- **Module Documentation** - Detailed docs for each component

## 🏗️ Core Protocol Modules

### Protocol Stack
- **[types](./types.md)**: Core protocol types - requests, responses, headers, status codes
- **[zhtp](./zhtp.md)**: ZHTP server, routing, content management, sessions
- **[zdns](./zdns.md)**: Zero-knowledge DNS with ownership proofs
- **[handlers](./handlers.md)**: Request handlers for all ZHTP methods
- **[validation](./validation.md)**: Protocol validation, ZK proofs, rate limiting

### Integration Layer
- **[integration](./integration.md)**: Unified system orchestrating all components
- **[crypto](./crypto.md)**: Cryptographic operations and ZK proof validation
- **[economics](./economics.md)**: Economic models, fee calculation, DAO integration
- **[storage](./storage.md)**: Distributed storage integration with lib-storage
- **[identity](./identity.md)**: Identity management with ZK-DID support
- **[secure_transfer](./secure_transfer.md)**: Secure wallet transfers with signature verification

### Utilities
- **[testing](./testing.md)**: Mock implementations and test utilities

##  Quick Start

See [OVERVIEW.md](./OVERVIEW.md) for complete examples and getting started guide.

##  Key Features

- **ZHTP v1.0**: HTTP replacement with built-in economics and privacy
- **ZDNS v1.0**: Censorship-resistant domain resolution
- **Post-Quantum Security**: CRYSTALS-Dilithium, CRYSTALS-Kyber
- **Zero-Knowledge Proofs**: Privacy-preserving validation
- **Economic Incentives**: 2% DAO fees for UBI funding
- ****: Complete mesh networking capability

## 📖 Documentation Resources

### Getting Started
1. **[OVERVIEW](./OVERVIEW.md)** - Architecture, design philosophy, and quick start
2. **[API_REFERENCE](./API_REFERENCE.md)** - Complete API documentation with method signatures
3. **[EXAMPLES](./EXAMPLES.md)** - Practical code examples for common use cases

### Module Documentation
Each module is documented with:
- Purpose and scope
- Key types and structures
- Feature highlights
- Usage examples

## 💡 Learning Path

**For New Users:**
1. Read [OVERVIEW.md](./OVERVIEW.md) to understand the architecture
2. Review [EXAMPLES.md](./EXAMPLES.md) for practical usage patterns
3. Explore individual module docs as needed

**For API Integration:**
1. Check [API_REFERENCE.md](./API_REFERENCE.md) for function signatures
2. Review [types.md](./types.md) for data structures
3. See [integration.md](./integration.md) for system-wide usage

**For Protocol Development:**
1. Study [zhtp.md](./zhtp.md) and [zdns.md](./zdns.md)
2. Review [crypto.md](./crypto.md) and [validation.md](./validation.md)
3. Understand [economics.md](./economics.md) for fee models
