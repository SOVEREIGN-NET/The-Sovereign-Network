# Other — sdk-ts

# @zhtp/sdk - TypeScript SDK for ZHTP/Web4 Protocol

## Overview

The `@zhtp/sdk` module is a TypeScript SDK designed for the ZHTP (Zero-Trust Hypertext Transport Protocol) network, utilizing QUIC as its transport layer. This SDK is built for Node.js environments (v18+) and is intended for server-side applications and CI/CD pipelines. It provides a structured way to interact with the ZHTP network, focusing on identity management, trust configuration, and authenticated client connections.

## Purpose

The SDK aims to facilitate the development of decentralized applications (dApps) on the ZHTP network by providing:

- A QUIC-native communication layer.
- A robust identity management system.
- A framework for building trust configurations.
- An interface for deploying applications and managing domains.

## Architecture

The SDK follows a three-layer initialization pattern, which is crucial for establishing a secure and authenticated client connection. The architecture is designed to be modular, allowing for easy extension and maintenance.

### Three-Layer Initialization Pattern

```mermaid
graph TD;
    A[Load Identity] -->|loadIdentityFromKeystore()| B[LoadedIdentity];
    B --> C[Build Trust Configuration];
    C -->|buildTrustConfig()| D[TrustConfig];
    D --> E[Create Authenticated Client];
    E -->|connectClient()| F[ZhtpClient];
    F --> G[Use Client];
```

### Key Components

1. **Identity Management** (`identity.ts`)
   - **Function**: `loadIdentityFromKeystore()`
   - **Purpose**: Loads user identity from a keystore, returning a `LoadedIdentity` object that contains the identity's DID and key pairs.

2. **Trust Configuration** (`client.ts`)
   - **Function**: `buildTrustConfig()`
   - **Purpose**: Constructs a trust configuration object that defines how the client should authenticate with the ZHTP network.

3. **Client Connection** (`client.ts`)
   - **Function**: `connectClient()`
   - **Purpose**: Establishes a connection to the ZHTP server using the loaded identity and trust configuration, returning an authenticated `ZhtpClient`.

4. **Domain Management** (`managers/domain.ts`)
   - **Function**: `register()`, `lookup()`, `transfer()`
   - **Purpose**: Provides methods for managing domains on the ZHTP network.

5. **Wallet Management** (`managers/wallet.ts`)
   - **Function**: `send()`, `stake()`, `history()`
   - **Purpose**: Facilitates wallet operations such as sending tokens and checking transaction history.

6. **Deployment Management** (`managers/deploy.ts`)
   - **Function**: `deploySite()`
   - **Purpose**: Handles the deployment of dApps to the ZHTP network.

### Error Handling

The SDK employs domain-specific error types defined in `error.ts`, which provide context for debugging. Errors are designed to carry meaningful messages that help developers understand the issues encountered during operations.

### Validation Functions

Validation functions are implemented as pure functions in `validation.ts`, ensuring that they do not have side effects. These functions validate inputs such as domain names and wallet addresses, returning structured results that indicate validity and any associated errors.

## Usage Example

### Initializing the Client

To initialize the client, follow these steps:

```typescript
import {
  loadIdentityFromKeystore,
  buildTrustConfig,
  connectClient,
} from '@zhtp/sdk';

async function initializeZhtpClient() {
  // Load identity from keystore
  const loaded = await loadIdentityFromKeystore('~/.zhtp/keystore');

  // Build trust configuration
  const trustConfig = buildTrustConfig({
    mode: 'bootstrap',
  });

  // Connect to ZHTP server
  const client = await connectClient(loaded.identity, trustConfig, 'quic://node.zhtp:5555');

  return client;
}
```

### Deploying a dApp

Once the client is initialized, you can deploy a dApp as follows:

```typescript
const client = await initializeZhtpClient();
const result = await client.deploy.deploySite({
  domain: 'myapp.zhtp',
  buildDir: '/path/to/build',
  mode: 'spa',
  indexFile: 'index.html',
  exclude: ['.txt', '__next.'],
});
console.log('Deployment complete:', result);
```

## Development Roadmap

The SDK is currently in **Alpha** stage, with the following phases planned:

- **Phase 1**: Foundation (Complete)
- **Phase 2**: QUIC Transport (In Progress)
- **Phase 3**: Managers (Upcoming)
- **Phase 4**: Examples & Testing (Upcoming)

## Security Considerations

The SDK is designed with security in mind, incorporating:

- **Post-Quantum Cryptography**: Utilizes UHP v2 with Kyber1024 and Dilithium5 for key agreement and signatures.
- **Signed Requests**: All mutations are signed using Dilithium5 key pairs.
- **Replay Protection**: Sequence numbers are used to prevent replay attacks.

## Conclusion

The `@zhtp/sdk` module provides a comprehensive framework for interacting with the ZHTP network, focusing on security, modularity, and ease of use. As the SDK evolves, it will continue to support the development of decentralized applications, making it easier for developers to build on the ZHTP protocol.

## Resources

- [ZHTP Network](https://github.com/SOVEREIGN-NET/The-Sovereign-Network)
- [zhtp-cli](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/zhtp-cli)
- [lib-network](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/lib-network)
- [lib-protocols](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/tree/development/lib-protocols)

## Contributing

For guidelines on contributing to the SDK, please refer to the `CONTRIBUTING.md` file in the repository.