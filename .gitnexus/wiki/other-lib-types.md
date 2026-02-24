# Other — lib-types

# lib-types Module Documentation

## Overview

The `lib-types` module provides foundational data structures and types for the Sovereign Network. It is designed to be protocol-neutral and free of runtime behavior, focusing solely on defining data shapes that can be utilized across various components of the network. This module is essential for ensuring that the data types used in the network are consistent and stable.

### Key Features
- **Protocol-Neutral Data Shapes**: The types defined in this module are agnostic to any specific protocol, making them reusable across different contexts.
- **Stability Contract**: The module adheres to a strict stability contract, ensuring that certain aspects of the data types remain unchanged across versions.
- **Minimal Dependencies**: The module relies only on a few external crates (`serde`, `blake3`, and `hex`), which simplifies maintenance and reduces potential conflicts.

## Non-Goals

The `lib-types` module explicitly avoids:
- Asynchronous programming and dependencies on frameworks like Tokio.
- Networking, storage, or logging functionalities.
- Feature flags or internal crate dependencies.
- Any behavior or policy logic; such logic should reside in other parts of the codebase.

## Crate Layout

The module is organized into several files and directories, each serving a specific purpose:

```
lib-types/
└── src/
    ├── lib.rs          # Main library entry point
    ├── node_id.rs      # Definitions related to Node IDs
    ├── dht/            # Distributed Hash Table related types and messages
    │   ├── mod.rs      # Module entry for DHT
    │   ├── types.rs    # DHT-specific types
    │   ├── message.rs   # DHT message structures
    │   └── transport.rs # DHT transport layer definitions
    ├── chunk.rs        # Definitions related to data chunks
    └── errors.rs       # Error handling types
```

## Key Components

### 1. NodeId

The `node_id.rs` file defines the `NodeId` type, which uniquely identifies nodes in the network. The binary layout of `NodeId` is guaranteed to remain stable, ensuring compatibility across different versions of the module.

### 2. ChunkId

Similar to `NodeId`, the `ChunkId` type is defined in `chunk.rs`. It represents unique identifiers for data chunks within the network. The stability of its binary layout is also guaranteed.

### 3. DHT Module

The `dht` directory contains several files that define types and messages used in the Distributed Hash Table (DHT) implementation:
- **types.rs**: Contains various types used within the DHT context.
- **message.rs**: Defines the structure of messages exchanged between nodes in the DHT.
- **transport.rs**: Contains definitions related to the transport layer of DHT communications.

### 4. Error Handling

The `errors.rs` file defines custom error types that can be used throughout the module. This allows for consistent error handling and reporting.

## Stability Contract

The module follows a strict stability contract:
- The binary layout of `NodeId` and `ChunkId` must not change.
- Serialized field names and enum variants are stable.
- New enums, structs, or modules can be added without breaking changes.
- Any changes to existing struct fields, enum variants, or serialization behavior will require a major version bump (v1.0).

## Usage

To use the types defined in the `lib-types` module, simply include it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
lib-types = { version = "0.1.0" }
```

You can then import the necessary types in your Rust files:

```rust
use lib_types::NodeId;
use lib_types::ChunkId;
```

## Conclusion

The `lib-types` module serves as a critical foundation for the Sovereign Network, providing stable and protocol-neutral data types. Its design principles ensure that it remains lightweight and focused solely on data representation, making it a reliable choice for developers working on the network's infrastructure. 

For further contributions or modifications, please adhere to the stability contract and dependency policy outlined in this documentation.