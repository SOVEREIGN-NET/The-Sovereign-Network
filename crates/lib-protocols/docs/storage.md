# Storage Module

This module provides integration with the `lib-storage` package for distributed content management, economic storage, DHT networking, and identity migration.

## Main Types
- `StorageIntegration`: Integrates with `UnifiedStorageSystem` from `lib-storage`.
- `StorageConfig`: Configures distributed storage, replication, pricing, and encryption.
- `StorageContract`: Represents storage agreements with providers, duration, cost, and status.

## Key Features
- Distributed storage with configurable replication
- Economic storage contracts with pricing per GB per day
- Content caching for faster access
- Integration with lib-storage DHT and economic models

## Example Usage
```rust
let storage = StorageIntegration::new(StorageConfig::default()).await?;
// Use storage for distributed content management
```
