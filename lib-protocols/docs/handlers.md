# Handlers Module

This module implements core ZHTP request handlers for all protocol methods (GET, POST, PUT, DELETE, etc.), with support for zero-knowledge proof validation, economic fee processing, and post-quantum cryptographic security.

## Main Types
- `ZhtpHandlers`: Main handler struct, manages content, config, cache, and stats.
- `HandlerConfig`: Configures caching, compression, validation, and test mode.
- `StoredContent`: Represents stored content with metadata, permissions, and proofs.

## Key Features
- Request caching and compression
- Content validation and access control
- Zero-knowledge proof and economic validation
- Handler statistics and request cache

## Example Usage
```rust
let handlers = ZhtpHandlers::new(...);
// Use handlers to process ZHTP requests
```
