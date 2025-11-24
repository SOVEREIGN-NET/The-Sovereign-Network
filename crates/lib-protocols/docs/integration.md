# Integration Module

This module provides integration utilities to coordinate and orchestrate interactions between all ZHTP protocol components, external packages, and third-party systems.

## Main Types
- `ZhtpIntegration`: Unified system with config, crypto, economics, storage, and identity.
- `IntegrationConfig`: Configures node ID, blockchain, identity, consensus, mesh, and monitoring.

## Key Features
- Unified initialization of all protocol components
- End-to-end request processing through all systems
- Integration statistics and monitoring

## Example Usage
```rust
let integration = ZhtpIntegration::new(IntegrationConfig::default()).await?;
let response = integration.process_integrated_request(request).await?;
```
