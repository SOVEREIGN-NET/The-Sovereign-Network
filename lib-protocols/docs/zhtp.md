# ZHTP Module

This module implements the ZHTP v1.0 Protocol Core, a complete replacement for HTTP with built-in economic incentives, zero-knowledge privacy, and post-quantum security.

## Submodules
- `server`: ZHTP server implementation with state management
- `config`: Server configuration types
- `access_control`: Access controller for request authorization
- `routing`: Router with routes and route handlers
- `content`: Content manager with storage backends, compression, and encryption
- `middleware`: Middleware trait and implementations
- `session`: Session manager with auth methods and security levels

## Key Constants
- `ZHTP_VERSION`: "1.0"
- `DEFAULT_ZHTP_PORT`: 9333
- `MAX_REQUEST_SIZE`: 16MB
- `DEFAULT_REQUEST_TIMEOUT`: 30 seconds

## Core Traits
- `ZhtpRequestHandler`: Trait for handling ZHTP requests
- `ZhtpMiddleware`: Trait for request/response middleware
- `ZhtpServerEvents`: Trait for server lifecycle events

## Core Types
- `ZhtpServer`: Main server with routing, handlers, and state
- `ServerConfig`: Server configuration (port, TLS, workers, etc.)
- `ServerCapabilities`: Server feature support advertisement
- `AccessController`: Access control and authorization
- `Router`: Route registration and dispatch
- `ContentManager`: Content storage and delivery
- `SessionManager`: Session authentication and security

## Example Usage
```rust
use lib_protocols::zhtp::{ZhtpServer, ServerConfig};

let config = ServerConfig::default();
let server = ZhtpServer::new(config);
// server.start().await?;
```
