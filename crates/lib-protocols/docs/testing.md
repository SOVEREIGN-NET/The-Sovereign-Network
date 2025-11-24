# Testing Module

This module provides comprehensive testing utilities for ZHTP protocol components, including mock implementations, test fixtures, and integration test helpers.

## Main Types
- `MockZhtpServer`: Mock server for testing with recorded requests and predefined responses.
- `TestConfig`: Configures mock blockchain, economics, storage, mesh, and timeouts.
- `TestStats`: Tracks test statistics for requests, responses, and performance.

## Key Features
- Mock implementations for blockchain, economics, storage, and mesh
- Request recording and response mocking
- Test fixtures and integration test helpers
- Configurable timeouts and test modes

## Example Usage
```rust
let mut server = MockZhtpServer::new(TestConfig::default());
server.add_response("GET /test", mock_response);
let response = server.process_request(request).await?;
```
