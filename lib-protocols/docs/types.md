# Types Module

This module contains all the fundamental types used across the ZHTP protocol stack, including request/response types, status codes, headers, and content structures.

## Submodules
- `status`: ZHTP status codes (Ok, NotFound, Forbidden, etc.)
- `method`: ZHTP methods (Get, Post, Put, Delete, Head, Options, Verify, etc.)
- `headers`: ZHTP header management
- `request`: `ZhtpRequest` type
- `response`: `ZhtpResponse` type
- `access_policy`: Access control policies and time restrictions
- `content`: Content metadata, encryption, compression, chunking, replication
- `economic`: Economic assessment types

## Key Constants
- `ZHTP_VERSION`: "1.0"
- `ZDNS_VERSION`: "1.0"
- `MAX_REQUEST_SIZE`: 16MB
- `MAX_HEADER_SIZE`: 64KB
- `DEFAULT_REQUEST_TIMEOUT`: 30 seconds
- `MIN_DAO_FEE`: 5 SOV tokens
- `DAO_FEE_PERCENTAGE`: 2.00% (200 basis points)

## Core Types
- `ZhtpRequest`: Request with method, URI, headers, body, timestamp, requester, auth proof
- `ZhtpResponse`: Response with status, headers, body, timestamp, server, validity proof
- `ZhtpStatus`: Status codes for protocol responses
- `ZhtpMethod`: Protocol methods (Get, Post, Put, Delete, etc.)
- `ZhtpHeaders`: Header key-value store
- `AccessPolicy`: Access control with allowed identities, time restrictions
- `ContentMetadata`: Content description with size, MIME type, encoding, tags
- `EconomicAssessment`: Fee breakdown for operations

## Example Usage
```rust
use lib_protocols::types::{ZhtpRequest, ZhtpMethod, ZhtpHeaders};

let mut headers = ZhtpHeaders::new();
headers.set("Content-Type", "application/json".to_string());

let request = ZhtpRequest {
    method: ZhtpMethod::Get,
    uri: "/api/test".to_string(),
    version: "1.0".to_string(),
    headers,
    body: vec![],
    timestamp: 1234567890,
    requester: None,
    auth_proof: None,
};
```
