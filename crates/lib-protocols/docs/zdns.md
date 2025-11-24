# ZDNS Module

This module implements ZDNS (Zero Knowledge Domain Name System), a DNS replacement for Web4 that provides decentralized domain name resolution with zero-knowledge proofs, ownership verification, and post-quantum security.

## Main Types
- `ZdnsServer`: Main ZDNS server with routing and resolution.
- `ZdnsRecord`: Domain records with ZK ownership proofs, post-quantum signatures, and DAO fee proofs.
- `ZdnsRecordType`: Comprehensive record types (A, AAAA, CNAME, MX, TXT, SRV, MESH, ZK, DAO, ECON, ID, CONTENT, MULTISIG, PQS, WEB4, etc.).
- `ZdnsQuery` / `ZdnsResponse`: Query and response types for ZDNS resolution.

## Key Features
- Censorship-resistant domain resolution
- Zero-knowledge ownership proofs (no private key revelation)
- Post-quantum security (CRYSTALS-Dilithium signatures)
- Economic incentives for domain hosting
- .zhtp domains and Web4 addressing
-  through mesh routing
- DAO governance records and economic records

## Example Usage
```rust
let server = ZdnsServer::new(ZdnsConfig::default());
let query = ZdnsQuery::new("example.zhtp", ZdnsRecordType::A);
let response = server.resolve(query).await?;
```
