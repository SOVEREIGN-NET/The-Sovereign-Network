# Secure Transfer Module

This module implements secure wallet transfer handling, ensuring client-side signing and server-side verification for all transactions.

## Main Types
- `SecureWalletTransferHandler`: Handles secure transfer requests and signature verification.
- `SecureTransferRequest` / `SecureTransferResponse`: Request/response types for wallet transfers.
- `VerificationDetails`: Details about identity, key, and signature verification.

## Key Features
- Client-side signing, server-side verification
- Blockchain-based identity verification
- No private keys ever transmitted to the server

## Example Usage
```rust
let handler = SecureWalletTransferHandler::new();
// Use handler to process secure wallet transfers
```
