# Obsidian Mail - Required API Endpoints

## Overview
This document specifies the HTTP API endpoints required for the Obsidian Mail project - a quantum-resistant, zero-knowledge private email system built on Sovereign Network.

**Branch:** `feat/obsidian-mail-api-endpoints`

---

## Current Status

### ✅ Existing Endpoints (Already Working)
1. `GET /api/status` - Node status
2. `GET /api/resolve` - DNS resolution
3. `GET /api/peer-availability` - Peer status
4. `POST /api/message` - Send message

### ❌ Missing Endpoints (Need to Add)

---

## 1. DNS Registration

### `POST /api/dns/register`
**Purpose:** Register .zhtp domain names for email addresses (e.g., username@domain.zhtp)

**Request:**
```json
{
  "domain": "alice.zhtp",
  "owner_public_key": "Kv9QjekWd+X45/cVWcttrxDEHTIIv0Dd4S0k...",
  "owner_secret_key": "SECRET_BASE64...",
  "addresses": ["127.0.0.1:7000"],
  "content_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

**Response:**
```json
{
  "success": true,
  "domain": "alice.zhtp",
  "message": "Domain registered successfully",
  "ownership_proof": "ZK_PROOF_DATA..."
}
```

**Implementation Notes:**
- Use existing `dns_service.register_domain()` from `src/zhtp/dns.rs:168`
- Convert Base64 keys to Keypair
- Generate ownership ZK proof
- Store in DNS registry

---

## 2. Cryptography Endpoints

### `POST /api/crypto/generate-keypair`
**Purpose:** Generate new quantum-resistant keypair for users

**Request:**
```json
{
  "algorithm": "dilithium5+kyber768"
}
```

**Response:**
```json
{
  "success": true,
  "address": "zh1ee65a89138340b4a0ac607b33304cdbc5e48729",
  "dilithium_public_key": "BASE64...",
  "dilithium_secret_key": "BASE64...",
  "kyber_public_key": "BASE64...",
  "kyber_secret_key": "BASE64...",
  "created_at": 1761295590,
  "rotation_due": 1761381990
}
```

**Implementation Notes:**
- Use `Keypair::generate()` from `src/zhtp/crypto.rs`
- Use `keypair.export_unencrypted()` to get Base64 keys
- Calculate address from public key hash (SHA256)

---

### `POST /api/crypto/encrypt`
**Purpose:** Encrypt data using Kyber768 (for email encryption)

**Request:**
```json
{
  "plaintext": "BASE64_ENCODED_DATA",
  "recipient_public_key": "KYBER_PUBLIC_KEY_BASE64"
}
```

**Response:**
```json
{
  "success": true,
  "ciphertext": "BASE64_ENCRYPTED_DATA",
  "kyber_ciphertext": "BASE64_ENCAPSULATED_KEY",
  "algorithm": "kyber768"
}
```

**Implementation Notes:**
- Use Kyber encapsulation from `src/zhtp/crypto.rs`
- Encrypt with shared secret
- Return both ciphertext and encapsulated key

---

### `POST /api/crypto/decrypt`
**Purpose:** Decrypt data using Kyber768 secret key

**Request:**
```json
{
  "ciphertext": "BASE64_ENCRYPTED_DATA",
  "kyber_ciphertext": "BASE64_ENCAPSULATED_KEY",
  "kyber_secret_key": "BASE64_SECRET_KEY"
}
```

**Response:**
```json
{
  "success": true,
  "plaintext": "BASE64_DECRYPTED_DATA"
}
```

**Implementation Notes:**
- Use Kyber decapsulation
- Decrypt with shared secret
- Return plaintext

---

## 3. Zero-Knowledge Proof Endpoints

### `POST /api/zk/generate-proof`
**Purpose:** Generate ZK proof for metadata privacy (hide sender, receiver, timestamp)

**Request:**
```json
{
  "proof_type": "metadata_privacy",
  "public_inputs": [1, 2, 3],
  "private_witness": [4, 5, 6],
  "circuit": "email_metadata"
}
```

**Response:**
```json
{
  "success": true,
  "proof": "ZK_PROOF_DATA_BASE64",
  "public_inputs": [1, 2, 3],
  "verification_key": "VK_BASE64"
}
```

**Implementation Notes:**
- Use existing ZK proof system from `src/zhtp/zk_proofs.rs`
- Support metadata privacy circuit
- Return proof for verification

---

### `POST /api/zk/verify-proof`
**Purpose:** Verify ZK proof

**Request:**
```json
{
  "proof": "ZK_PROOF_DATA_BASE64",
  "public_inputs": [1, 2, 3],
  "verification_key": "VK_BASE64"
}
```

**Response:**
```json
{
  "success": true,
  "valid": true
}
```

**Implementation Notes:**
- Use proof verification from `src/zhtp/zk_proofs.rs`
- Return validation result

---

## 4. Wallet Endpoints

### `POST /api/wallet/create`
**Purpose:** Create new wallet (wrapper around generate-keypair with additional wallet info)

**Request:**
```json
{
  "network": "local-testnet"
}
```

**Response:**
```json
{
  "success": true,
  "wallet_address": "zh1ee65a89138340b4a0ac607b33304cdbc5e48729",
  "public_key": "DILITHIUM_PUBLIC_KEY_BASE64",
  "secret_key": "DILITHIUM_SECRET_KEY_BASE64",
  "balance": 0,
  "network": "local-testnet",
  "quantum_resistant": true,
  "algorithm": "Dilithium5+Kyber768"
}
```

**Implementation Notes:**
- Same as generate-keypair but with wallet metadata
- Initialize balance to 0
- Add to account state (if wallet balance system exists)

---

### `GET /api/wallet/balance?address=zh1...`
**Purpose:** Get wallet balance

**Request:** Query parameter: `address=zh1ee65a89138340b4a0ac607b33304cdbc5e48729`

**Response:**
```json
{
  "success": true,
  "address": "zh1ee65a89138340b4a0ac607b33304cdbc5e48729",
  "balance": 1000,
  "currency": "ZHTP"
}
```

**Implementation Notes:**
- **Note:** Wallet balance system doesn't exist yet in backend
- For now, return mock balance of 0
- TODO: Implement account state storage later

---

## 5. DApp Endpoints (Optional - for browser interface)

### `GET /api/dapps`
**Purpose:** List deployed DApps

**Response:**
```json
{
  "success": true,
  "dapps": [
    {
      "name": "DAO Governance",
      "address": "dao.zhtp",
      "description": "Decentralized governance",
      "deployed_at": 1761295590
    }
  ]
}
```

---

### `GET /api/network/activity`
**Purpose:** Real-time network activity feed

**Response:**
```json
{
  "success": true,
  "activities": [
    {
      "type": "transaction",
      "timestamp": 1761295590,
      "description": "ZK proof verified"
    },
    {
      "type": "domain_registration",
      "timestamp": 1761295585,
      "domain": "alice.zhtp"
    }
  ]
}
```

---

## Implementation Priority

### Phase 1: Critical for Obsidian Mail (Do First)
1. ✅ `POST /api/crypto/generate-keypair` - Identity generation
2. ✅ `POST /api/dns/register` - Email address registration
3. ✅ `POST /api/crypto/encrypt` - Email encryption
4. ✅ `POST /api/crypto/decrypt` - Email decryption

### Phase 2: Privacy Features
5. ✅ `POST /api/zk/generate-proof` - Metadata privacy
6. ✅ `POST /api/zk/verify-proof` - Proof verification

### Phase 3: Wallet Integration
7. ✅ `POST /api/wallet/create` - Wallet creation
8. ✅ `GET /api/wallet/balance` - Balance checking

### Phase 4: Browser UI Support (Optional)
9. ⚠️ `GET /api/dapps` - DApp listing
10. ⚠️ `GET /api/network/activity` - Activity feed

---

## Testing Plan

After implementing each endpoint, test with curl:

```bash
# Generate keypair
curl -X POST http://localhost:8001/api/crypto/generate-keypair \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "dilithium5+kyber768"}'

# Register domain
curl -X POST http://localhost:8001/api/dns/register \
  -H "Content-Type: application/json" \
  -d '{"domain": "alice.zhtp", "owner_public_key": "...", ...}'

# Encrypt data
curl -X POST http://localhost:8001/api/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "SGVsbG8gV29ybGQ=", "recipient_public_key": "..."}'

# Decrypt data
curl -X POST http://localhost:8001/api/crypto/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "...", "kyber_ciphertext": "...", "kyber_secret_key": "..."}'
```

---

## File Modifications Required

**Main file:** `src/network_service.rs`
- Add new endpoint handlers in the HTTP request router (around line 654)
- Add helper functions for each endpoint
- Import necessary modules (crypto, dns, zk_proofs)

**Example structure:**
```rust
// In src/network_service.rs, add to match statement:

("POST", "/api/crypto/generate-keypair") => {
    handle_generate_keypair(request).await
}

("POST", "/api/dns/register") => {
    handle_dns_register(request, dns_service).await
}

// ... etc
```

---

## Security Considerations

1. **Private Keys in Responses:**
   - ⚠️ Returning secret keys in HTTP responses is INSECURE
   - For production: Use session management, never return secret keys
   - For development/testing: OK for now, add warnings

2. **Input Validation:**
   - Validate all Base64 inputs
   - Validate domain name formats
   - Validate key sizes

3. **Rate Limiting:**
   - TODO: Add rate limiting to prevent abuse
   - Especially for expensive operations (ZK proofs, encryption)

4. **CORS:**
   - Already enabled with `Access-Control-Allow-Origin: *`
   - OK for local development

---

## Estimated Implementation Time

- **Phase 1 (Critical):** 4-6 hours
- **Phase 2 (Privacy):** 2-3 hours
- **Phase 3 (Wallet):** 1-2 hours
- **Phase 4 (Optional):** 2-3 hours

**Total:** 9-14 hours for all phases

---

## Success Criteria

✅ All Phase 1-3 endpoints implemented
✅ All endpoints tested with curl
✅ Browser interface can:
  - Generate identity
  - Register email address (username@domain.zhtp)
  - Encrypt/decrypt messages
  - Generate ZK proofs for metadata privacy

---

## Next Steps

1. Mark first task as in_progress
2. Implement `POST /api/crypto/generate-keypair`
3. Test with curl
4. Commit and move to next endpoint
5. Repeat until all critical endpoints done
