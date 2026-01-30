# Token API and CLI Implementation Plan

## Overview

Implement complete token management API endpoints and CLI commands for custom token creation, minting, and transfer operations.

---

## Phase 1: API Endpoints (zhtp/src/api/handlers/token/)

### Endpoints to Implement

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/token/create` | Deploy new custom token |
| `POST` | `/api/v1/token/mint` | Mint tokens (creator only) |
| `POST` | `/api/v1/token/transfer` | Transfer tokens |
| `GET` | `/api/v1/token/{id}` | Get token info |
| `GET` | `/api/v1/token/{id}/balance/{address}` | Get balance |
| `GET` | `/api/v1/token/list` | List all tokens |

### Request/Response Structures

#### POST /api/v1/token/create
```json
// Request
{
  "name": "MyToken",
  "symbol": "MTK",
  "initial_supply": 1000000,
  "decimals": 8,
  "max_supply": null,  // optional, defaults to unlimited
  "creator_identity": "did:zhtp:abc123..."
}

// Response
{
  "token_id": "0x...",
  "name": "MyToken",
  "symbol": "MTK",
  "total_supply": 1000000,
  "creator": "did:zhtp:abc123...",
  "tx_hash": "0x..."
}
```

#### POST /api/v1/token/mint
```json
// Request
{
  "token_id": "0x...",
  "amount": 5000,
  "to": "did:zhtp:recipient...",
  "creator_identity": "did:zhtp:abc123..."  // must be token creator
}

// Response
{
  "success": true,
  "new_total_supply": 1005000,
  "tx_hash": "0x..."
}
```

#### POST /api/v1/token/transfer
```json
// Request
{
  "token_id": "0x...",
  "from": "did:zhtp:sender...",
  "to": "did:zhtp:recipient...",
  "amount": 100
}

// Response
{
  "success": true,
  "tx_hash": "0x...",
  "from_balance": 900,
  "to_balance": 100
}
```

#### GET /api/v1/token/{id}
```json
// Response
{
  "token_id": "0x...",
  "name": "MyToken",
  "symbol": "MTK",
  "decimals": 8,
  "total_supply": 1000000,
  "max_supply": null,
  "creator": "did:zhtp:abc123...",
  "is_deflationary": false,
  "created_at_block": 15
}
```

#### GET /api/v1/token/{id}/balance/{address}
```json
// Response
{
  "token_id": "0x...",
  "address": "did:zhtp:abc123...",
  "balance": 5000
}
```

#### GET /api/v1/token/list
```json
// Response
{
  "tokens": [
    {
      "token_id": "0x...",
      "name": "SOV",
      "symbol": "SOV",
      "total_supply": 1000000000
    },
    {
      "token_id": "0x...",
      "name": "MyToken",
      "symbol": "MTK",
      "total_supply": 1000000
    }
  ],
  "count": 2
}
```

---

## Phase 2: CLI Commands (zhtp-cli/src/commands/token.rs)

### Commands to Implement

```bash
# Create a new token
zhtp-cli token create --name "MyToken" --symbol "MTK" --supply 1000000

# Mint more tokens (creator only)
zhtp-cli token mint --token-id <id> --amount 5000 --to <address>

# Transfer tokens
zhtp-cli token transfer --token-id <id> --amount 100 --to <address>

# Get token info
zhtp-cli token info --token-id <id>

# Check balance
zhtp-cli token balance --token-id <id> --address <address>

# List all tokens
zhtp-cli token list
```

---

## Implementation Steps

### Step 1: Create Token Handler (API)
- [x] Create `zhtp/src/api/handlers/token/mod.rs`
- [x] Implement `TokenHandler` struct
- [x] Add request/response types
- [x] Implement all 6 endpoints

### Step 2: Register Routes
- [x] Add `pub mod token;` to `handlers/mod.rs`
- [x] Export `TokenHandler`
- [x] Register routes in server

### Step 3: Create CLI Token Module
- [x] Create `zhtp-cli/src/commands/token.rs`
- [x] Add subcommand structs (Create, Mint, Transfer, Info, Balance, List)
- [x] Implement QUIC calls to API

### Step 4: Register CLI Commands
- [x] Add `Token` variant to main command enum
- [x] Wire up subcommand handling

### Step 5: Testing
- [ ] Unit tests for API handlers
- [ ] Integration tests for CLI
- [ ] Manual testing on testnet

---

## Files to Create/Modify

### New Files
- `zhtp/src/api/handlers/token/mod.rs` - API handler
- `zhtp-cli/src/commands/token.rs` - CLI commands

### Modified Files
- `zhtp/src/api/handlers/mod.rs` - Add token module
- `zhtp/src/unified_server.rs` - Register token routes
- `zhtp-cli/src/commands/mod.rs` - Add token commands
- `zhtp-cli/src/main.rs` - Wire token subcommand

---

## Security Considerations

1. **Creator-only minting**: Verify caller is token creator before minting
2. **Sufficient balance**: Check balance before transfers
3. **Identity verification**: All operations require valid identity
4. **Transaction signing**: All state-changing ops create signed transactions

---

## Estimated Effort

| Task | Estimate |
|------|----------|
| API Handler | 2-3 hours |
| Route Registration | 30 min |
| CLI Commands | 2 hours |
| CLI Registration | 30 min |
| Testing | 1 hour |
| **Total** | **~6 hours** |
