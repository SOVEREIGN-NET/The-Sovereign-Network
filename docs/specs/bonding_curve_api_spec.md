# Bonding Curve Token API Specification

**Version:** 1.0  
**Base URL:** `/api/v1`  
**Content-Type:** `application/json`

---

## Overview

The Bonding Curve Token API provides endpoints for deploying, trading, and managing tokens with a two-phase lifecycle:

1. **Curve Phase:** Protocol-controlled pricing using mathematical curves (Linear, Exponential, Sigmoid)
2. **AMM Phase:** Market-driven pricing via constant product AMM after graduation

---

## Authentication

| Endpoint Type | Authentication Required | Notes |
|--------------|------------------------|-------|
| **Write Operations** (deploy, buy, sell, swap, liquidity) | ✅ Yes | Requires valid identity session |
| **Read Operations** (list, stats, price, valuation) | ❌ No | Public endpoints |

**Authentication Header:**
```http
Authorization: Bearer <session_token>
X-Identity-ID: <identity_id>
```

---

## Endpoints

### CurveHandler - Bonding Curve Lifecycle

Base path: `/api/v1/curve`

---

#### 1. Deploy Bonding Curve Token

**POST** `/api/v1/curve/deploy`

Deploy a new token with bonding curve pricing.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "My Token",
  "symbol": "MYTKN",
  "curve_type": {
    "type": "linear",
    "base_price": 1000000,
    "slope": 100
  },
  "threshold": {
    "type": "reserve_amount",
    "min_reserve": 10000000
  },
  "sell_enabled": true
}
```

**Curve Types:**
| Type | Parameters | Description |
|------|------------|-------------|
| `linear` | `base_price`, `slope` | Price = base + (supply × slope) |
| `exponential` | `base_price`, `growth_rate_bps` | Price grows exponentially |
| `sigmoid` | `max_price`, `midpoint_supply`, `steepness` | S-curve pricing |

**Threshold Types:**
| Type | Parameters | Description |
|------|------------|-------------|
| `reserve_amount` | `min_reserve` | Graduate when reserve reaches amount |
| `supply_amount` | `min_supply` | Graduate when supply reaches amount |
| `time_and_reserve` | `min_time_seconds`, `min_reserve` | Both time and reserve |
| `time_and_supply` | `min_time_seconds`, `min_supply` | Both time and supply |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "name": "My Token",
  "symbol": "MYTKN",
  "phase": "curve",
  "tx_status": "confirmed"
}
```

**Errors:**
- `400 Bad Request` - Invalid parameters
- `401 Unauthorized` - Not authenticated
- `409 Conflict` - Token with this name/symbol already exists

---

#### 2. Buy Tokens from Curve

**POST** `/api/v1/curve/buy`

Purchase tokens from the bonding curve.

**Authentication:** Required

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "stable_amount": 100000000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |
| `stable_amount` | uint64 | Amount of stablecoin to spend (8 decimals) |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "stable_paid": 100000000,
  "tokens_received": 950000000,
  "auto_graduated": false,
  "tx_status": "confirmed"
}
```

**Errors:**
- `400 Bad Request` - Token not in curve phase
- `401 Unauthorized` - Not authenticated
- `404 Not Found` - Token not found

---

#### 3. Sell Tokens to Curve

**POST** `/api/v1/curve/sell`

Sell tokens back to the bonding curve (only if `sell_enabled` was true at deployment).

**Authentication:** Required

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "token_amount": 500000000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |
| `token_amount` | uint64 | Amount of tokens to sell (8 decimals) |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "tokens_sold": 500000000,
  "stable_received": 47500000,
  "tx_status": "confirmed"
}
```

**Errors:**
- `400 Bad Request` - Selling disabled or token not in curve phase
- `401 Unauthorized` - Not authenticated
- `404 Not Found` - Token not found

---

#### 4. List All Tokens

**GET** `/api/v1/curve/list`

Get a list of all bonding curve tokens.

**Authentication:** None (Public)

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "token_id": "a1b2c3d4e5f6...",
      "name": "My Token",
      "symbol": "MYTKN",
      "phase": "curve",
      "current_price": 1050000,
      "total_supply": 1000000000,
      "reserve_balance": 50000000
    }
  ],
  "total_count": 1,
  "curve_count": 1,
  "graduated_count": 0,
  "amm_count": 0
}
```

---

#### 5. List Tokens by Phase

**GET** `/api/v1/curve/list/{phase}`

Get tokens filtered by phase (`curve`, `graduated`, or `amm`).

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Values | Description |
|-----------|--------|-------------|
| `phase` | `curve`, `graduated`, `amm` | Filter by token phase |

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "token_id": "a1b2c3d4e5f6...",
      "name": "My Token",
      "symbol": "MYTKN",
      "phase": "curve",
      "current_price": 1050000
    }
  ],
  "count": 1
}
```

---

#### 6. Get Token Info

**GET** `/api/v1/curve/{token_id}`

Get detailed information about a specific token.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "name": "My Token",
  "symbol": "MYTKN",
  "decimals": 8,
  "phase": "curve",
  "total_supply": 1000000000,
  "reserve_balance": 50000000,
  "current_price": 1050000,
  "curve_type": "linear",
  "sell_enabled": true,
  "can_graduate": false,
  "graduation_progress_percent": 50,
  "creator": "did:zhtp:abcd...",
  "deployed_at": 1600000000,
  "amm_pool_id": null
}
```

---

#### 7. Get Token Stats

**GET** `/api/v1/curve/{token_id}/stats`

Get statistics and historical data for a token.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "total_supply": 1000000000,
  "reserve_balance": 50000000,
  "current_price": 1050000,
  "total_trades": 150,
  "total_volume_stable": 500000000,
  "unique_holders": 45,
  "phase": "curve"
}
```

---

#### 8. Get Token Price

**GET** `/api/v1/curve/{token_id}/price`

Get current price from curve (pre-graduation).

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "price_usd_cents": 10,
  "source": "curve_linear",
  "phase": "curve"
}
```

---

#### 9. Check Graduation Eligibility

**GET** `/api/v1/curve/{token_id}/can-graduate`

Check if a token is ready to graduate to AMM.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | 64-character hex token ID |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "can_graduate": true,
  "reason": "Reserve threshold met",
  "current_reserve": 10000000,
  "threshold_reserve": 10000000,
  "progress_percent": 100
}
```

---

#### 10. List Ready-to-Graduate Tokens

**GET** `/api/v1/curve/ready-to-graduate`

Get all tokens that are ready for graduation.

**Authentication:** None (Public)

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "token_id": "a1b2c3d4e5f6...",
      "name": "My Token",
      "symbol": "MYTKN",
      "current_reserve": 10000000,
      "threshold_reserve": 10000000
    }
  ],
  "count": 1
}
```

---

### SwapHandler - AMM Operations (Post-Graduation)

Base path: `/api/v1/swap`

---

#### 11. Execute AMM Swap

**POST** `/api/v1/swap`

Execute a swap on the AMM pool (only for graduated tokens in AMM phase).

**Authentication:** Required

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "amount_in": 100000000,
  "min_amount_out": 90000000,
  "token_to_sov": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string (hex) | Token ID (64 hex chars) |
| `pool_id` | string (hex) | AMM Pool ID (64 hex chars) |
| `amount_in` | uint64 | Input amount (8 decimals) |
| `min_amount_out` | uint64 | Minimum output (slippage protection, 0 = no protection) |
| `token_to_sov` | bool | `true` = token→SOV, `false` = SOV→token |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "amount_in": 100000000,
  "amount_out": 95000000,
  "price_impact_bps": 50,
  "tx_status": "ready_for_execution"
}
```

**Errors:**
- `400 Bad Request` - Token not in AMM phase or pool ID mismatch
- `401 Unauthorized` - Not authenticated
- `404 Not Found` - Token or pool not found

---

#### 12. Add Liquidity

**POST** `/api/v1/swap/liquidity/add`

Add liquidity to an AMM pool.

**Authentication:** Required

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "token_amount": 1000000000,
  "sov_amount": 100000000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string (hex) | Token ID |
| `pool_id` | string (hex) | Pool ID |
| `token_amount` | uint64 | Token amount to add |
| `sov_amount` | uint64 | SOV amount to add |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "token_amount": 1000000000,
  "sov_amount": 100000000,
  "lp_tokens_minted": 31622776,
  "tx_status": "submitted_to_mempool"
}
```

---

#### 13. Remove Liquidity

**POST** `/api/v1/swap/liquidity/remove`

Remove liquidity from an AMM pool.

**Authentication:** Required

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "lp_amount": 31622776
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string (hex) | Token ID |
| `pool_id` | string (hex) | Pool ID |
| `lp_amount` | uint64 | LP tokens to burn |

**Response (200 OK):**
```json
{
  "success": true,
  "token_id": "a1b2c3d4e5f6...",
  "pool_id": "f1e2d3c4b5a6...",
  "lp_tokens_burned": 31622776,
  "token_amount_received": 1000000000,
  "sov_amount_received": 100000000,
  "tx_status": "submitted_to_mempool"
}
```

---

#### 14. Get Pool Info

**GET** `/api/v1/swap/pools/{token_id}`

Get AMM pool information for a token.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | Token ID |

**Response (200 OK):**
```json
{
  "exists": true,
  "pool_id": "f1e2d3c4b5a6...",
  "token_id": "a1b2c3d4e5f6...",
  "token_symbol": "MYTKN",
  "phase": "amm",
  "total_liquidity_token": 1000000000,
  "total_liquidity_sov": 100000000,
  "lp_token_supply": 31622776,
  "fee_bps": 100,
  "k": "100000000000000000",
  "initialized": true
}
```

---

### ValuationHandler - Price Queries

Base paths: `/api/v1/price`, `/api/v1/valuation`

---

#### 15. Get Token Valuation

**GET** `/api/v1/valuation/{token_id}`

Get comprehensive valuation with price source and confidence.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | Token ID |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "price_usd_cents": 10,
  "source": "curve_linear",
  "confidence_level": "high",
  "phase": "curve"
}
```

**Price Sources:**
- `curve_linear` - Linear bonding curve
- `curve_exponential` - Exponential bonding curve
- `curve_sigmoid` - Sigmoid bonding curve
- `amm_spot` - AMM spot price
- `amm_twap` - AMM time-weighted average price
- `srv` - SRV-derived price (for SOV only)

**Confidence Levels:**
- `high` - Curve pricing (deterministic)
- `medium` - AMM with good liquidity
- `low` - AMM with low liquidity or volatile

---

#### 16. Get Token Price (Simple)

**GET** `/api/v1/price/{token_id}`

Get current price only.

**Authentication:** None (Public)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `token_id` | string (hex) | Token ID |

**Query Parameters (optional):**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `price_type` | string | `twap` | `spot` or `twap` |

**Response (200 OK):**
```json
{
  "token_id": "a1b2c3d4e5f6...",
  "price": 1050000,
  "price_type": "twap",
  "timestamp": 1600000000
}
```

---

#### 17. Batch Valuation

**POST** `/api/v1/valuation/batch`

Get valuations for multiple tokens at once.

**Authentication:** None (Public)

**Request Body:**
```json
{
  "token_ids": [
    "a1b2c3d4e5f6...",
    "b2c3d4e5f6a7..."
  ]
}
```

**Response (200 OK):**
```json
{
  "valuations": [
    {
      "token_id": "a1b2c3d4e5f6...",
      "price_usd_cents": 10,
      "source": "curve_linear",
      "confidence_level": "high"
    },
    {
      "token_id": "b2c3d4e5f6a7...",
      "price_usd_cents": 25,
      "source": "amm_twap",
      "confidence_level": "medium"
    }
  ]
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": true,
  "status": 400,
  "message": "Token not in curve phase",
  "code": "INVALID_PHASE"
}
```

**Common Error Codes:**

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | `INVALID_PHASE` | Token not in correct phase for operation |
| 400 | `SELL_DISABLED` | Selling not enabled for this token |
| 400 | `SLIPPAGE_EXCEEDED` | Price moved beyond slippage tolerance |
| 401 | `UNAUTHORIZED` | Authentication required |
| 404 | `TOKEN_NOT_FOUND` | Token ID doesn't exist |
| 404 | `POOL_NOT_FOUND` | AMM pool not found |
| 409 | `TOKEN_EXISTS` | Token with name/symbol already exists |
| 409 | `POOL_MISMATCH` | Pool ID doesn't match token |

---

## Data Types

### Token ID
- 32-byte value encoded as 64-character hexadecimal string
- Example: `a1b2c3d4e5f6789012345678901234567890abcd1234567890abcdef12345678`

### Amounts
- All amounts use 8 decimal places (like SOV)
- 1 token = 100,000,000 atomic units
- Example: `100000000` = 1.0 token

### Prices
- Prices are in USD cents with 8 decimal precision
- Example: `1000000` = $0.01 USD per token

### Phases
| Phase | Description | Operations Allowed |
|-------|-------------|-------------------|
| `curve` | Initial bonding curve phase | deploy, buy, sell |
| `graduated` | Transition phase (frozen) | None (temporary) |
| `amm` | AMM market phase | swap, add/remove liquidity |

---

## Frontend Integration Guide

### 1. Deploy a Token
```javascript
const response = await fetch('/api/v1/curve/deploy', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${sessionToken}`
  },
  body: JSON.stringify({
    name: "My Token",
    symbol: "MYTKN",
    curve_type: { type: "linear", base_price: 1000000, slope: 100 },
    threshold: { type: "reserve_amount", min_reserve: 10000000 },
    sell_enabled: true
  })
});
const { token_id } = await response.json();
```

### 2. Buy Tokens
```javascript
const response = await fetch('/api/v1/curve/buy', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${sessionToken}`
  },
  body: JSON.stringify({
    token_id: tokenId,
    stable_amount: 100000000  // 1.0 USDC
  })
});
```

### 3. Get Price (No Auth)
```javascript
const response = await fetch(`/api/v1/price/${tokenId}`);
const { price } = await response.json();
```

### 4. Swap on AMM (Post-Graduation)
```javascript
const response = await fetch('/api/v1/swap', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${sessionToken}`
  },
  body: JSON.stringify({
    token_id: tokenId,
    pool_id: poolId,
    amount_in: 100000000,
    min_amount_out: 95000000,  // 5% slippage protection
    token_to_sov: true
  })
});
```

---

## WebSocket Events (Future)

Real-time updates for:
- `token.purchased` - New buy event
- `token.sold` - New sell event
- `token.graduated` - Token graduated to AMM
- `swap.executed` - AMM swap completed
- `price.updated` - Price change alert

---

*Specification Version: 1.0*  
*Last Updated: 2026-02-21*
