# ZHTP API Documentation

## Overview

The ZHTP API provides REST endpoints for interacting with the Zero-Knowledge Hypertext Transfer Protocol network. All endpoints use HTTP/1.1 for compatibility while implementing ZHTP protocol features.

**Base URL**: `http://127.0.0.1:9333/api/v1`

## Authentication

Most endpoints require API authentication. Include these headers:
- `Content-Type: application/json`
- `Accept: application/json`
- `Authorization: Bearer <api_key>` (when required)

## Identity Management

### Create DID Identity

Creates a new Zero-Knowledge Decentralized Identifier (DID) with full Web4 citizen onboarding.

**Endpoint**: `POST /identity/create`

**Request Body**:
```json
{
  "identity_type": "human",
  "display_name": "TestUser",
  "recovery_options": [
    "recovery_phrase_testuser",
    "backup_phrase_1726374017"
  ],
  "initial_wallet_type": "citizen_wallet"
}
```

**Request Parameters**:
- `identity_type` (string): Type of identity (`"human"`, `"organization"`, `"service"`)
- `display_name` (string): Human-readable name for the identity
- `recovery_options` (array): Recovery phrases for account recovery
- `initial_wallet_type` (string): Type of initial wallet (`"citizen_wallet"`, `"business_wallet"`)

**Response** (Success - 200 OK):
```json
{
  "did": "did:zhtp:81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285",
  "identity_id": "81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285",
  "primary_wallet_id": "82fcaa64469b576b51f04d0344f97e3e5649cbbceefceb1547a61d3f4e4eb75c",
  "ubi_wallet_id": "2d3c5489f97f2ad6...",
  "savings_wallet_id": "97abcbd5b19cb31b...",
  "dao_registration": {
    "voting_power": 1,
    "registration_status": "active"
  },
  "ubi_registration": {
    "daily_amount": 33000000000000000000,
    "monthly_amount": 1000000000000000000000,
    "eligibility_status": "approved"
  },
  "blockchain": {
    "transaction_hash": "e12958e1d46f15cec4dd6b43787f66ab16bf72d5de10c946c76421fb02cbea3b",
    "registration_status": "transaction_created",
    "block_height": 1
  },
  "welcome_bonus": {
    "amount": 5000000000000000000000,
    "status": "credited"
  },
  "web4_access": {
    "services_available": 10,
    "access_level": "full_citizen"
  },
  "privacy_credentials": {
    "zk_credentials": 2,
    "selective_disclosure": true
  }
}
```

**Features Enabled**:
- **Quantum-Resistant DID**: Post-quantum cryptographic identity
- **Multi-Wallet System**: Primary, UBI, and Savings wallets created
- **DAO Voting Rights**: Automatic DAO registration with voting power
- **UBI Eligibility**: Daily 33 ZHTP, Monthly 1000 ZHTP tokens
- **Welcome Bonus**: 5000 ZHTP tokens for new citizens
- **Blockchain Registration**: Identity registered on ZHTP blockchain
- **Web4 Access**: Full access to 10 Web4 services
- **Zero-Knowledge Privacy**: 2 ZK credentials for selective disclosure

### Verify Identity

Verifies an existing ZHTP identity and returns verification status.

**Endpoint**: `POST /identity/verify`

**Request Body**:
```json
{
  "identity_data": {
    "identity_id": "81b3eefad482f2f6a2621d0c10c5c4b2340e81e86c3be637cd4a60df48cf8285",
    "verification_requested": true
  },
  "verification_level": "Standard"
}
```

**Response**:
```json
{
  "verified": true,
  "verification_score": 95,
  "verification_level": "Standard",
  "identity_status": "active",
  "blockchain_confirmed": true
}
```

## Wallet Operations

### Transfer Tokens

**Endpoint**: `POST /wallet/transfer`

**Request Body**:
```json
{
  "from_wallet": "sender_wallet_id",
  "to_wallet": "receiver_wallet_id", 
  "amount": 1000,
  "memo": "Payment for services",
  "priority": "Normal"
}
```

## DAO Operations

### Get DAO Information

**Endpoint**: `GET /dao/info`

**Response**:
```json
{
  "total_members": 1250,
  "active_proposals": 3,
  "treasury_balance": 50000000,
  "voting_power_distribution": "decentralized",
  "governance_model": "liquid_democracy"
}
```

### Create Proposal

**Endpoint**: `POST /dao/proposal/create`

### Vote on Proposal  

**Endpoint**: `POST /dao/proposal/vote`

## Blockchain Operations

### Get Blockchain Status

**Endpoint**: `GET /blockchain/status`

### Get Block Information

**Endpoint**: `GET /blockchain/block`

### Get Transaction

**Endpoint**: `GET /blockchain/transaction/{tx_hash}`

## Network Operations

###  Status

**Endpoint**: `GET /network/isp-bypass`

### Mesh Network Status

**Endpoint**: `GET /network/mesh/status`

### Network Statistics

**Endpoint**: `GET /network/stats`

## Error Responses

All endpoints may return these error responses:

**400 Bad Request**:
```json
{
  "error": "invalid_request",
  "message": "Missing required field: identity_type",
  "details": {}
}
```

**401 Unauthorized**:
```json
{
  "error": "unauthorized",
  "message": "Invalid API key or authentication required"
}
```

**500 Internal Server Error**:
```json
{
  "error": "internal_error",
  "message": "Blockchain integration error",
  "details": {
    "component": "blockchain",
    "retry_suggested": true
  }
}
```

## Rate Limiting

- **Default**: 100 requests per minute per IP
- **Authenticated**: 1000 requests per minute per API key
- **Identity Operations**: 10 creates per hour per IP

## Economic Model

All API operations include economic incentives:

- **2% DAO Fee**: Automatically deducted from transactions for UBI funding
- **Network Fees**: Based on computational cost and priority
- **Quality Bonuses**: Extra rewards for high-quality service provision

## Security Features

- **Post-Quantum Cryptography**: All endpoints use quantum-resistant algorithms
- **Zero-Knowledge Proofs**: Privacy-preserving transaction validation  
- **Identity Verification**: Blockchain-backed identity confirmation
- **Economic Security**: Anti-spam through economic incentives

## Integration Examples

### cURL Example

```bash
# Create a new DID identity
curl -X POST http://127.0.0.1:9333/api/v1/identity/create \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "identity_type": "human",
    "display_name": "Alice",
    "recovery_options": ["recovery_phrase_alice", "backup_phrase_12345"],
    "initial_wallet_type": "citizen_wallet"
  }'
```

### JavaScript Example

```javascript
// Create identity using fetch API
const response = await fetch('http://127.0.0.1:9333/api/v1/identity/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  body: JSON.stringify({
    identity_type: 'human',
    display_name: 'Bob',
    recovery_options: ['recovery_phrase_bob', 'backup_phrase_67890'],
    initial_wallet_type: 'citizen_wallet'
  })
});

const result = await response.json();
console.log('DID Created:', result.did);
```

## Development & Testing

The ZHTP API server runs on `http://127.0.0.1:9333` by default and includes:

- **Live Monitoring**: Real-time system health and metrics
- **Development Logging**: Comprehensive request/response logging
- **Test Mode**: Simplified operations for development testing
- **Simulation Mode**: Network operations without hardware requirements

For production deployment, configure appropriate security headers, rate limiting, and authentication mechanisms.
