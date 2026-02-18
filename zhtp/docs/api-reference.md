# ZHTP API Reference

## Overview

The ZHTP API provides a comprehensive interface for interacting with the ZHTP node orchestrator. The API is built on the ZHTP protocol and provides endpoints for identity management, blockchain operations, network coordination, storage, and more.

## Base Configuration

- **Protocol**: ZHTP/1.0 over QUIC
- **Default QUIC endpoint**: 127.0.0.1:9334
- **Content-Type**: application/json

## Authentication

Authentication is handled at the transport layer via a QUIC handshake using the UHP (Unified Handshake Protocol).

## API Endpoints

### Network Management

#### Get Network Peers
Retrieve a list of connected network peers.

```
GET /api/v1/blockchain/network/peers
```

**Response:**
```json
{
  "status": "success",
  "peer_count": 5,
  "peers": [
    {
      "peer_id": "peer_1",
      "peer_type": "local",
      "status": "connected",
      "connection_time": 1697834400
    }
  ]
}
```

**Peer Types:**
- `local` - Local mesh peers
- `regional` - Regional mesh peers  
- `global` - Global mesh peers
- `relay` - Relay peers

#### Get Network Statistics
Retrieve comprehensive network statistics and health metrics.

```
GET /api/v1/blockchain/network/stats
```

**Response:**
```json
{
  "status": "success",
  "mesh_status": {
    "internet_connected": true,
    "mesh_connected": true,
    "connectivity_percentage": 85.5,
    "coverage": 72.3,
    "stability": 94.2
  },
  "traffic_stats": {
    "bytes_sent": 1024000,
    "bytes_received": 2048000,
    "packets_sent": 500,
    "packets_received": 750,
    "connection_count": 12
  },
  "peer_distribution": {
    "active_peers": 15,
    "local_peers": 8,
    "regional_peers": 5,
    "global_peers": 2,
    "relay_peers": 0
  }
}
```

#### Add Network Peer
Add a new peer to the network.

```
POST /api/v1/blockchain/network/peer/add
```

**Request Body:**
```json
{
  "peer_address": "192.168.1.100:9334",
  "peer_type": "local"
}
```

**Response:**
```json
{
  "status": "success",
  "peer_id": "peer_12345",
  "message": "Successfully initiated connection to peer 192.168.1.100:9334",
  "connected": true
}
```

#### Remove Network Peer
Remove a peer from the network.

```
DELETE /api/v1/blockchain/network/peer/{peer_id}
```

**Response:**
```json
{
  "status": "success",
  "peer_id": "peer_12345",
  "message": "Successfully initiated disconnection from peer peer_12345",
  "removed": true
}
```

### Identity Management

#### Create Identity
Create a new zero-knowledge DID identity.

```
POST /api/v1/identity/create
```

**Request Body:**
```json
{
  "name": "Alice",
  "identity_type": "human",
  "recovery_options": ["email", "phone"]
}
```

**Response:**
```json
{
  "status": "success",
  "identity_id": "did:zhtp:abc123...",
  "public_key": "04a1b2c3...",
  "created_at": 1697834400
}
```

#### Verify Identity
Verify an existing identity.

```
POST /api/v1/identity/verify
```

**Request Body:**
```json
{
  "identity_id": "did:zhtp:abc123...",
  "proof": "proof_data_here"
}
```

**Response:**
```json
{
  "status": "success",
  "verified": true,
  "verification_level": "full",
  "expires_at": 1697920800
}
```

#### List Identities
Get a list of all identities.

```
GET /api/v1/identity/list
```

**Response:**
```json
{
  "status": "success",
  "identities": [
    {
      "identity_id": "did:zhtp:abc123...",
      "name": "Alice",
      "type": "human",
      "status": "active",
      "created_at": 1697834400
    }
  ]
}
```

### Blockchain Operations

#### Get Blockchain Status
Get the current blockchain status and statistics.

```
GET /api/v1/blockchain/status
```

**Response:**
```json
{
  "status": "active",
  "height": 12345,
  "pending_transactions": 8,
  "total_identities": 150,
  "blockchain_ready": true,
  "last_block_time": 1697834400,
  "network_hash_rate": "1.5 TH/s"
}
```

#### Get Transaction
Retrieve information about a specific transaction.

```
GET /api/v1/blockchain/transaction/{tx_hash}
```

**Response:**
```json
{
  "status": "success",
  "transaction": {
    "hash": "0xabc123...",
    "block_height": 12340,
    "from": "did:zhtp:sender...",
    "to": "did:zhtp:receiver...",
    "amount": 100,
    "fee": 1,
    "timestamp": 1697834000,
    "confirmations": 5,
    "status": "confirmed"
  }
}
```

#### Submit Transaction
Submit a new transaction to the blockchain.

```
POST /api/v1/blockchain/transaction/submit
```

**Request Body:**
```json
{
  "from": "did:zhtp:sender...",
  "to": "did:zhtp:receiver...", 
  "amount": 100,
  "fee": 1,
  "signature": "signature_data_here"
}
```

**Response:**
```json
{
  "status": "success",
  "transaction_hash": "0xabc123...",
  "message": "Transaction submitted successfully"
}
```

### Wallet Operations

#### Create Wallet
Create a new wallet.

```
POST /api/v1/wallet/create
```

**Request Body:**
```json
{
  "name": "MyWallet",
  "wallet_type": "citizen"
}
```

**Response:**
```json
{
  "status": "success",
  "wallet_address": "zhtp1abc123...",
  "public_key": "04a1b2c3...",
  "wallet_type": "citizen"
}
```

#### Get Wallet Balance
Get the balance for a specific wallet.

```
GET /api/v1/wallet/balance/{address}
```

**Response:**
```json
{
  "status": "balance_found",
  "address": "zhtp1abc123...",
  "balance": 1500,
  "pending_balance": 0,
  "transaction_count": 42,
  "note": "Pending balance unavailable due to privacy-preserving commitments"
}
```

**Note:** The `pending_balance` field is always 0 because transaction amounts are hidden via Pedersen commitments for privacy. Attempting to estimate pending balances would defeat the privacy guarantees of the system.

#### Transfer Funds
Transfer funds between wallets.

```
POST /api/v1/wallet/transfer
```

**Request Body:**
```json
{
  "from": "zhtp1sender...",
  "to": "zhtp1receiver...",
  "amount": 100,
  "memo": "Payment for services"
}
```

**Response:**
```json
{
  "status": "success",
  "transaction_hash": "0xabc123...",
  "fee": 1,
  "total_amount": 101
}
```

### Storage Operations

#### Store Content
Store content in the distributed storage system.

```
POST /api/v1/storage/store
```

**Request Body:**
```json
{
  "content": "base64_encoded_content",
  "content_type": "text/plain",
  "encryption": true,
  "redundancy": 3
}
```

**Response:**
```json
{
  "status": "success",
  "content_hash": "Qm...",
  "storage_nodes": 5,
  "cost": 10
}
```

#### Retrieve Content
Retrieve content from distributed storage.

```
GET /api/v1/storage/retrieve/{content_hash}
```

**Response:**
```json
{
  "status": "success",
  "content": "base64_encoded_content",
  "content_type": "text/plain",
  "retrieved_from": ["node1", "node2"],
  "cost": 2
}
```

### DAO Operations

#### Get DAO Information
Get information about the DAO governance system.

```
GET /api/v1/dao/info
```

**Response:**
```json
{
  "status": "success",
  "dao": {
    "total_members": 500,
    "active_proposals": 3,
    "treasury_balance": 100000,
    "voting_power_distributed": 45000,
    "current_period": "voting"
  }
}
```

#### Create Proposal
Create a new DAO proposal.

```
POST /api/v1/dao/propose
```

**Request Body:**
```json
{
  "title": "Increase UBI Rate",
  "description": "Proposal to increase the UBI rate from 10 to 15 SOV per day",
  "proposal_type": "economic",
  "voting_duration": 604800
}
```

**Response:**
```json
{
  "status": "success",
  "proposal_id": "prop_123",
  "voting_starts": 1697834400,
  "voting_ends": 1698439200
}
```

#### Vote on Proposal
Cast a vote on a DAO proposal.

```
POST /api/v1/dao/vote
```

**Request Body:**
```json
{
  "proposal_id": "prop_123",
  "choice": "yes",
  "voting_power": 100
}
```

**Response:**
```json
{
  "status": "success",
  "vote_recorded": true,
  "voting_power_used": 100,
  "current_tally": {
    "yes": 15000,
    "no": 8000,
    "abstain": 2000
  }
}
```

#### Claim UBI
Claim Universal Basic Income.

```
POST /api/v1/dao/claim-ubi
```

**Response:**
```json
{
  "status": "success",
  "amount_claimed": 10,
  "next_claim_available": 1697920800,
  "total_claimed": 300
}
```

### System Monitoring

#### Health Check
Get overall system health status.

```
GET /api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "protocol": "ZHTP/1.0",
  "timestamp": 1697834400,
  "handlers": ["identity", "blockchain", "storage", "protocol"]
}
```

#### Get System Statistics
Get comprehensive system statistics.

```
GET /api/v1/stats
```

**Response:**
```json
{
  "status": "active",
  "handlers_registered": 4,
  "middleware_layers": 4,
  "requests_processed": 15847,
  "uptime": 86400,
  "identity_stats": {
    "total_identities": 150
  },
  "blockchain_stats": {
    "block_count": 12345,
    "transaction_count": 98765
  },
  "storage_stats": {
    "total_storage_used": 1073741824,
    "total_content_count": 5000
  },
  "economic_stats": {
    "total_supply": 1000000,
    "circulating_supply": 750000
  }
}
```

## Request/Response Format

### Response Headers
```
Content-Type: application/json
X-Handler: HandlerName
X-Protocol: ZHTP/1.0
X-Response-Time: 45ms
```

### Error Response Format
```json
{
  "status": "error",
  "error_code": "INVALID_REQUEST",
  "message": "Detailed error description",
  "timestamp": 1697834400
}
```

### Common Error Codes
- `INVALID_REQUEST` - Malformed request
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMITED` - Too many requests
- `INTERNAL_ERROR` - Server error

## Rate Limiting

- Default: 100 requests per minute
- Burst: Up to 20 requests in 10 seconds
- Headers included in response:
  - `X-RateLimit-Limit`: Rate limit
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Reset time

## Economic Requirements

Some operations require SOV token payments:
- Storage operations: Based on size and redundancy
- High-priority transactions: Network fee
- Premium API access: Subscription model

This API reference provides comprehensive access to all ZHTP node orchestrator functionality, enabling developers to build applications on the ZHTP network with zero-knowledge privacy, economic incentives, and decentralized governance.