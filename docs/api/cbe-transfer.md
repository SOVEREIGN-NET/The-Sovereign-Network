# CBE Transfer API Documentation

## Overview

CBE (Corporate Bond/Equity) token transfers use the `TokenTransfer` transaction type over the **ZHTP protocol** (Zero Knowledge Hypertext Transfer Protocol) via QUIC. The Compensation pool (40% of supply) has no vesting restrictions, while other pools have cliff and linear vesting periods.

**Protocol:** ZHTP v1.0 over QUIC (port 9334)

## CLI Usage

### Transfer CBE Tokens

```bash
zhtp-cli cbe transfer --to <RECIPIENT> --amount <AMOUNT>
```

**Arguments:**
- `--to`: Recipient address (32-byte hex key_id or `did:zhtp:...` format)
- `--amount`: Amount in CBE atoms (1 CBE = 100,000,000 atoms)

**Example:**
```bash
# Transfer 10 CBE to a recipient
zhtp-cli cbe transfer --to did:zhtp:a1b2c3d4... --amount 1000000000

# Transfer using hex key_id
zhtp-cli cbe transfer --to 0xa1b2c3d4... --amount 1000000000
```

**Notes:**
- The sender must have sufficient **vested** CBE balance
- Compensation pool tokens are immediately transferable (no vesting)
- Other pool tokens must be vested according to their schedules
- Transfers use nonce-based replay protection

## ZHTP API Endpoints

### POST /api/v1/token/transfer

Transfer CBE (or any token) to another wallet.

**ZHTP Request:**
```
Method: POST
URI: /api/v1/token/transfer
Content-Type: application/json
Body: {
  "signed_tx": "<hex-encoded-signed-transaction>"
}
```

**ZHTP Response (Success):**
```json
{
  "success": true,
  "tx_hash": "a1b2c3d4...",
  "token": "CBE",
  "from": "sender_key_id",
  "to": "recipient_key_id",
  "amount": "1000000000"
}
```

**ZHTP Response (Error):**
```json
{
  "success": false,
  "error": "Insufficient vested balance: have 500000000, need 1000000000"
}
```

### GET /api/v1/token/nonce/{token_id}/{address}

Fetch the current nonce for a token transfer (required for transaction signing).

**ZHTP Request:**
```
Method: GET
URI: /api/v1/token/nonce/{token_id_hex}/{address_hex}
```

**ZHTP Response:**
```json
{
  "nonce": 5
}
```

## Transaction Structure

### TokenTransferData

```rust
pub struct TokenTransferData {
    /// Token identifier (CBE token ID is derived from "CBE Equity" + "CBE")
    pub token_id: [u8; 32],
    /// Sender key_id (32 bytes)
    pub from: [u8; 32],
    /// Recipient key_id (32 bytes)
    pub to: [u8; 32],
    /// Amount in atoms (1 CBE = 100,000,000 atoms)
    pub amount: u128,
    /// Nonce for replay protection (incrementing per sender)
    pub nonce: u64,
}
```

### CBE Token ID Derivation

The CBE token ID is deterministically derived:

```rust
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

let mut hasher = DefaultHasher::new();
"CBE Equity".hash(&mut hasher);
"CBE".hash(&mut hasher);
let hash = hasher.finish();

let mut token_id = [0u8; 32];
token_id[..8].copy_from_slice(&hash.to_le_bytes());
for i in 8..32 {
    token_id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
}
```

## Vesting Schedules

### Pool Allocations

| Pool | Allocation | Vesting Schedule |
|------|-----------|------------------|
| Compensation | 40% (40B CBE) | No vesting - immediately transferable |
| Operational | 30% (30B CBE) | 12-month cliff, 36-month vest |
| Performance | 20% (20B CBE) | 6-month cliff, 24-month vest |
| Strategic | 10% (10B CBE) | 12-month cliff, 48-month vest |

### Vesting Formula

```rust
if current_block < start_block + cliff_blocks:
    vested = 0
elif current_block >= start_block + vesting_duration:
    vested = total_amount
else:
    vested = total_amount * (blocks_since_start / vesting_duration)
```

## Error Codes

| Error | Description |
|-------|-------------|
| `InsufficientVestedBalance` | Attempted to transfer more than vested amount |
| `InsufficientBalance` | Attempted to transfer more than total balance |
| `TokensNotVested` | Transfer attempted before cliff period ends |
| `ZeroAmount` | Transfer amount is zero |
| `ZeroRecipient` | Recipient address is zero/empty |
| `Unauthorized` | Caller not authorized (wrong key) |
| `MintingDisabled` | CBE has fixed supply - no minting allowed |

## Differences from SOV Transfers

| Aspect | SOV | CBE |
|--------|-----|-----|
| Storage | `token_contracts` HashMap | Dedicated `cbe_token` field |
| Vesting | None | Yes (pool-dependent) |
| Fees | 1% to treasury | None (direct transfer) |
| Supply | Minted via UBI | Fixed 100B at genesis |
| Decimals | 8 | 8 |

## Related Commands

```bash
# Check CBE balance (uses standard token balance endpoint)
zhtp-cli token balance --token-id <CBE_TOKEN_ID> --address <YOUR_ADDRESS>

# Initialize CBE pools (Bootstrap Council only)
zhtp-cli cbe init-pools \
  --compensation <KEY> \
  --operational <KEY> \
  --performance <KEY> \
  --strategic <KEY>

# Create employment contract (pays CBE salary)
zhtp-cli cbe create-contract \
  --dao-id <DAO_ID> \
  --employee <EMPLOYEE_KEY> \
  --compensation <AMOUNT> \
  --period <0=monthly,1=quarterly,2=annually>

# Process payroll (triggers CBE transfer)
zhtp-cli cbe payroll --contract-id <CONTRACT_ID>
```

## Implementation Notes

1. **Protocol**: All API calls use ZHTP over QUIC (port 9334), not HTTP
2. **Vesting Check**: The `CbeToken::transfer()` function checks `vested_balance_of()` before allowing transfers
3. **Nonce Management**: Each sender has an independent nonce per token
4. **Key Resolution**: Recipients are resolved by `key_id` - the blockchain looks up the full public key
5. **No Fees**: CBE transfers don't incur protocol fees (unlike SOV which has 1%)
6. **Atomic**: Transfers are atomic - either fully succeed or fail

## ZHTP Protocol Reference

### ZhtpMethod
- `Get` - Read operations
- `Post` - Write/transfer operations
- `Put` - Update operations
- `Delete` - Remove operations

### Default Port
- ZHTP Server: 9333
- QUIC Client API: 9334

### Content Types
- `application/json` - JSON payloads
- `application/octet-stream` - Binary data

## See Also

- [CBE Token Contract](../../lib-blockchain/src/contracts/tokens/cbe_token.rs)
- [Token Transfer Implementation](../../lib-blockchain/src/blockchain/contracts.rs)
- [CLI CBE Commands](../../zhtp-cli/src/commands/cbe.rs)
- [ZHTP Protocol](../../lib-protocols/src/zhtp/)
