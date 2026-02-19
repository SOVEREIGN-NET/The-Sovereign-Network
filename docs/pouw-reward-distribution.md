# PoUW Reward Distribution - Mobile App Integration Guide

## Overview

This document explains when and how the mobile app will receive PoUW (Proof-of-Useful-Work) rewards.

## Reward Distribution Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Mobile App    │────▶│   ZHTP Node     │────▶│   Blockchain   │
│  (Worker)       │     │  (Validation)    │     │  (Payout)      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                         │                        │
   Submit work            Validate receipts         On-chain payout
   (receipts)            Calculate rewards         (SOV tokens)
```

## Current Implementation Status

### Phase 1-3: Complete ✅
- Challenge generation (Node)
- Receipt validation (Node)
- Reward calculation (Node)

### Phase 4-5: In Progress 🔄
- On-chain payout integration
- Mobile app integration

## When Does the Mobile App Receive Rewards?

### Current State (Node-Side Only)

The current implementation calculates rewards **server-side** but does NOT automatically transfer them to the mobile app. Here's the timeline:

| Stage | What Happens | Mobile App Receives |
|-------|--------------|---------------------|
| 1. Work Submission | Mobile submits receipts | Nothing yet |
| 2. Validation | Node validates receipts | Nothing yet |
| 3. Epoch End | Rewards calculated | Nothing yet |
| 4. Payout | On-chain transfer | **SOV Tokens** |

### Epoch-Based Distribution

Rewards are calculated per **epoch** (default: 1 hour):

```
Epoch Duration: 3600 seconds (1 hour)
Reward Calculation: End of each epoch
Payout: After epoch closes + confirmation time
```

### Expected Payout Timeline

```
Epoch N starts ──────────▶ Epoch N ends
      │                          │
      │    [Validation Period]  │
      │                          │
      ▼                          ▼
Mobile submits work         Rewards calculated
                            (for Epoch N)
                                    │
                                    ▼
                            [Settlement Period]
                                    │
                                    ▼
                            Payout to wallet
                                    │
                                    ▼
                            Mobile sees balance
```

**Estimated Time to Receive Rewards:**
- Best case: ~1-2 hours after work submission
- Typical: End of current epoch + processing time

## How Rewards Are Calculated

### Proof Type Multipliers

| Proof Type | Multiplier | Description |
|------------|------------|-------------|
| Hash | 1x | Basic computation |
| Merkle | 2x | Merkle proof verification |
| Signature | 3x | Cryptographic signature |

### Reward Formula

```
final_reward = raw_bytes × base_rate × proof_multiplier
```

Where:
- `raw_bytes`: Amount of data processed
- `base_rate`: Configurable (default: 1000 units)
- `proof_multiplier`: Based on proof type (1x, 2x, or 3x)

### Cap Limits

- **Per client per epoch**: Maximum 1,000,000 units
- **Anti-gaming**: Duplicate receipts are rejected

## Mobile App Integration

### Required Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/pouw/challenge` | GET | Get work challenge |
| `/pouw/submit` | POST | Submit work receipt |
| `/pouw/rewards/{client_did}` | GET | Check accumulated rewards |

### Example: Checking Rewards

```javascript
// Mobile app polls for rewards
async function checkRewards(clientDid) {
  const response = await fetch(`/pouw/rewards/${encodeURIComponent(clientDid)}`);
  const data = await response.json();
  
  console.log(`Total Earned: ${data.total_earned / 1e8} SOV`);
  console.log(`Pending: ${data.pending / 1e8} SOV`);
  console.log(`Paid: ${data.total_paid / 1e8} SOV`);
}
```

## Future: Automated Payouts

Currently, rewards are calculated and stored but require manual triggering for on-chain payout. Future implementation will include:

1. **Automatic epoch settlement** - Rewards automatically distributed at epoch end
2. **Wallet integration** - Direct deposit to user's wallet
3. **Notification** - Push notification when rewards received

## Architecture Notes

### Reward Status States

| Status | Meaning |
|--------|---------|
| `Pending` | Calculated but not yet paid |
| `Paid` | Successfully transferred to wallet |
| `Failed` | Payout failed (will be retried) |

### Persistence

- Rewards stored in node's memory (not persistent across restarts in current implementation)
- For production: Rewards should be persisted to database

## Integration Checklist

For mobile app to receive rewards:

- [ ] Node must have initialized Treasury Kernel
- [ ] Mobile app must have valid DID (`did:sov:` or `did:zhtp:`)
- [ ] Work must be submitted and validated
- [ ] Epoch must close
- [ ] Payout must be triggered (manual or automatic)

## Troubleshooting

### Rewards Not Received?

1. **Check identity**: Is the mobile app's DID registered?
2. **Check epoch**: Has the epoch ended?
3. **Check status**: Use `/pouw/rewards/{did}` endpoint to verify
4. **Check blockchain**: Verify on-chain transaction

### API Response Example

```json
{
  "client_did": "did:sov:mobile-user-123",
  "total_rewards": 5,
  "total_earned": 1000000,
  "total_paid": 0,
  "pending": 1000000,
  "rewards": [
    {
      "reward_id": "abc123...",
      "epoch": 42,
      "final_amount": 200000,
      "payout_status": "Pending"
    }
  ]
}
```

---

**Last Updated**: 2026-02-19
**Related Issues**: #867, #877, #865
