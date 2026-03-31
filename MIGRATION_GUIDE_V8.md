# V8 Transaction Format Migration Guide

## Overview

Commit `124ff65d` removed legacy V1-V7 transaction compatibility. All clients must now use V8 format.

## Breaking Changes

### 1. Transaction Serialization
- **Removed**: `legacy.rs` module (618 lines)
- **Impact**: Mobile clients using pre-V8 wire format will fail signature validation
- **Action**: Update to lib-client v0.8.0+

### 2. Hashing Changes
- **Removed**: `hash_for_signature_v1_to_v7()` dispatch
- **Impact**: Old transactions will produce different hashes
- **Action**: Re-sign all pending transactions with V8 clients

### 3. SOV Sender Validation
- **Changed**: Removed version >= 8 guard
- **Impact**: Strict key_id validation for all transactions
- **Action**: Ensure all wallets use proper Dilithium key_ids

## Migration Steps

### For Node Operators
1. Update to latest zhtp release
2. Clear mempool before upgrade
3. Monitor for rejected legacy transactions

### For Mobile Developers
1. Update to lib-client v0.8.0+
2. Test transaction signing flow
3. Verify hash consistency with nodes

### For Tooling
1. testnet_reset tool updated to use V8 format
2. Wallet registration now uses zero initial_balance
3. SOV minting happens via explicit TokenMint transactions

## Verification

```bash
# Check transaction version
zhtp-cli tx inspect --tx-hex YOUR_TX_HEX

# Verify hash consistency
zhtp-cli tx hash --tx-hex YOUR_TX_HEX
```

## Rollback

If issues occur, revert to commit `124ff65d^` and use legacy compatibility mode.

## Support

Report issues to: https://github.com/sovereign-network/zhtp/issues
Tag with: `v8-migration`