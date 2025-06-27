#!/bin/bash
# End-to-End Transaction Test
# Tests the complete transaction flow with ZK proofs

set -e

VALIDATOR_PRIMARY="zhtp-validator-primary:8080"
STORAGE_NODE="zhtp-storage-node:8080"

echo "Testing end-to-end transaction with ZK proofs..."

# Create a test transaction
TRANSACTION_DATA='{
    "from": "test_sender_address",
    "to": "test_receiver_address", 
    "amount": 50,
    "nonce": 1,
    "gas_limit": 21000,
    "generate_proof": true
}'

# Submit transaction
echo "Submitting transaction..."
TRANSACTION_HASH=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/transactions/submit" \
    -H "Content-Type: application/json" \
    -d "$TRANSACTION_DATA" | jq -r '.hash' 2>/dev/null || echo "")

if [ -z "$TRANSACTION_HASH" ] || [ "$TRANSACTION_HASH" = "null" ]; then
    echo "❌ Failed to submit transaction"
    exit 1
fi

echo "✅ Transaction submitted with hash: $TRANSACTION_HASH"

# Wait for transaction to be included in a block
echo "Waiting for transaction to be mined..."
sleep 30

# Check transaction status
TRANSACTION_STATUS=$(curl -s "http://$VALIDATOR_PRIMARY/transactions/status/$TRANSACTION_HASH" | jq -r '.status' 2>/dev/null || echo "unknown")

if [ "$TRANSACTION_STATUS" = "confirmed" ]; then
    echo "✅ Transaction confirmed successfully"
    
    # Verify ZK proof was generated and verified
    PROOF_VERIFIED=$(curl -s "http://$VALIDATOR_PRIMARY/transactions/proof/$TRANSACTION_HASH" | jq -r '.verified' 2>/dev/null || echo "false")
    
    if [ "$PROOF_VERIFIED" = "true" ]; then
        echo "✅ ZK proof generated and verified successfully"
        exit 0
    else
        echo "❌ ZK proof verification failed"
        exit 1
    fi
else
    echo "❌ Transaction not confirmed. Status: $TRANSACTION_STATUS"
    exit 1
fi
