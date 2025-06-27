#!/bin/bash
# DNS Resolution Test
# Tests decentralized DNS with ownership proofs

set -e

VALIDATOR_PRIMARY="zhtp-validator-primary:8080"

echo "Testing decentralized DNS resolution with ownership proofs..."

# Register a test domain
DOMAIN_DATA='{
    "domain": "test.zhtp",
    "owner": "test_owner_address",
    "ip_address": "192.168.1.100",
    "ttl": 3600,
    "generate_ownership_proof": true
}'

# Submit domain registration
echo "Registering test domain..."
REGISTRATION_HASH=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/dns/register" \
    -H "Content-Type: application/json" \
    -d "$DOMAIN_DATA" | jq -r '.registration_hash' 2>/dev/null || echo "")

if [ -z "$REGISTRATION_HASH" ] || [ "$REGISTRATION_HASH" = "null" ]; then
    echo "❌ Failed to register domain"
    exit 1
fi

echo "✅ Domain registered with hash: $REGISTRATION_HASH"

# Wait for registration to be processed
sleep 20

# Test DNS resolution
echo "Testing DNS resolution..."
RESOLVED_IP=$(curl -s "http://$VALIDATOR_PRIMARY/dns/resolve/test.zhtp" | jq -r '.ip_address' 2>/dev/null || echo "")

if [ "$RESOLVED_IP" = "192.168.1.100" ]; then
    echo "✅ DNS resolution successful: test.zhtp -> $RESOLVED_IP"
    
    # Verify ownership proof
    OWNERSHIP_PROOF=$(curl -s "http://$VALIDATOR_PRIMARY/dns/ownership-proof/test.zhtp" | jq -r '.verified' 2>/dev/null || echo "false")
    
    if [ "$OWNERSHIP_PROOF" = "true" ]; then
        echo "✅ DNS ownership proof verified successfully"
        exit 0
    else
        echo "❌ DNS ownership proof verification failed"
        exit 1
    fi
else
    echo "❌ DNS resolution failed. Expected: 192.168.1.100, Got: $RESOLVED_IP"
    exit 1
fi
