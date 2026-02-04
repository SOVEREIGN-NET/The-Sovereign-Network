#!/bin/bash

# API test script for recovery phrase validation
# Tests the actual ZHTP API endpoints with 20 and 24-word recovery phrases
# Requires a running ZHTP server on localhost:8000

set -e

echo "🔑 Recovery Phrase API Test Script"
echo "=================================="
echo ""

SERVER_URL="${ZHTP_SERVER:-http://localhost:8000}"
echo "Server: $SERVER_URL"
echo ""

# Test credentials
IDENTITY_ID="0000000000000000000000000000000000000000000000000000000000000000"
SESSION_TOKEN="test_session_token"

# 20-word custom ZHTP recovery phrase
PHRASE_20="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20"

# 24-word BIP39 standard recovery phrase
PHRASE_24="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24"

# 19-word invalid phrase
PHRASE_19="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19"

# Test helper function
test_endpoint() {
    local endpoint=$1
    local method=$2
    local phrase=$3
    local description=$4
    local expected=$5

    echo "Test: $description"
    echo "  Endpoint: $method $endpoint"
    echo "  Phrase words: $(echo $phrase | wc -w | tr -d ' ')"
    echo "  Expected: $expected"
    echo ""

    # Check if server is running
    if ! curl -s -m 2 "$SERVER_URL/api/v1/health" > /dev/null 2>&1; then
        echo "  ⚠️  Server not running at $SERVER_URL"
        echo "  To test against a live API:"
        echo "    1. Start the ZHTP server: cargo run --bin zhtp-server"
        echo "    2. Run this script again"
        echo ""
        return
    fi

    # Send request to API
    if [ "$method" == "POST" ]; then
        response=$(curl -s -X POST "$SERVER_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "{\"recovery_phrase\":\"$phrase\",\"identity_id\":\"$IDENTITY_ID\",\"session_token\":\"$SESSION_TOKEN\"}" \
            2>&1 || echo "ERROR")

        if [[ "$response" == *"ERROR"* ]]; then
            echo "  ❌ Request failed (server not responding)"
        else
            echo "  Response: $response"
        fi
    fi
    echo ""
}

echo "API Endpoints to Test:"
echo "---------------------"
echo ""

# Test verify recovery phrase endpoint
echo "1️⃣  Testing /api/v1/identity/backup/verify"
echo ""
test_endpoint "/api/v1/identity/backup/verify" "POST" "$PHRASE_20" \
    "20-word recovery phrase verification" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/backup/verify" "POST" "$PHRASE_24" \
    "24-word recovery phrase verification" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/backup/verify" "POST" "$PHRASE_19" \
    "19-word recovery phrase (invalid)" "❌ ERROR"
echo ""

# Test recover identity endpoint
echo "2️⃣  Testing /api/v1/identity/recover"
echo ""
test_endpoint "/api/v1/identity/recover" "POST" "$PHRASE_20" \
    "20-word identity recovery" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/recover" "POST" "$PHRASE_24" \
    "24-word identity recovery" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/recover" "POST" "$PHRASE_19" \
    "19-word identity recovery (invalid)" "❌ ERROR"
echo ""

# Test restore from seed endpoint
echo "3️⃣  Testing /api/v1/identity/restore/seed"
echo ""
test_endpoint "/api/v1/identity/restore/seed" "POST" "$PHRASE_20" \
    "20-word seed restoration" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/restore/seed" "POST" "$PHRASE_24" \
    "24-word seed restoration" "✅ ACCEPTED"
test_endpoint "/api/v1/identity/restore/seed" "POST" "$PHRASE_19" \
    "19-word seed restoration (invalid)" "❌ ERROR"
echo ""

echo "Summary:"
echo "--------"
echo ""
echo "✅ Valid recovery phrases (20 or 24 words):"
echo "  - /api/v1/identity/backup/verify"
echo "  - /api/v1/identity/recover"
echo "  - /api/v1/identity/restore/seed"
echo ""
echo "❌ Invalid recovery phrases (any other length):"
echo "  - Returns error message: 'Recovery phrase must be 20 or 24 words, got {actual}'"
echo ""
echo "To run with a live server:"
echo "  ZHTP_SERVER=http://localhost:8000 $0"
echo "  or"
echo "  export ZHTP_SERVER=http://localhost:8000"
echo "  $0"
