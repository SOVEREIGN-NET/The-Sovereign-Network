#!/bin/bash
# DAO Voting System Test
# Tests anonymous voting with ZK proofs

set -e

VALIDATOR_PRIMARY="zhtp-validator-primary:8080"

echo "Testing DAO voting system with anonymous ZK proofs..."

# Create a test proposal
PROPOSAL_DATA='{
    "title": "Test Proposal",
    "description": "A test proposal for the DAO voting system",
    "voting_period": 3600,
    "options": ["Yes", "No", "Abstain"]
}'

# Submit proposal
echo "Creating DAO proposal..."
PROPOSAL_ID=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/dao/proposals" \
    -H "Content-Type: application/json" \
    -d "$PROPOSAL_DATA" | jq -r '.proposal_id' 2>/dev/null || echo "")

if [ -z "$PROPOSAL_ID" ] || [ "$PROPOSAL_ID" = "null" ]; then
    echo "❌ Failed to create proposal"
    exit 1
fi

echo "✅ Proposal created with ID: $PROPOSAL_ID"

# Cast anonymous votes
echo "Casting anonymous votes..."

# Vote 1 (Yes)
VOTE1_DATA='{
    "proposal_id": "'$PROPOSAL_ID'",
    "vote": "Yes",
    "voter_commitment": "commitment1",
    "generate_proof": true
}'

VOTE1_HASH=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/dao/vote" \
    -H "Content-Type: application/json" \
    -d "$VOTE1_DATA" | jq -r '.vote_hash' 2>/dev/null || echo "")

# Vote 2 (No)
VOTE2_DATA='{
    "proposal_id": "'$PROPOSAL_ID'",
    "vote": "No",
    "voter_commitment": "commitment2",
    "generate_proof": true
}'

VOTE2_HASH=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/dao/vote" \
    -H "Content-Type: application/json" \
    -d "$VOTE2_DATA" | jq -r '.vote_hash' 2>/dev/null || echo "")

if [ -z "$VOTE1_HASH" ] || [ "$VOTE1_HASH" = "null" ] || [ -z "$VOTE2_HASH" ] || [ "$VOTE2_HASH" = "null" ]; then
    echo "❌ Failed to cast votes"
    exit 1
fi

echo "✅ Votes cast successfully"

# Wait for votes to be processed
sleep 15

# Check voting results
echo "Checking voting results..."
VOTING_RESULTS=$(curl -s "http://$VALIDATOR_PRIMARY/dao/proposals/$PROPOSAL_ID/results" 2>/dev/null || echo "")

if [ -n "$VOTING_RESULTS" ] && [ "$VOTING_RESULTS" != "null" ]; then
    echo "✅ Voting results retrieved successfully"
    
    # Verify vote anonymity (voter identities should not be revealed)
    VOTER_ANONYMITY=$(echo "$VOTING_RESULTS" | jq -r '.voter_anonymity_preserved' 2>/dev/null || echo "false")
    
    if [ "$VOTER_ANONYMITY" = "true" ]; then
        echo "✅ Voter anonymity preserved successfully"
        exit 0
    else
        echo "❌ Voter anonymity not preserved"
        exit 1
    fi
else
    echo "❌ Failed to retrieve voting results"
    exit 1
fi
