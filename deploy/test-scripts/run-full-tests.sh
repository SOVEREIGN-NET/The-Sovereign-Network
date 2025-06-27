#!/bin/bash
# ZHTP Complete System Test Suite
# This script runs comprehensive end-to-end tests of the entire ZHTP system

set -e

echo "==================================="
echo "ZHTP Complete System Test Suite"
echo "==================================="
echo "Starting comprehensive testing of ZHTP blockchain internet system..."

# Test configuration
CEREMONY_COORDINATOR="zhtp-ceremony-coordinator:8080"
VALIDATOR_PRIMARY="zhtp-validator-primary:8080"
VALIDATOR_SECONDARY="zhtp-validator-secondary:8080"
STORAGE_NODE="zhtp-storage-node:8080"
FULL_NODE="zhtp-full-node:8080"

TEST_RESULTS_DIR="/home/zhtp/test-results"
LOG_FILE="$TEST_RESULTS_DIR/full-test-$(date +%Y%m%d-%H%M%S).log"

# Ensure test results directory exists
mkdir -p "$TEST_RESULTS_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Test result tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log "Running test: $test_name"
    
    if eval "$test_command" >> "$LOG_FILE" 2>&1; then
        log "✅ PASSED: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log "❌ FAILED: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Function to wait for service to be ready
wait_for_service() {
    local service_url="$1"
    local service_name="$2"
    local max_attempts=60
    local attempt=1
    
    log "Waiting for $service_name to be ready at $service_url..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "http://$service_url/health" > /dev/null 2>&1; then
            log "✅ $service_name is ready"
            return 0
        fi
        log "Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    log "❌ $service_name failed to start within timeout"
    return 1
}

# Function to test ceremony completion
test_ceremony_completion() {
    log "Testing trusted setup ceremony completion..."
    
    # Check ceremony coordinator status
    local ceremony_status=$(curl -s "http://$CEREMONY_COORDINATOR/ceremony/status" | jq -r '.status' 2>/dev/null || echo "unknown")
    
    if [ "$ceremony_status" = "completed" ]; then
        log "✅ Ceremony completed successfully"
        return 0
    elif [ "$ceremony_status" = "in_progress" ]; then
        log "⏳ Ceremony in progress, waiting..."
        # Wait up to 10 minutes for ceremony completion
        local wait_attempts=120
        local attempt=1
        
        while [ $attempt -le $wait_attempts ]; do
            ceremony_status=$(curl -s "http://$CEREMONY_COORDINATOR/ceremony/status" | jq -r '.status' 2>/dev/null || echo "unknown")
            if [ "$ceremony_status" = "completed" ]; then
                log "✅ Ceremony completed after waiting"
                return 0
            fi
            sleep 5
            attempt=$((attempt + 1))
        done
        
        log "❌ Ceremony did not complete within timeout"
        return 1
    else
        log "❌ Ceremony status unknown: $ceremony_status"
        return 1
    fi
}

# Function to test validator registration
test_validator_registration() {
    log "Testing validator registration..."
    
    # Check if validators are registered
    local registered_validators=$(curl -s "http://$VALIDATOR_PRIMARY/validators/list" | jq '. | length' 2>/dev/null || echo "0")
    
    if [ "$registered_validators" -ge 2 ]; then
        log "✅ Validators registered successfully: $registered_validators validators"
        return 0
    else
        log "❌ Insufficient validators registered: $registered_validators"
        return 1
    fi
}

# Function to test blockchain operation
test_blockchain_operation() {
    log "Testing blockchain operation..."
    
    # Check if blockchain is producing blocks
    local current_height=$(curl -s "http://$VALIDATOR_PRIMARY/blockchain/height" | jq -r '.height' 2>/dev/null || echo "0")
    
    if [ "$current_height" -gt 0 ]; then
        log "✅ Blockchain is active, current height: $current_height"
        
        # Wait for a few more blocks to ensure continuous operation
        sleep 30
        local new_height=$(curl -s "http://$VALIDATOR_PRIMARY/blockchain/height" | jq -r '.height' 2>/dev/null || echo "0")
        
        if [ "$new_height" -gt "$current_height" ]; then
            log "✅ Blockchain is producing new blocks: $current_height -> $new_height"
            return 0
        else
            log "❌ Blockchain not producing new blocks"
            return 1
        fi
    else
        log "❌ Blockchain not active"
        return 1
    fi
}

# Function to test ZK proof generation and verification
test_zk_proofs() {
    log "Testing ZK proof generation and verification..."
    
    # Test transaction proof
    local proof_result=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/zkp/test" \
        -H "Content-Type: application/json" \
        -d '{"type": "transaction", "amount": 100}' | jq -r '.verified' 2>/dev/null || echo "false")
    
    if [ "$proof_result" = "true" ]; then
        log "✅ ZK proof generation and verification working"
        return 0
    else
        log "❌ ZK proof generation or verification failed"
        return 1
    fi
}

# Function to test storage operations
test_storage_operations() {
    log "Testing storage operations..."
    
    # Test data storage
    local test_data='{"test": "data", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'
    local store_result=$(curl -s -X POST "http://$STORAGE_NODE/storage/store" \
        -H "Content-Type: application/json" \
        -d "$test_data" | jq -r '.hash' 2>/dev/null || echo "")
    
    if [ -n "$store_result" ] && [ "$store_result" != "null" ]; then
        log "✅ Data storage successful, hash: $store_result"
        
        # Test data retrieval
        local retrieved_data=$(curl -s "http://$STORAGE_NODE/storage/retrieve/$store_result" 2>/dev/null || echo "")
        if [ -n "$retrieved_data" ] && [ "$retrieved_data" != "null" ]; then
            log "✅ Data retrieval successful"
            return 0
        else
            log "❌ Data retrieval failed"
            return 1
        fi
    else
        log "❌ Data storage failed"
        return 1
    fi
}

# Function to test network connectivity
test_network_connectivity() {
    log "Testing network connectivity between nodes..."
    
    # Test peer connectivity
    local peer_count=$(curl -s "http://$FULL_NODE/network/peers" | jq '. | length' 2>/dev/null || echo "0")
    
    if [ "$peer_count" -ge 3 ]; then
        log "✅ Network connectivity good, connected to $peer_count peers"
        return 0
    else
        log "❌ Poor network connectivity, only $peer_count peers"
        return 1
    fi
}

# Function to test quantum-resistant cryptography
test_quantum_cryptography() {
    log "Testing quantum-resistant cryptography..."
    
    # Test Dilithium signatures
    local crypto_test=$(curl -s -X POST "http://$VALIDATOR_PRIMARY/crypto/test" \
        -H "Content-Type: application/json" \
        -d '{"algorithm": "dilithium", "message": "test message"}' | jq -r '.verified' 2>/dev/null || echo "false")
    
    if [ "$crypto_test" = "true" ]; then
        log "✅ Quantum-resistant cryptography working"
        return 0
    else
        log "❌ Quantum-resistant cryptography test failed"
        return 1
    fi
}

# Main test execution
main() {
    log "Starting ZHTP complete system tests..."
    
    # Phase 1: Wait for all services to be ready
    log "Phase 1: Waiting for services to start..."
    wait_for_service "$CEREMONY_COORDINATOR" "Ceremony Coordinator" || exit 1
    wait_for_service "$VALIDATOR_PRIMARY" "Primary Validator" || exit 1
    wait_for_service "$VALIDATOR_SECONDARY" "Secondary Validator" || exit 1
    wait_for_service "$STORAGE_NODE" "Storage Node" || exit 1
    wait_for_service "$FULL_NODE" "Full Node" || exit 1
    
    # Phase 2: Ceremony and Setup Tests
    log "Phase 2: Ceremony and setup tests..."
    run_test "Ceremony Completion" "test_ceremony_completion"
    run_test "Validator Registration" "test_validator_registration"
    
    # Phase 3: Core Functionality Tests
    log "Phase 3: Core functionality tests..."
    run_test "Blockchain Operation" "test_blockchain_operation"
    run_test "ZK Proof System" "test_zk_proofs"
    run_test "Storage Operations" "test_storage_operations"
    run_test "Network Connectivity" "test_network_connectivity"
    run_test "Quantum Cryptography" "test_quantum_cryptography"
    
    # Phase 4: Integration Tests
    log "Phase 4: Integration tests..."
    run_test "End-to-End Transaction" "./test-scripts/test-e2e-transaction.sh"
    run_test "DAO Voting System" "./test-scripts/test-dao-voting.sh"
    run_test "DNS Resolution" "./test-scripts/test-dns-resolution.sh"
    
    # Final Results
    log "==================================="
    log "TEST RESULTS SUMMARY"
    log "==================================="
    log "Total Tests: $TOTAL_TESTS"
    log "Passed: $PASSED_TESTS"
    log "Failed: $FAILED_TESTS"
    log "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
    log "==================================="
    
    # Generate test report
    cat > "$TEST_RESULTS_DIR/test-report.json" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "success_rate": $(( PASSED_TESTS * 100 / TOTAL_TESTS )),
    "log_file": "$LOG_FILE"
}
EOF
    
    if [ $FAILED_TESTS -eq 0 ]; then
        log "🎉 ALL TESTS PASSED! ZHTP system is fully operational."
        exit 0
    else
        log "⚠️  Some tests failed. Check the logs for details."
        exit 1
    fi
}

# Run main function
main "$@"
