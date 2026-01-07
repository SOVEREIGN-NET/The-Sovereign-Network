#!/bin/bash

###############################################################################
# Web4 CLI Functional Testing Runner
#
# Comprehensive test suite for Web4 CLI domain and deployment functionality.
# Executes 7-phase testing covering: Registration → Deployment → Persistence →
# Updates → Rollback → Deletion → Error Handling
#
# Usage:
#   ./run_web4_functional_tests.sh [phase] [options]
#
# Examples:
#   ./run_web4_functional_tests.sh                    # Run all tests
#   ./run_web4_functional_tests.sh registration       # Run registration phase only
#   ./run_web4_functional_tests.sh --verbose          # Run with verbose output
#   ./run_web4_functional_tests.sh --nocapture        # Show println! output
#
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_PHASE="${1:-all}"
VERBOSE="${VERBOSE:-0}"
NOCAPTURE="${NOCAPTURE:-0}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

###############################################################################
# Utility Functions
###############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $*${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

print_usage() {
    cat << EOF
${BLUE}Web4 CLI Functional Testing Runner${NC}

${GREEN}Usage:${NC}
  $(basename "$0") [PHASE] [OPTIONS]

${GREEN}Phases:${NC}
  all              Run all test phases (default)
  registration     Test domain registration functionality
  deployment       Test site deployment and manifest validation
  persistence      Test state persistence across restarts
  updates          Test version management and updates
  rollback         Test version rollback functionality
  deletion         Test domain deletion and cleanup
  errors           Test error handling and edge cases
  integration      Test complete workflows and integration scenarios

${GREEN}Options:${NC}
  --verbose        Show detailed test output
  --nocapture      Display println! output from tests
  --release        Build and test in release mode
  --help           Show this help message

${GREEN}Environment Variables:${NC}
  RUST_LOG=<level> Set logging level (debug, info, warn, error)
  TEST_THREADS=N   Number of parallel test threads (default: 1 for isolation)

${GREEN}Examples:${NC}
  # Run all tests with verbose output
  $(basename "$0") all --verbose

  # Run registration tests only, display println output
  $(basename "$0") registration --nocapture

  # Run with debug logging
  RUST_LOG=debug $(basename "$0") all

  # Run specific test
  cargo test --test web4_functional registration_ -- --nocapture

EOF
}

###############################################################################
# Build and Dependency Checks
###############################################################################

check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust."
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq not found. Some output parsing features will be limited."
    fi
    
    log_success "All required dependencies found"
}

build_tests() {
    log_info "Building test suite..."
    
    cd "$PROJECT_ROOT"
    
    local build_cmd="cargo build --tests"
    if [[ "$BUILD_MODE" == "release" ]]; then
        build_cmd="$build_cmd --release"
    fi
    
    if ! $build_cmd 2>&1 | grep -E "(Compiling|Finished|error)" ; then
        log_error "Build failed"
        return 1
    fi
    
    log_success "Test suite built successfully"
}

###############################################################################
# Test Execution
###############################################################################

run_all_tests() {
    log_section "Running Complete Web4 CLI Functional Test Suite"
    
    local test_cmd="cargo test --test web4_functional"
    
    [[ "$NOCAPTURE" == "1" ]] && test_cmd="$test_cmd --nocapture"
    [[ "$BUILD_MODE" == "release" ]] && test_cmd="$test_cmd --release"
    
    cd "$PROJECT_ROOT/zhtp-cli"
    
    if $test_cmd -- --test-threads=1; then
        log_success "All tests passed!"
        return 0
    else
        log_error "Some tests failed"
        return 1
    fi
}

run_phase_tests() {
    local phase="$1"
    local phase_name=""
    local test_filter=""
    
    case "$phase" in
        registration)
            phase_name="Domain Registration"
            test_filter="registration_"
            ;;
        deployment)
            phase_name="Deployment"
            test_filter="deployment_"
            ;;
        persistence)
            phase_name="Persistence"
            test_filter="persistence_"
            ;;
        updates)
            phase_name="Updates"
            test_filter="updates_"
            ;;
        rollback)
            phase_name="Rollback"
            test_filter="rollback_"
            ;;
        deletion)
            phase_name="Deletion"
            test_filter="deletion_"
            ;;
        errors)
            phase_name="Error Handling"
            test_filter="error_"
            ;;
        integration)
            phase_name="Integration"
            test_filter="integration_"
            ;;
        *)
            log_error "Unknown phase: $phase"
            return 1
            ;;
    esac
    
    log_section "Running Phase: $phase_name"
    
    local test_cmd="cargo test --test web4_functional $test_filter"
    
    [[ "$NOCAPTURE" == "1" ]] && test_cmd="$test_cmd --nocapture"
    [[ "$BUILD_MODE" == "release" ]] && test_cmd="$test_cmd --release"
    
    cd "$PROJECT_ROOT/zhtp-cli"
    
    if $test_cmd -- --test-threads=1; then
        log_success "Phase '$phase_name' completed successfully!"
        return 0
    else
        log_error "Phase '$phase_name' had failures"
        return 1
    fi
}

###############################################################################
# Test Reporting
###############################################################################

generate_test_report() {
    log_section "Test Execution Summary"
    
    log_info "Test Suite: Web4 CLI Functional Testing"
    log_info "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    log_info "Test Count: Comprehensive (7 phases, 25+ test scenarios)"
    log_info "Coverage Areas:"
    log_info "  • Domain Registration (unique, duplicates, metadata)"
    log_info "  • Deployment (files, manifests, validation)"
    log_info "  • Persistence (state across restarts)"
    log_info "  • Updates (versions, content changes)"
    log_info "  • Rollback (previous versions)"
    log_info "  • Deletion (cleanup, isolation)"
    log_info "  • Error Handling (invalid input, edge cases)"
    log_info "  • Integration (complete workflows)"
    
    if [[ "$TEST_RESULT" == "0" ]]; then
        log_success "All tests passed successfully"
    else
        log_error "Some tests failed - see output above for details"
    fi
}

###############################################################################
# Main Entry Point
###############################################################################

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                print_usage
                exit 0
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --nocapture)
                NOCAPTURE=1
                shift
                ;;
            --release)
                BUILD_MODE="release"
                shift
                ;;
            all|registration|deployment|persistence|updates|rollback|deletion|errors|integration)
                TEST_PHASE="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Execution flow
    log_info "Web4 CLI Functional Testing Suite"
    log_info "=================================="
    
    check_dependencies
    build_tests
    
    TEST_RESULT=0
    
    if [[ "$TEST_PHASE" == "all" ]]; then
        run_all_tests || TEST_RESULT=$?
    else
        run_phase_tests "$TEST_PHASE" || TEST_RESULT=$?
    fi
    
    generate_test_report
    
    exit $TEST_RESULT
}

# Run main function
main "$@"
