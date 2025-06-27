#!/bin/bash
# ZHTP Complete System Deployment and Testing Script
# This script orchestrates the full deployment and testing of the ZHTP blockchain internet system

set -e

echo "=============================================="
echo "ZHTP Blockchain Internet System Deployment"
echo "=============================================="
echo "Starting complete system deployment and testing..."

# Configuration
DEPLOYMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$DEPLOYMENT_DIR")"
COMPOSE_FILE="$DEPLOYMENT_DIR/docker-compose.full-test.yml"
LOG_FILE="$DEPLOYMENT_DIR/deployment-$(date +%Y%m%d-%H%M%S).log"

# Create necessary directories
mkdir -p "$DEPLOYMENT_DIR"/{data,logs,monitoring/grafana}

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    log "Cleaning up..."
    docker-compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    docker system prune -f 2>/dev/null || true
}

# Error handler
error_handler() {
    log "❌ Error occurred on line $1"
    log "Deployment failed. Check logs for details."
    cleanup
    exit 1
}

trap 'error_handler $LINENO' ERR
trap cleanup EXIT

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log "❌ Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log "❌ Docker Compose is not installed"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log "❌ Docker daemon is not running"
        exit 1
    fi
    
    log "✅ Prerequisites check passed"
}

# Function to build images
build_images() {
    log "Building ZHTP Docker images..."
    
    cd "$PROJECT_ROOT"
    
    # Build main ZHTP image
    log "Building main ZHTP image..."
    docker build -f deploy/Dockerfile -t zhtp:latest . || {
        log "❌ Failed to build main ZHTP image"
        exit 1
    }
    
    # Build test image
    log "Building ZHTP test image..."
    docker build -f deploy/Dockerfile.test -t zhtp-test:latest . || {
        log "❌ Failed to build ZHTP test image"
        exit 1
    }
    
    log "✅ Docker images built successfully"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    log "Deploying ZHTP infrastructure..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Start ceremony and validator infrastructure
    log "Starting ceremony infrastructure..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        zhtp-ceremony-coordinator \
        zhtp-ceremony-participant-1 \
        zhtp-ceremony-participant-2 \
        zhtp-ceremony-participant-3
    
    # Wait for ceremony to be ready
    log "Waiting for ceremony infrastructure..."
    sleep 60
    
    # Start validator nodes
    log "Starting validator nodes..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        zhtp-validator-primary \
        zhtp-validator-secondary
    
    # Wait for validators
    log "Waiting for validators..."
    sleep 45
    
    # Start remaining infrastructure
    log "Starting remaining infrastructure..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        zhtp-storage-node \
        zhtp-full-node
    
    # Start monitoring
    log "Starting monitoring infrastructure..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        zhtp-monitor \
        zhtp-metrics \
        zhtp-logs
    
    log "✅ Infrastructure deployed successfully"
}

# Function to wait for system readiness
wait_for_system_ready() {
    log "Waiting for system to be fully operational..."
    
    local max_attempts=120
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log "System readiness check attempt $attempt/$max_attempts..."
        
        # Check if all services are healthy
        local healthy_services=$(docker-compose -f "$COMPOSE_FILE" ps --services --filter "status=running" | wc -l)
        local total_services=$(docker-compose -f "$COMPOSE_FILE" config --services | wc -l)
        
        if [ "$healthy_services" -ge 8 ]; then  # Core services should be running
            log "✅ System appears ready ($healthy_services/$total_services services running)"
            return 0
        fi
        
        log "System not ready yet ($healthy_services/$total_services services running)"
        sleep 15
        attempt=$((attempt + 1))
    done
    
    log "❌ System did not become ready within timeout"
    return 1
}

# Function to run system tests
run_system_tests() {
    log "Running comprehensive system tests..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Run the complete test suite
    docker-compose -f "$COMPOSE_FILE" --profile test run --rm zhtp-test-runner || {
        log "❌ System tests failed"
        return 1
    }
    
    log "✅ System tests completed successfully"
}

# Function to display system status
show_system_status() {
    log "System Status Dashboard:"
    log "========================="
    
    # Show running containers
    log "Running Services:"
    docker-compose -f "$COMPOSE_FILE" ps
    
    # Show service URLs
    log ""
    log "Service URLs:"
    log "- Ceremony Coordinator: http://localhost:8080"
    log "- Primary Validator: http://localhost:8090"
    log "- Secondary Validator: http://localhost:8091"
    log "- Storage Node: http://localhost:8092"
    log "- Full Node: http://localhost:8093"
    log "- Monitoring Dashboard: http://localhost:3000 (admin/zhtp123)"
    log "- Metrics: http://localhost:9090"
    log ""
    
    # Show logs locations
    log "Logs and Data:"
    log "- Container logs: docker-compose -f $COMPOSE_FILE logs [service-name]"
    log "- Test results: $DEPLOYMENT_DIR/data/test-results/"
    log "- Deployment log: $LOG_FILE"
}

# Function to run interactive mode
interactive_mode() {
    log "Entering interactive mode..."
    log "Available commands:"
    log "  status  - Show system status"
    log "  test    - Run tests again"
    log "  logs    - Show recent logs"
    log "  stop    - Stop all services"
    log "  restart - Restart all services"
    log "  quit    - Exit interactive mode"
    
    while true; do
        echo -n "ZHTP> "
        read -r command
        
        case $command in
            "status")
                show_system_status
                ;;
            "test")
                run_system_tests
                ;;
            "logs")
                docker-compose -f "$COMPOSE_FILE" logs --tail=50
                ;;
            "stop")
                docker-compose -f "$COMPOSE_FILE" stop
                log "All services stopped"
                ;;
            "restart")
                docker-compose -f "$COMPOSE_FILE" restart
                log "All services restarted"
                ;;
            "quit"|"exit")
                break
                ;;
            *)
                log "Unknown command: $command"
                ;;
        esac
    done
}

# Main deployment function
main() {
    log "Starting ZHTP complete system deployment..."
    
    # Phase 1: Prerequisites and Build
    check_prerequisites
    build_images
    
    # Phase 2: Infrastructure Deployment
    deploy_infrastructure
    wait_for_system_ready
    
    # Phase 3: System Testing
    run_system_tests
    
    # Phase 4: Status and Monitoring
    show_system_status
    
    log "🎉 ZHTP system deployed and tested successfully!"
    log "The complete blockchain internet system is now operational."
    
    # Check if running in interactive mode
    if [ "${1:-}" = "--interactive" ] || [ "${1:-}" = "-i" ]; then
        interactive_mode
    else
        log "System is running. Use --interactive flag for interactive management."
        log "To stop the system: docker-compose -f $COMPOSE_FILE down"
    fi
}

# Script entry point
case "${1:-}" in
    "build")
        check_prerequisites
        build_images
        ;;
    "deploy")
        check_prerequisites
        deploy_infrastructure
        wait_for_system_ready
        show_system_status
        ;;
    "test")
        run_system_tests
        ;;
    "clean")
        cleanup
        ;;
    "status")
        show_system_status
        ;;
    *)
        main "$@"
        ;;
esac
