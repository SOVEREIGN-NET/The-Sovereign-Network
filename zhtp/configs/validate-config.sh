#!/bin/bash
# ZHTP Configuration Validator
# Validates node configuration files for common issues

set -e

CONFIG_FILE="$1"

if [ -z "$CONFIG_FILE" ]; then
    echo "Usage: $0 <config-file>"
    echo "Example: $0 ./configs/full-node.toml"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo "Validating ZHTP configuration: $CONFIG_FILE"
echo "================================================"

# Check if it's a valid TOML file
if ! command -v toml &> /dev/null; then
    echo "  TOML validator not found, skipping syntax check"
else
    echo "TOML syntax validation..."
    toml check "$CONFIG_FILE" || exit 1
fi

# Extract key values for validation
MESH_MODE=$(grep '^mesh_mode' "$CONFIG_FILE" | cut -d'"' -f2 2>/dev/null || echo "")
SECURITY_LEVEL=$(grep '^security_level' "$CONFIG_FILE" | cut -d'"' -f2 2>/dev/null || echo "")
VALIDATOR_ENABLED=$(grep '^validator_enabled' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")
STORAGE_CAPACITY=$(grep '^storage_capacity_gb' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")
MAX_PEERS=$(grep '^max_peers' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")

echo
echo "Configuration Summary:"
echo "  Mesh Mode: $MESH_MODE"
echo "  Security Level: $SECURITY_LEVEL"  
echo "  Validator Enabled: $VALIDATOR_ENABLED"
echo "  Storage Capacity: ${STORAGE_CAPACITY}GB"
echo "  Max Peers: $MAX_PEERS"

# Validation checks
echo
echo "Running validation checks..."

# Check mesh mode vs protocols
if [ "$MESH_MODE" = "PureMesh" ]; then
    if grep -q '"tcp"' "$CONFIG_FILE"; then
        echo " WARNING: Pure mesh mode should not include TCP protocol"
    else
        echo "Pure mesh mode: TCP protocol correctly excluded"
    fi
fi

# Check validator security requirements
if [ "$VALIDATOR_ENABLED" = "true" ]; then
    if [ "$SECURITY_LEVEL" != "Maximum" ]; then
        echo " WARNING: Validator nodes should use Maximum security level"
    else
        echo "Validator security: Maximum level configured"
    fi
fi

# Check storage capacity reasonableness
if [ ! -z "$STORAGE_CAPACITY" ]; then
    if [ "$STORAGE_CAPACITY" -lt 10 ]; then
        echo " WARNING: Very low storage capacity (${STORAGE_CAPACITY}GB)"
    elif [ "$STORAGE_CAPACITY" -gt 50000 ]; then
        echo " WARNING: Very high storage capacity (${STORAGE_CAPACITY}GB) - ensure disk space available"
    else
        echo "Storage capacity: ${STORAGE_CAPACITY}GB looks reasonable"
    fi
fi

# Check peer count
if [ ! -z "$MAX_PEERS" ]; then
    if [ "$MAX_PEERS" -lt 10 ]; then
        echo " WARNING: Low peer count ($MAX_PEERS) may affect network connectivity"
    elif [ "$MAX_PEERS" -gt 1000 ]; then
        echo " WARNING: High peer count ($MAX_PEERS) may use significant resources"
    else
        echo "Peer count: $MAX_PEERS looks reasonable"
    fi
fi

# Check port configurations
MESH_PORT=$(grep '^mesh_port' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")
DHT_PORT=$(grep '^dht_port' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")
API_PORT=$(grep '^api_port' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d ' ' 2>/dev/null || echo "")

if [ ! -z "$MESH_PORT" ] && [ ! -z "$DHT_PORT" ] && [ ! -z "$API_PORT" ]; then
    if [ "$MESH_PORT" = "$DHT_PORT" ] || [ "$MESH_PORT" = "$API_PORT" ] || [ "$DHT_PORT" = "$API_PORT" ]; then
        echo "ERROR: Port conflict detected - mesh, DHT, and API ports must be different"
        exit 1
    else
        echo "Port configuration: No conflicts detected"
    fi
fi

# Check data directory
DATA_DIR=$(grep '^data_directory' "$CONFIG_FILE" | cut -d'"' -f2 2>/dev/null || echo "")
if [ ! -z "$DATA_DIR" ]; then
    if [[ "$DATA_DIR" == /* ]] || [[ "$DATA_DIR" == ./* ]]; then
        echo "Data directory: $DATA_DIR"
    else
        echo " WARNING: Data directory should be absolute or relative path: $DATA_DIR"
    fi
fi

echo
echo "Configuration validation completed!"
echo "Start your node with: zhtp node start --config $CONFIG_FILE"