#!/bin/bash
# Check for TRUE duplicate type definitions across crates
# Only flags types that have IDENTICAL field definitions
# Part of TYPES-EPIC #1642

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Checking for TRUE duplicate type definitions (same name + same fields)..."

# Allowlist: Known duplicates that need to be fixed in a future refactor
# Format: "TypeName"
ALLOWLIST=(
    "ValidatorInfo"
    "BandwidthStatistics"
    "DiscoveryStatistics"
    "MeshStatus"
    "NetworkStatistics"
    "BlockchainSyncManager"
    "NetworkConfig"
    "NullBlockchainProvider"
    "PeerReputation"
    "StorageStats"
    "SyncCoordinator"
    "CacheConfig"
    "ContentMetadata"
    "EconomicAssessment"
    "EconomicConfig"
    "EconomicRequirements"
    "EconomicStats"
    "MeshConfig"
    "RateLimitConfig"
    "SecurityConfig"
    "SessionActivity"
    "SessionStats"
    "StorageConfig"
    "StorageContract"
    "StorageIntegration"
    "TimeRestrictions"
    "ZdnsConfig"
    "ZdnsFlags"
    "ZdnsQuery"
    "ZdnsRecord"
    "ZdnsResponse"
    "ErasureConfig"
)

ALLOWLIST_PATTERN=$(printf "|%s" "${ALLOWLIST[@]}")
ALLOWLIST_PATTERN="${ALLOWLIST_PATTERN:1}"  # Remove leading |

# Temp file to store type definitions
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Find all pub structs and extract their full definitions
for crate in lib-*/src; do
    if [[ "$crate" == "lib-types/src" ]]; then
        continue  # Skip lib-types (canonical source)
    fi
    
    crate_name=$(echo "$crate" | sed 's|/src||')
    
    # Find all pub struct definitions with their fields
    grep -rh "^pub struct" "$crate" --include="*.rs" 2>/dev/null | while read -r line; do
        struct_name=$(echo "$line" | sed -n 's/.*pub struct \([A-Za-z0-9_]*\).*/\1/p')
        if [[ -z "$struct_name" ]]; then
            continue
        fi
        
        # Skip if in allowlist
        if echo "$struct_name" | grep -qE "^($ALLOWLIST_PATTERN)$"; then
            continue
        fi
        
        file=$(grep -l "pub struct $struct_name" "$crate"/*.rs 2>/dev/null | head -1)
        if [[ -z "$file" ]]; then
            continue
        fi
        
        fields=$(sed -n "/pub struct $struct_name/,/^}/p" "$file" 2>/dev/null | \
            grep -E "^\s+\w+:" | \
            sed 's/:.*//' | \
            tr '\n' ' ' | \
            xargs)
        
        if [[ -n "$fields" ]]; then
            echo "$crate_name:$struct_name:$fields" >> "$TEMP_DIR/types.txt"
        else
            echo "$crate_name:$struct_name:" >> "$TEMP_DIR/types.txt"
        fi
    done
done

# Find duplicates (same name + same fields)
DUPLICATES=$(cat "$TEMP_DIR/types.txt" | sort | uniq -d | grep -v "^:$" || true)

if [[ -n "$DUPLICATES" ]]; then
    echo ""
    echo -e "${RED}ERROR: Found TRUE duplicate type definitions:${NC}"
    echo ""
    echo "$DUPLICATES" | while read -r dup; do
        crate=$(echo "$dup" | cut -d: -f1)
        name=$(echo "$dup" | cut -d: -f2)
        echo -e "  ${YELLOW}$name${NC} in $crate"
    done
    echo ""
    exit 1
fi

echo -e "${GREEN}No true duplicate types found.${NC}"
exit 0
