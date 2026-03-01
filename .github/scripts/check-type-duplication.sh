#!/bin/bash
# Check for duplicate type definitions across crates
# Part of TYPES-EPIC #1642

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Checking for duplicate type definitions across crates..."

# Allowlist: types that are intentionally duplicated (re-exports, etc.)
ALLOWLIST_PATTERN="^(AccessLevel|AccessPattern|AccessPolicy|ActivityType|Amount|ApprovalVerifierType|AttestationType|AuthMethod|BandwidthStatistics|BatchOp|BatchRangeProof|BiometricType|BlockMetadata|ByzantineEvidence|CacheConfig|CacheStats|CachedVerificationResult|CallPermissions|ChallengeType|ChunkMetadata|Config|ConnectionId|ContentMetadata|ContentType|ContractConfig|ContractMetadata|ContractState|CryptoConfig|DataChunk|DatabaseStats|DeviceInfo|DeviceMetadata|DiskUsage|EgressPolicy|EncryptionLevel|Endpoint|EngineState|Error|Event|EventType|ExecutionResult|FeeConfig|Filter|Hash|Header|Identity|IdentityId|IdentityMetadata|KeyShare|KeyType|LeaseConfig|Message|MessageType|Metadata|NetworkConfig|NetworkStats|NodeId|Notification|Operation|OperationType|Order|PackedEpoch|PeerInfo|Permission|Policy|PoolStats Prefix|Price|Priority|Proof|Proposal|ProtocolConfig|ProviderStats|ProxyConfig|PublicKey|Query|RateLimit|Registration|Request|RequestType|Response|Reward|RewardConfig|RewardType|Role|Route|RoutingTable|Script|SecretKey|Signature|SignatureAlgorithm|SignatureType|SocketAddr|State|StateMachine|Status|StorageConfig|StorageStats|StorageTier|Transaction|TransactionInput|TransactionOutput|TransactionType|TxKind|VerificationResult|Version|Vote|Wallet|WalletConfig|WatcherConfig)$"

# Find all public structs and enums across all crate src directories
# Exclude target directory, lib-types (canonical source), and test files
DUPLICATES=""

# Get all rust source files in crate src directories
for crate in lib-*/src; do
    # Skip lib-types as it's the canonical source
    if [[ "$crate" == "lib-types/src" ]]; then
        continue
    fi
    
    crate_name=$(echo "$crate" | sed 's|/src||')
    
    # Find all pub struct and pub enum definitions
    while IFS= read -r line; do
        # Extract type name
        type_name=$(echo "$line" | sed -n 's/.*pub \(struct\|enum\) \([A-Za-z0-9_]*\).*/\2/p')
        
        if [[ -n "$type_name" ]]; then
            # Check if it's in the allowlist
            if ! echo "$type_name" | grep -qE "$ALLOWLIST_PATTERN"; then
                echo "$crate_name:$type_name"
            fi
        fi
    done < <(grep -rh "^pub struct\|^pub enum" "$crate" --include="*.rs" 2>/dev/null | grep -v "#\[derive")
done | sort | uniq -d | while read -r dup; do
    echo -e "${RED}ERROR: Duplicate type: $dup${NC}"
    DUPLICATES="$DUPLICATES$dup\n"
done

if [[ -n "$DUPLICATES" ]]; then
    echo ""
    echo -e "${RED}ERROR: Found duplicate type definitions across crates!${NC}"
    echo -e "${YELLOW}If these are intentional re-exports, add them to the ALLOWLIST in this script.${NC}"
    echo ""
    echo "Duplicate types found:"
    echo -e "$DUPLICATES"
    exit 1
fi

echo -e "${GREEN}No duplicate types found (excluding intentional re-exports).${NC}"
exit 0
