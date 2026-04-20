#!/bin/bash
# Chain Replay Script
#
# Re-provisions all identities, wallets, and runs payroll allocations
# from the testnet snapshot after a chain reset.
#
# Usage: ./scripts/replay-chain.sh [--dry-run]
#
# Prerequisites:
#   - CLI binary built: target/dev-release/zhtp-cli (or target/release/zhtp-cli)
#   - Validator identity keystore on g1: /root/.zhtp/keystore/
#   - Chain running on g1 (77.42.37.161:9334)
#   - Snapshot files in docs/testnet/

set -euo pipefail

SERVER="77.42.37.161:9334"
SNAPSHOT="docs/testnet/testnet_snapshot_2026-04-14.json"
CBE_SNAPSHOT="docs/testnet/cbe_transactions_snapshot_2026-04-13.json"
DRY_RUN="${1:-}"

# Find CLI binary
if [ -f "target/dev-release/zhtp-cli" ]; then
    CLI="target/dev-release/zhtp-cli"
elif [ -f "target/release/zhtp-cli" ]; then
    CLI="target/release/zhtp-cli"
else
    echo "FATAL: CLI not found. Build with: cargo build --profile dev-release -p zhtp-cli"
    exit 1
fi

log() { echo "[$(date '+%H:%M:%S')] $1"; }
ok()  { echo "[$(date '+%H:%M:%S')] ✅ $1"; }
err() { echo "[$(date '+%H:%M:%S')] ❌ $1"; }

[ -f "$SNAPSHOT" ] || { echo "FATAL: Snapshot not found: $SNAPSHOT"; exit 1; }
[ -f "$CBE_SNAPSHOT" ] || { echo "FATAL: CBE snapshot not found: $CBE_SNAPSHOT"; exit 1; }

log "=== CHAIN REPLAY ==="
log "Server: $SERVER"
log "Snapshot: $SNAPSHOT"
log "CLI: $CLI"

# ============================================================================
# STEP 1: Deploy CLI to g1
# ============================================================================
log ""
log "=== STEP 1: Deploy CLI to g1 ==="
if [ "$DRY_RUN" = "--dry-run" ]; then
    log "[DRY RUN] Would deploy CLI to g1"
else
    scp "$CLI" zhtp-g1:/opt/zhtp/zhtp-cli
    ssh zhtp-g1 "chmod +x /opt/zhtp/zhtp-cli"
    ok "CLI deployed to g1"
fi

# ============================================================================
# STEP 2: Register identities + wallets from snapshot
# ============================================================================
log ""
log "=== STEP 2: Register identities + wallets ==="

# Validator/council DIDs already in genesis — skip these
SKIP_DIDS="59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d
f37a307761b863130adb6129f16c269af4e395eb3d4b14b070a756bef282c07b
bf409db91ad276fa35e8af9c78a48facdfba99eb95fcbf01719310e91c558a9c
da0c583fc07decd4ec6e0c341e198702d0dbb2772ede87ea84910b0136bceb65
22ceddadf411554b675e94df220489997e7541188865484fba699f04be168056
b448980ab32f171273221030c9a547e48942fff08184bca9bb99c800e6fcddf2
ee364ad7a51ede2a0642a708e59b3acd3f83bf4e24c7694c1d3cfbae14c8376a
94563acff1be7506bde97263611d03d53c5f1a78ba3712eb986e275a1592c821"

# Extract wallet provisioning commands from snapshot
python3 -c "
import json, sys

snapshot = json.load(open('$SNAPSHOT'))
cbe_snapshot = json.load(open('$CBE_SNAPSHOT'))

skip_dids = set('''$SKIP_DIDS'''.strip().split('\n'))

wallets = snapshot.get('wallets', [])
identities = snapshot.get('identities', [])

# Build DID -> identity_id mapping
did_to_id = {}
for ident in identities:
    did = ident.get('did', '')
    did_hash = did.replace('did:zhtp:', '')
    did_to_id[did] = did_hash

# Count what we'll provision
provision_count = 0
skip_count = 0

# Output provision commands
for w in wallets:
    owner = w.get('owner_identity_id', '')
    if owner in skip_dids:
        skip_count += 1
        continue
    wallet_id = w.get('wallet_id', '')
    wallet_type = w.get('wallet_type', 'Primary')
    public_key = w.get('public_key', '')
    if not wallet_id or not owner:
        continue
    # Only Primary wallets get welcome bonus
    bonus_flag = '--welcome-bonus' if wallet_type == 'Primary' else ''
    pk_flag = f'--public-key {public_key}' if public_key else ''
    print(f'PROVISION|{wallet_id}|{owner}|{wallet_type}|{bonus_flag}|{pk_flag}')
    provision_count += 1

# Output summary to stderr
print(f'Total wallets in snapshot: {len(wallets)}', file=sys.stderr)
print(f'Skipping (genesis): {skip_count}', file=sys.stderr)
print(f'To provision: {provision_count}', file=sys.stderr)

# Output CBE payroll commands
print(f'', file=sys.stderr)
CBE_ATOM_SCALE = 10 ** 10  # 8-decimal (snapshot) → 18-decimal (payroll)
print(f'=== CBE PAYROLL ===', file=sys.stderr)
print(f'Total CBE transfers to replay as payroll: {len(cbe_snapshot)}', file=sys.stderr)
total_cbe_8dec = sum(int(t.get('amount', 0)) for t in cbe_snapshot)
total_cbe_18dec = total_cbe_8dec * CBE_ATOM_SCALE
print(f'Total CBE (8-dec atoms): {total_cbe_8dec} = {total_cbe_8dec / 1e8:.0f} CBE', file=sys.stderr)
print(f'Total CBE (18-dec atoms): {total_cbe_18dec}', file=sys.stderr)

for t in cbe_snapshot:
    to_wallet = t.get('to', '')
    amount_8dec = int(t.get('amount', '0'))
    amount_18dec = amount_8dec * CBE_ATOM_SCALE
    print(f'PAYROLL|{to_wallet}|{amount_18dec}')
" > /tmp/replay_commands.txt 2>&1

# Parse and show summary
grep -v "^PROVISION\|^PAYROLL" /tmp/replay_commands.txt || true

# Extract provision commands
PROVISION_TOTAL=$(grep -c "^PROVISION" /tmp/replay_commands.txt || echo 0)
PAYROLL_TOTAL=$(grep -c "^PAYROLL" /tmp/replay_commands.txt || echo 0)

log "Wallets to provision: $PROVISION_TOTAL"
log "Payroll allocations: $PAYROLL_TOTAL"

if [ "$DRY_RUN" = "--dry-run" ]; then
    log ""
    log "[DRY RUN] Would provision $PROVISION_TOTAL wallets and run $PAYROLL_TOTAL payroll allocations"
    log "Sample provision commands:"
    grep "^PROVISION" /tmp/replay_commands.txt | head -5 | while IFS='|' read -r _ wid owner wtype bonus pk; do
        echo "  zhtp-cli -s $SERVER wallet provision --wallet-id $wid --owner $owner --wallet-type $wtype $bonus $pk"
    done
    log "Sample payroll commands:"
    grep "^PAYROLL" /tmp/replay_commands.txt | head -5 | while IFS='|' read -r _ to amount; do
        echo "  zhtp-cli -s $SERVER cbe payroll --contract-id <TBD> --collaborator $to --amount-cbe $amount --deliverable-hash <TBD>"
    done
    exit 0
fi

# ============================================================================
# STEP 2a: Execute wallet provisioning on g1
# ============================================================================
log ""
log "=== Provisioning wallets ==="

count=0
errors=0

grep "^PROVISION" /tmp/replay_commands.txt | while IFS='|' read -r _ wid owner wtype bonus pk; do
    count=$((count + 1))
    # Build command
    cmd="/opt/zhtp/zhtp-cli -s 127.0.0.1:9334 wallet provision --wallet-id $wid --owner $owner --wallet-type $wtype"
    [ -n "$bonus" ] && cmd="$cmd $bonus"
    [ -n "$pk" ] && cmd="$cmd $pk"

    result=$(ssh zhtp-g1 "$cmd" 2>&1) || {
        err "[$count/$PROVISION_TOTAL] Failed: $wid ($wtype) - $result"
        errors=$((errors + 1))
        continue
    }
    ok "[$count/$PROVISION_TOTAL] $wtype wallet $wid for $owner"

    # Don't overwhelm the node — batch 10 then pause
    if [ $((count % 10)) -eq 0 ]; then
        sleep 2
    fi
done

log "Wallet provisioning complete: $count wallets, $errors errors"

# ============================================================================
# STEP 3: Run CBE payroll allocations
# ============================================================================
log ""
log "=== STEP 3: CBE payroll allocations ==="
log "NOTE: Payroll requires an employment contract. Creating genesis employment contract first."

# The CBE payroll system needs:
# 1. CBE token initialized (init-pools)
# 2. Employment contract created for the signer
# 3. ProcessPayroll transaction for each payment
#
# The signer for all 15 transfers was b8b099a1... which is the CBE holder wallet.
# We need to run payroll from the council member's keystore.

count=0
errors=0

grep "^PAYROLL" /tmp/replay_commands.txt | while IFS='|' read -r _ to amount; do
    count=$((count + 1))
    # Generate a deterministic contract_id from the collaborator wallet
    contract_id=$(echo -n "replay_contract_$to" | sha256sum | cut -c1-64)
    deliverable_hash=$(echo -n "replay_deliverable_${count}_$to" | sha256sum | cut -c1-64)

    cmd="$CLI -s $SERVER cbe payroll --contract-id $contract_id --amount-cbe $amount --collaborator $to --deliverable-hash $deliverable_hash --keystore /tmp/council_keystore"

    result=$(ssh zhtp-g1 "$cmd" 2>&1) || {
        err "[$count/$PAYROLL_TOTAL] Failed payroll to $to amount=$amount - $result"
        errors=$((errors + 1))
        continue
    }
    ok "[$count/$PAYROLL_TOTAL] Payroll $amount to ${to:0:16}..."

    sleep 2
done

log "Payroll replay complete: $count allocations, $errors errors"

# ============================================================================
# STEP 4: Verify
# ============================================================================
log ""
log "=== STEP 4: Verification ==="
ssh zhtp-g1 "/opt/zhtp/zhtp-cli -s 127.0.0.1:9334 blockchain status" 2>&1 || log "Could not get blockchain status"

log ""
log "=== CHAIN REPLAY COMPLETE ==="
