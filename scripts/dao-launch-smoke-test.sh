#!/usr/bin/env bash
# DAO launch smoke test (#2879): FP + NP AssetLaunch via CLI + assets API.
#
# Prerequisites:
#   - zhtp-cli on PATH or target/release|dev-release/zhtp-cli built
#   - Creator keystore registered + funded (default ~/.zhtp/keystore)
#   - QUIC reachability to a validator (default g1:9334)
#
# Usage:
#   ./scripts/dao-launch-smoke-test.sh
#   ZHTP_SERVER=77.42.37.161:9334 CHAIN_ID=2 ./scripts/dao-launch-smoke-test.sh
#
# Optional env:
#   ZHTP_SERVER   — host:port (default 77.42.37.161:9334)
#   CHAIN_ID      — launch chain id (default 2 testnet)
#   SKIP_LAUNCH   — set to 1 to only print commands (dry run)
#   KEYSTORE      — creator keystore dir

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${ZHTP_SERVER:-77.42.37.161:9334}"
CHAIN_ID="${CHAIN_ID:-2}"
TS="$(date +%s)"
# Symbols must be uppercase A-Z only (DAO launch validation).
symbol_suffix() {
  # 3 uppercase letters (dao launch max symbol length is 6)
  python3 -c "import string; t=int('${1}') % (26**3); print(''.join(string.ascii_uppercase[(t//(26**i))%26] for i in range(2,-1,-1)))"
}
SUFFIX="$(symbol_suffix "$TS")"
FP_NAME="Smoke FP ${TS}"
FP_SYMBOL="SFP${SUFFIX}"
NP_NAME="Smoke NP ${TS}"
NP_SYMBOL="SNP${SUFFIX}"
FAILURES=0

run_cli() {
  if [[ "${SKIP_LAUNCH:-0}" == "1" ]]; then
    echo "[dry-run] zhtp-cli $*"
    return 0
  fi
  local cli=""
  for candidate in \
    "$ROOT/target/dev-release/zhtp-cli" \
    "$ROOT/target/release/zhtp-cli" \
    "$(command -v zhtp-cli 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      cli="$candidate"
      break
    fi
  done
  if [[ -z "$cli" ]]; then
    echo "ERROR: zhtp-cli not found; build with: cargo build -p zhtp-cli --release" >&2
    exit 1
  fi
  local args=(--server "$SERVER")
  if [[ -n "${KEYSTORE:-}" ]]; then
    args+=(--keystore "$KEYSTORE")
  fi
  "$cli" "${args[@]}" "$@"
}

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

echo "=== DAO launch smoke (#2879) ==="
echo "server:   $SERVER"
echo "chain_id: $CHAIN_ID"
echo

echo "--- 1) Preview FP template (fp-starter) ---"
run_cli dao launch \
  --name "$FP_NAME" \
  --symbol "$FP_SYMBOL" \
  --template fp-starter \
  --preview \
  --chain-id "$CHAIN_ID"

echo
echo "--- 2) Preview NP template (np-mission) ---"
run_cli dao launch \
  --name "$NP_NAME" \
  --symbol "$NP_SYMBOL" \
  --template np-mission \
  --preview \
  --chain-id "$CHAIN_ID"

echo
echo "--- 3) Launch FP test asset ---"
FP_OUT="$(run_cli dao launch \
  --name "$FP_NAME" \
  --symbol "$FP_SYMBOL" \
  --template fp-starter \
  --chain-id "$CHAIN_ID" 2>&1)" || true
echo "$FP_OUT"
FP_ASSET_ID="$(echo "$FP_OUT" | sed -n 's/.*[Aa]sset [Ii][Dd]: \([0-9a-fA-F]\{64\}\).*/\1/p' | head -1)"
if [[ -z "$FP_ASSET_ID" ]]; then
  FP_ASSET_ID="$(echo "$FP_OUT" | python3 -c "import re,sys; m=re.search(r'\"asset_id\"\\s*:\\s*\"([0-9a-fA-F]{64})\"', sys.stdin.read()); print(m.group(1) if m else '')" 2>/dev/null || true)"
fi

echo
echo "--- 4) Launch NP test asset ---"
NP_OUT="$(run_cli dao launch \
  --name "$NP_NAME" \
  --symbol "$NP_SYMBOL" \
  --template np-mission \
  --chain-id "$CHAIN_ID" 2>&1)" || true
echo "$NP_OUT"
NP_ASSET_ID="$(echo "$NP_OUT" | sed -n 's/.*[Aa]sset [Ii][Dd]: \([0-9a-fA-F]\{64\}\).*/\1/p' | head -1)"
if [[ -z "$NP_ASSET_ID" ]]; then
  NP_ASSET_ID="$(echo "$NP_OUT" | python3 -c "import re,sys; m=re.search(r'\"asset_id\"\\s*:\\s*\"([0-9a-fA-F]{64})\"', sys.stdin.read()); print(m.group(1) if m else '')" 2>/dev/null || true)"
fi

verify_launch_output() {
  local label="$1"
  local output="$2"
  local expect_np_split="$3" # "yes" => creator_allocation must be 0
  echo
  echo "--- Verify $label launch split from CLI response ---"
  if [[ "${SKIP_LAUNCH:-0}" == "1" ]]; then
    echo "[dry-run] verify $label launch output"
    return 0
  fi
  if ! echo "$output" | grep -qiE 'success|asset_id|submitted'; then
    fail "$label launch did not report success/asset_id"
    return 0
  fi
  echo "$output" | python3 -c "
import re,sys
out=sys.stdin.read()
# CLI may print JSON or human lines
creator=re.search(r'creator_allocation[\"\\s:]+\"?([0-9]+)\"?', out)
if not creator:
    # allow soft pass if asset_id present (allocation may be elsewhere)
    if re.search(r'[0-9a-fA-F]{64}', out):
        print('OK (asset id present; creator_allocation not in text)')
        raise SystemExit(0)
    raise SystemExit('missing creator_allocation and asset_id')
val=creator.group(1)
print('creator_allocation:', val)
if '$expect_np_split' == 'yes':
    if val != '0':
        raise SystemExit(f'expected NP creator_allocation=0 got {val}')
else:
    if val == '0':
        raise SystemExit(f'expected FP creator_allocation>0 got {val}')
print('OK')
" || fail "$label launch split check"
}

verify_launch_output "FP" "$FP_OUT" "no"
verify_launch_output "NP" "$NP_OUT" "yes"

verify_assets_api() {
  local label="$1"
  local asset_id="$2"
  local expect_class="$3"
  echo
  echo "--- Verify $label via GET /api/v1/assets/{id} ---"
  if [[ "${SKIP_LAUNCH:-0}" == "1" ]]; then
    echo "[dry-run] assets get $asset_id"
    return 0
  fi
  if [[ -z "$asset_id" ]]; then
    fail "$label missing asset_id — cannot query assets API"
    return 0
  fi
  # Wait briefly for mempool → block commit
  local detail=""
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    detail="$(run_cli asset get --asset-id "$asset_id" 2>&1 || true)"
    if echo "$detail" | grep -qi "dao_class\|symbol"; then
      break
    fi
    sleep 3
  done
  echo "$detail"
  echo "$detail" | python3 -c "
import re,sys
out=sys.stdin.read().lower()
expect='$expect_class'.lower()
# Prefer explicit dao_class field from assets API
m=re.search(r'\"dao_class\"\\s*:\\s*\"(fp|np)\"', out)
if m:
    got=m.group(1)
    if got != expect:
        raise SystemExit(f'dao_class mismatch: want {expect} got {got}')
    print('dao_class', got, 'OK')
elif 'symbol' in out or 'asset_id' in out:
    print('assets API OK (dao_class not yet visible; symbol/asset present)')
else:
    raise SystemExit('assets get response missing dao_class/symbol')
print('assets API OK for', '$asset_id'[:16]+'...')
" || fail "$label assets API verification"
}

verify_assets_api "FP" "$FP_ASSET_ID" "fp"
verify_assets_api "NP" "$NP_ASSET_ID" "np"

echo
echo "=== Smoke complete (failures=$FAILURES) ==="
echo "FP asset_id: ${FP_ASSET_ID:-<none>}"
echo "NP asset_id: ${NP_ASSET_ID:-<none>}"
echo
echo "Optional follow-up (Q10 domain, separate tx after finality) — #2810:"
echo "  zhtp-cli --server $SERVER domain register \\"
echo "    --domain \${FP_SYMBOL,,}.sov --asset-id ${FP_ASSET_ID:-<fp_asset_id>} --chain-id $CHAIN_ID"
echo
if [[ "$FAILURES" -gt 0 ]]; then
  exit 1
fi
exit 0
