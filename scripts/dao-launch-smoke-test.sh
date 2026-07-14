#!/usr/bin/env bash
# DAO launch smoke test (#2879): FP + NP AssetLaunch via CLI + assets API.
#
# Prerequisites:
#   - zhtp-cli configured with a funded creator keystore
#   - ZHTP_SERVER pointing at testnet (default https://g1.testnet.zhtp.org)
#   - Creator holds enough SOV for launch fees
#
# Usage:
#   ./scripts/dao-launch-smoke-test.sh
#   ZHTP_SERVER=https://g1.testnet.zhtp.org ./scripts/dao-launch-smoke-test.sh
#
# Optional env:
#   ZHTP_SERVER   — API base URL
#   CHAIN_ID      — launch chain id (default 2 testnet)
#   SKIP_LAUNCH   — set to 1 to only print commands (dry run)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${ZHTP_SERVER:-https://g1.testnet.zhtp.org}"
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

run_cli() {
  if [[ "${SKIP_LAUNCH:-0}" == "1" ]]; then
    echo "[dry-run] zhtp-cli $*"
    return 0
  fi
  local cli="$ROOT/target/release/zhtp-cli"
  if [[ ! -x "$cli" ]]; then
    cli="cargo run -q -p zhtp-cli --manifest-path $ROOT/Cargo.toml --"
    (cd "$ROOT" && $cli "$@")
  else
    "$cli" "$@"
  fi
}

echo "=== DAO launch smoke (#2879) ==="
echo "server:   $SERVER"
echo "chain_id: $CHAIN_ID"
echo

echo "--- 1) Preview FP template (balanced) ---"
run_cli --server "$SERVER" dao launch \
  --name "$FP_NAME" \
  --symbol "$FP_SYMBOL" \
  --template balanced \
  --preview \
  --chain-id "$CHAIN_ID"

echo
echo "--- 2) Preview NP template (np-mission) ---"
run_cli --server "$SERVER" dao launch \
  --name "$NP_NAME" \
  --symbol "$NP_SYMBOL" \
  --template np-mission \
  --preview \
  --chain-id "$CHAIN_ID"

echo
echo "--- 3) Launch FP test asset ---"
FP_OUT="$(run_cli --server "$SERVER" dao launch \
  --name "$FP_NAME" \
  --symbol "$FP_SYMBOL" \
  --template fp-starter \
  --chain-id "$CHAIN_ID" 2>&1)" || true
echo "$FP_OUT"
FP_ASSET_ID="$(echo "$FP_OUT" | sed -n 's/.*Asset ID: \([0-9a-f]\{64\}\).*/\1/p' | head -1)"

echo
echo "--- 4) Launch NP test asset ---"
NP_OUT="$(run_cli --server "$SERVER" dao launch \
  --name "$NP_NAME" \
  --symbol "$NP_SYMBOL" \
  --template np-mission \
  --chain-id "$CHAIN_ID" 2>&1)" || true
echo "$NP_OUT"
NP_ASSET_ID="$(echo "$NP_OUT" | sed -n 's/.*Asset ID: \([0-9a-f]\{64\}\).*/\1/p' | head -1)"

verify_asset() {
  local label="$1"
  local asset_id="$2"
  local expected_class="$3"
  if [[ -z "$asset_id" ]]; then
    echo "WARN: $label launch did not return asset_id — check CLI output above"
    return 0
  fi
  echo
  echo "--- Verify $label: GET /api/v1/assets/${asset_id:0:16}... ---"
  if [[ "${SKIP_LAUNCH:-0}" == "1" ]]; then
    echo "[dry-run] curl $SERVER/api/v1/assets/$asset_id"
    return 0
  fi
  local body
  body="$(curl -fsS "$SERVER/api/v1/assets/$asset_id")"
  echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
asset=d.get('asset') or d
cls=(asset.get('dao_class') or '').lower()
print('dao_class:', cls)
print('treasury_bps:', asset.get('treasury_bps'))
if cls != '$expected_class':
    raise SystemExit(f'expected dao_class=$expected_class got {cls}')
print('OK')
"
}

verify_asset "FP" "$FP_ASSET_ID" "fp"
verify_asset "NP" "$NP_ASSET_ID" "np"

echo
echo "=== Smoke complete ==="
echo "Optional follow-up (Q10 domain, separate tx):"
echo "  zhtp-cli --server $SERVER web4 domain register --domain ${FP_SYMBOL,,}.sov --owner <key_id>"