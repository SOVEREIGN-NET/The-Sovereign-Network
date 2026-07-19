#!/usr/bin/env bash
#
# Backup validator keystores into a local credentials vault.
#
# Usage:
#   scripts/backup-testnet-keystores.sh <vault-dir>
#   scripts/backup-testnet-keystores.sh ~/zhtp-testnet-vault --include-retired
#
# Pulls /opt/zhtp/.zhtp/keystore from each host. Does not contain genesis
# council keys — copy those manually (see docs/ops/testnet-credentials-vault.md).
#
set -euo pipefail

VAULT="${1:?usage: $0 <vault-dir> [--include-retired]}"
INCLUDE_RETIRED=0
[[ "${2:-}" == "--include-retired" ]] && INCLUDE_RETIRED=1

ACTIVE=(
  "g1|zhtp-g1|77.42.37.161|59e07e17556e2955581443538839d576974e4f8a9af424c0a2cc7df79c995c9d"
  "g2|zhtp-g2|77.42.74.80|f37a307761b863130adb6129f16c269af4e395eb3d4b14b070a756bef282c07b"
  "g3|zhtp-g3|178.105.9.247|bf409db91ad276fa35e8af9c78a48facdfba99eb95fcbf01719310e91c558a9c"
)
# Offline / retired hosts — only with --include-retired. Not deploy targets.
RETIRED=(
  "g4|zhtp-g4|148.113.140.176|14225182b8140220c2adf3e61471ba5f0117f863408ee6b2b86cff4d0f679cef"
  "g5|zhtp-g5|51.75.62.133|3218b9025f1b7c678e115c094a73d3e077801f60501452babd43c7a32ecdf284"
  "gateway|zhtp-gateway|91.98.113.188|"
  "gateway2|zhtp-gateway-2|57.128.30.74|"
)

REMOTE_KEYSTORE=/opt/zhtp/.zhtp/keystore
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

backup_host() {
  local label=$1 alias=$2 ip=$3 did=$4
  local dest="$VAULT/validators/${label}-${ip}"
  [[ "$label" == g4 || "$label" == g5 || "$label" == gateway* ]] && dest="$VAULT/retired/${label}-${ip}"

  mkdir -p "$dest"
  log "backing up $alias ($ip) -> $dest"

  if ! ssh -o ConnectTimeout=15 "$alias" "test -d $REMOTE_KEYSTORE" 2>/dev/null; then
    log "  WARN: no keystore on $alias ($REMOTE_KEYSTORE)"
    return 0
  fi

  rsync -az "$alias:$REMOTE_KEYSTORE/" "$dest/keystore/"
  cat >"$dest/meta.env" <<EOF
# Generated $TS — no private key material in this file
HOST_ALIAS=$alias
HOST_IP=$ip
EXPECTED_DID=$did
REMOTE_KEYSTORE=$REMOTE_KEYSTORE
EOF
  log "  ok ($(find "$dest/keystore" -type f 2>/dev/null | wc -l) files)"
}

mkdir -p "$VAULT/validators" "$VAULT/council/bootstrap-council" "$VAULT/ops"
log "vault: $VAULT"

for row in "${ACTIVE[@]}"; do
  IFS='|' read -r label alias ip did <<<"$row"
  backup_host "$label" "$alias" "$ip" "$did"
done

if [[ $INCLUDE_RETIRED -eq 1 ]]; then
  mkdir -p "$VAULT/retired"
  for row in "${RETIRED[@]}"; do
    IFS='|' read -r label alias ip did <<<"$row"
    backup_host "$label" "$alias" "$ip" "$did"
  done
fi

# Machine-readable inventory
python3 - <<'PY' "$VAULT" "$TS"
import json, sys
from pathlib import Path
vault, ts = Path(sys.argv[1]), sys.argv[2]
inv = {"backed_up_at": ts, "hosts": []}
for meta in sorted(vault.rglob("meta.env")):
    d = {}
    for line in meta.read_text().splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        d[k.strip()] = v.strip()
    d["path"] = str(meta.parent.relative_to(vault))
    ks = meta.parent / "keystore"
    d["keystore_files"] = sorted(p.name for p in ks.glob("*")) if ks.is_dir() else []
    inv["hosts"].append(d)
(vault / "inventory.json").write_text(json.dumps(inv, indent=2) + "\n")
print(f"inventory.json written ({len(inv['hosts'])} hosts)")
PY

log "done — copy council keystore manually to $VAULT/council/bootstrap-council/"
log "see docs/ops/testnet-credentials-vault.md"