#!/usr/bin/env bash
#
# RETIRED — testnet has no gateway fleet.
#
# Live rollout surface is validators only (g1–g3):
#   scripts/deploy-validators.sh target/dev-release/zhtp
#
# Historical hosts (zhtp-gateway, zhtp-gateway-2, g4, g5) are offline /
# out of scope. Do not rsync binaries there. Do not "finish" a deploy by
# chasing gateway-2 SSH failures.
#
set -euo pipefail

cat >&2 <<'EOF'
error: gateway deploy is retired

  Testnet nodes: zhtp-g1, zhtp-g2, zhtp-g3 only.
  Use:  scripts/deploy-validators.sh target/dev-release/zhtp

  There are no gateways to upgrade. Stop.
EOF
exit 2
