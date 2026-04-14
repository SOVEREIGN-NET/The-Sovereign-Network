#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install-zhtp-daemon-linux.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_DIR="${ROOT_DIR}"
BIN_SRC="${PACKAGE_DIR}/bin/zhtp-daemon"
CONFIG_SRC="${PACKAGE_DIR}/config/config.toml"
SERVICE_SRC="${PACKAGE_DIR}/systemd/zhtp-daemon.service"

BIN_DST="/usr/local/bin/zhtp-daemon"
SERVICE_DST="/etc/systemd/system/zhtp-daemon.service"
STATE_DIR="/var/lib/zhtp-daemon"
SERVICE_USER="zhtp-daemon"
SERVICE_GROUP="zhtp-daemon"

if [[ ! -x "${BIN_SRC}" ]]; then
  echo "Missing binary at ${BIN_SRC}" >&2
  exit 1
fi

if [[ ! -f "${CONFIG_SRC}" ]]; then
  echo "Missing config at ${CONFIG_SRC}" >&2
  exit 1
fi

if [[ ! -f "${SERVICE_SRC}" ]]; then
  echo "Missing systemd unit at ${SERVICE_SRC}" >&2
  exit 1
fi

if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd \
    --system \
    --home "${STATE_DIR}" \
    --create-home \
    --shell /usr/sbin/nologin \
    --gid "${SERVICE_GROUP}" \
    "${SERVICE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${STATE_DIR}"
install -m 0755 "${BIN_SRC}" "${BIN_DST}"

if [[ ! -f "${STATE_DIR}/config.toml" ]]; then
  install -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0640 "${CONFIG_SRC}" "${STATE_DIR}/config.toml"
else
  echo "Keeping existing config at ${STATE_DIR}/config.toml"
fi

install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

systemctl daemon-reload
systemctl enable --now zhtp-daemon
systemctl status --no-pager zhtp-daemon

cat <<EOF

Installed zhtp-daemon.

- binary: ${BIN_DST}
- service: ${SERVICE_DST}
- state dir: ${STATE_DIR}
- config: ${STATE_DIR}/config.toml

Inspect logs with:
  journalctl -u zhtp-daemon -f
EOF
