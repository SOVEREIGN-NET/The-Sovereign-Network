#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/target/release"
PACKAGE_NAME="zhtp-daemon-linux-x86_64"
STAGE_DIR="${TARGET_DIR}/${PACKAGE_NAME}"
ARCHIVE_PATH="${TARGET_DIR}/${PACKAGE_NAME}.tar.gz"
CHECKSUM_PATH="${TARGET_DIR}/${PACKAGE_NAME}.sha256"

rm -rf "${STAGE_DIR}" "${ARCHIVE_PATH}" "${CHECKSUM_PATH}"
mkdir -p "${STAGE_DIR}/bin" "${STAGE_DIR}/config" "${STAGE_DIR}/systemd"

install -m 0755 "${TARGET_DIR}/zhtp-daemon" "${STAGE_DIR}/bin/zhtp-daemon"
install -m 0644 "${ROOT_DIR}/zhtp-daemon/README.md" "${STAGE_DIR}/README.md"
install -m 0644 "${ROOT_DIR}/zhtp-daemon/config.example.toml" "${STAGE_DIR}/config/config.toml"
install -m 0644 "${ROOT_DIR}/deploy/zhtp-daemon.service" "${STAGE_DIR}/systemd/zhtp-daemon.service"

tar -C "${TARGET_DIR}" -czf "${ARCHIVE_PATH}" "${PACKAGE_NAME}"
(
  cd "${TARGET_DIR}"
  sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.sha256"
)
