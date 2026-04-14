#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/target/browser-extension"
PACKAGE_NAME="zhtp-browser-bridge-chrome"
STAGE_DIR="${TARGET_DIR}/${PACKAGE_NAME}"
ARCHIVE_PATH="${TARGET_DIR}/${PACKAGE_NAME}.zip"
CHECKSUM_PATH="${TARGET_DIR}/${PACKAGE_NAME}.sha256"

rm -rf "${STAGE_DIR}" "${ARCHIVE_PATH}" "${CHECKSUM_PATH}"
mkdir -p "${STAGE_DIR}"

install -m 0644 "${ROOT_DIR}/browser-extension/manifest.json" "${STAGE_DIR}/manifest.json"
install -m 0644 "${ROOT_DIR}/browser-extension/background.js" "${STAGE_DIR}/background.js"
install -m 0644 "${ROOT_DIR}/browser-extension/compat.js" "${STAGE_DIR}/compat.js"
install -m 0644 "${ROOT_DIR}/browser-extension/popup.html" "${STAGE_DIR}/popup.html"
install -m 0644 "${ROOT_DIR}/browser-extension/popup.css" "${STAGE_DIR}/popup.css"
install -m 0644 "${ROOT_DIR}/browser-extension/popup.js" "${STAGE_DIR}/popup.js"
install -m 0644 "${ROOT_DIR}/browser-extension/viewer.html" "${STAGE_DIR}/viewer.html"
install -m 0644 "${ROOT_DIR}/browser-extension/viewer.css" "${STAGE_DIR}/viewer.css"
install -m 0644 "${ROOT_DIR}/browser-extension/viewer.js" "${STAGE_DIR}/viewer.js"
install -m 0644 "${ROOT_DIR}/browser-extension/README.md" "${STAGE_DIR}/README.md"

(
  cd "${TARGET_DIR}"
  zip -rq "${PACKAGE_NAME}.zip" "${PACKAGE_NAME}"
  sha256sum "${PACKAGE_NAME}.zip" > "${PACKAGE_NAME}.sha256"
)
