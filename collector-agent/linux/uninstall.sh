#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/ai-soc-linux-collector"
SERVICE_NAME="ai-soc-linux-collector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  $SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
fi

if [ -f "$SERVICE_FILE" ]; then
  $SUDO rm -f "$SERVICE_FILE"
fi

if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl daemon-reload
fi

read -r -p "Keep config.json, state.json, and logs directory in $INSTALL_DIR? [Y/n]: " KEEP
KEEP="${KEEP:-Y}"
case "$KEEP" in
  n|N|no|NO)
    $SUDO rm -f "$INSTALL_DIR/config.json" "$INSTALL_DIR/state.json"
    $SUDO rm -rf "$INSTALL_DIR/logs"
    echo "Removed config, state, and logs."
    ;;
  *)
    echo "Kept config, state, and logs."
    ;;
esac

echo "Uninstalled ${SERVICE_NAME}."
