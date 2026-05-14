#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="ai-soc-linux-collector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 is required but was not found on PATH." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for service installation." >&2
  exit 1
fi

cd "$AGENT_DIR"

if [ ! -d ".venv" ]; then
  "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f config.json ]; then
  read -r -p "Backend URL [http://127.0.0.1]: " BACKEND_URL
  BACKEND_URL="${BACKEND_URL:-http://127.0.0.1}"
  read -r -p "Collector token: " COLLECTOR_TOKEN
  if [ -z "$COLLECTOR_TOKEN" ]; then
    echo "Collector token is required. Create a Linux collector in the AI SOC UI first." >&2
    exit 1
  fi
  DEFAULT_SOURCE="$(hostname 2>/dev/null || echo linux-host)"
  read -r -p "Source name [${DEFAULT_SOURCE}]: " SOURCE_NAME
  SOURCE_NAME="${SOURCE_NAME:-$DEFAULT_SOURCE}"

  sed \
    -e "s|http://127.0.0.1|${BACKEND_URL}|g" \
    -e "s|paste-collector-token-here|${COLLECTOR_TOKEN}|g" \
    -e "s|linux-host-01|${SOURCE_NAME}|g" \
    config.example.json > config.json
  chmod 600 config.json
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

$SUDO tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=AI SOC Linux Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${AGENT_DIR}
ExecStart=${AGENT_DIR}/.venv/bin/python ${AGENT_DIR}/linux_collector.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME"
$SUDO systemctl restart "$SERVICE_NAME"
$SUDO systemctl status "$SERVICE_NAME" --no-pager

echo
echo "Installed ${SERVICE_NAME}."
echo "Run a manual test with: cd ${AGENT_DIR} && .venv/bin/python linux_collector.py --test"
