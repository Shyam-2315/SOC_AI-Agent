#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ai-soc-linux-collector"
SERVICE_NAME="ai-soc-linux-collector"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MODE="install"

for arg in "$@"; do
  case "$arg" in
    --repair) MODE="repair" ;;
    --status) MODE="status" ;;
    --test) MODE="test" ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 1; }
}

need_cmd "$PYTHON_BIN"
need_cmd systemctl

copy_files() {
  $SUDO mkdir -p "$INSTALL_DIR"
  $SUDO cp "$SOURCE_DIR"/linux_collector.py "$INSTALL_DIR"/
  $SUDO cp "$SOURCE_DIR"/requirements.txt "$INSTALL_DIR"/
  $SUDO cp "$SOURCE_DIR"/config.example.json "$INSTALL_DIR"/
  $SUDO cp "$SOURCE_DIR"/install.sh "$INSTALL_DIR"/
  $SUDO cp "$SOURCE_DIR"/uninstall.sh "$INSTALL_DIR"/
  $SUDO cp "$SOURCE_DIR"/README.md "$INSTALL_DIR"/
  $SUDO mkdir -p "$INSTALL_DIR/logs"
}

ensure_venv() {
  if [ ! -d "$INSTALL_DIR/.venv" ]; then
    $SUDO "$PYTHON_BIN" -m venv "$INSTALL_DIR/.venv"
  fi
  $SUDO "$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
  $SUDO "$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
}

validate_config() {
  local config="$INSTALL_DIR/config.json"
  [ -f "$config" ] || return 1
  "$INSTALL_DIR/.venv/bin/python" - <<'PY' "$config"
import json,sys
p=sys.argv[1]
with open(p,'r',encoding='utf-8') as f:
    c=json.load(f)
for key in ("backend_url","collector_token","source_name"):
    if not c.get(key):
        raise SystemExit(1)
print("ok")
PY
}

write_or_update_config() {
  local config="$INSTALL_DIR/config.json"
  if [ -f "$config" ] && [ "$MODE" != "repair" ]; then
    if validate_config >/dev/null 2>&1; then
      echo "config exists: yes"
      return
    fi
    read -r -p "config.json is invalid. Update it now? [y/N]: " ans
    case "${ans:-N}" in
      y|Y|yes|YES) ;;
      *) echo "config.json was not modified"; exit 1 ;;
    esac
  fi

  local default_backend="http://127.0.0.1:8000"
  local default_source
  default_source="$(hostname 2>/dev/null || echo linux-host)"
  local existing_token=""
  if [ -f "$config" ]; then
    default_backend="$($INSTALL_DIR/.venv/bin/python - <<'PY' "$config"
import json,sys
c=json.load(open(sys.argv[1],'r',encoding='utf-8'))
print(c.get('backend_url') or 'http://127.0.0.1:8000')
PY
)"
    default_source="$($INSTALL_DIR/.venv/bin/python - <<'PY' "$config"
import json,sys,os
c=json.load(open(sys.argv[1],'r',encoding='utf-8'))
print(c.get('source_name') or os.uname().nodename)
PY
)"
    existing_token="$($INSTALL_DIR/.venv/bin/python - <<'PY' "$config"
import json,sys
c=json.load(open(sys.argv[1],'r',encoding='utf-8'))
print(c.get('collector_token') or '')
PY
)"
  fi

  read -r -p "Backend URL [$default_backend]: " backend_url
  backend_url="${backend_url:-$default_backend}"
  if [ -n "$existing_token" ]; then
    read -r -p "Collector token [Enter keeps existing]: " collector_token
    collector_token="${collector_token:-$existing_token}"
  else
    read -r -p "Collector token: " collector_token
  fi
  read -r -p "Source name [$default_source]: " source_name
  source_name="${source_name:-$default_source}"

  if [ -z "$backend_url" ] || [ -z "$collector_token" ] || [ -z "$source_name" ]; then
    echo "backend_url, collector_token, and source_name are required" >&2
    exit 1
  fi

  $SUDO "$INSTALL_DIR/.venv/bin/python" - <<'PY' "$config" "$backend_url" "$collector_token" "$source_name"
import json,sys
path,backend,token,source=sys.argv[1:5]
cfg={
  "backend_url": backend,
  "collector_token": token,
  "source_name": source,
  "polling_interval_seconds": 15,
  "batch_size": 50,
  "logs_directory": "logs",
  "state_file": "state.json",
  "auth_log_paths": ["/var/log/auth.log", "/var/log/secure"],
  "watched_files": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"],
  "enable_process_monitoring": True,
  "enable_docker_monitoring": True,
  "enable_file_integrity": True,
  "heartbeat_interval_seconds": 300,
}
with open(path,'w',encoding='utf-8') as f:
    json.dump(cfg,f,indent=2)
print("wrote")
PY
  $SUDO chmod 600 "$config"
  echo "config exists: yes"
}

install_service() {
  $SUDO tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=AI SOC Linux Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python $INSTALL_DIR/linux_collector.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable "$SERVICE_NAME" >/dev/null
  $SUDO systemctl restart "$SERVICE_NAME"
}

backend_reachable() {
  local config="$INSTALL_DIR/config.json"
  [ -f "$config" ] || return 1
  local backend
  backend="$($INSTALL_DIR/.venv/bin/python - <<'PY' "$config"
import json,sys
print((json.load(open(sys.argv[1],encoding='utf-8')).get('backend_url') or '').rstrip('/'))
PY
)"
  [ -n "$backend" ] || return 1
  curl -fsS --max-time 6 "$backend/health/ready" >/dev/null 2>&1
}

print_status() {
  local enabled="no"
  local running="no"
  if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then enabled="yes"; fi
  if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then running="yes"; fi
  echo "service enabled: $enabled"
  echo "service running: $running"

  if validate_config >/dev/null 2>&1; then
    echo "config exists: yes"
  else
    echo "config exists: no"
  fi

  if backend_reachable; then
    echo "backend reachable: yes"
  else
    echo "backend reachable: no"
  fi

  echo "last collector logs:"
  if [ -f "$INSTALL_DIR/logs/collector.log" ]; then
    tail -n 20 "$INSTALL_DIR/logs/collector.log"
  else
    echo "collector log not found"
  fi
}

run_test() {
  if $SUDO "$INSTALL_DIR/.venv/bin/python" "$INSTALL_DIR/linux_collector.py" --test; then
    echo "test event accepted"
  else
    echo "test event rejected"
    exit 1
  fi
}

case "$MODE" in
  status)
    print_status
    ;;
  test)
    print_status
    run_test
    ;;
  install|repair)
    copy_files
    ensure_venv
    write_or_update_config
    install_service
    print_status
    ;;
esac
