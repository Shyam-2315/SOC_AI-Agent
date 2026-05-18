#!/usr/bin/env bash
set -euo pipefail

if [[ "${AI_SOC_COMMON_SH_LOADED:-0}" -eq 1 ]]; then
  return 0
fi
AI_SOC_COMMON_SH_LOADED=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
ENV_FILE="$BACKEND_DIR/.env"
COMPOSE_FILE_PROD="$BACKEND_DIR/docker-compose.prod.yml"
COMPOSE_FILE_LOCAL="$BACKEND_DIR/docker-compose.local.yml"

MODE="${MODE:-prod}"
DEBUG="${DEBUG:-0}"
SYSLOG_ENABLED_CACHE=""

readonly COLOR_RESET=$'\033[0m'
readonly COLOR_BLUE=$'\033[1;34m'
readonly COLOR_GREEN=$'\033[1;32m'
readonly COLOR_YELLOW=$'\033[1;33m'
readonly COLOR_RED=$'\033[1;31m'
readonly COLOR_GRAY=$'\033[0;37m'

timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

print_line() {
  local level="$1"
  local color="$2"
  shift 2
  printf "%s %b[%s]%b %s\n" "$(timestamp)" "$color" "$level" "$COLOR_RESET" "$*"
}

info() { print_line "INFO" "$COLOR_BLUE" "$@"; }
ok() { print_line "OK" "$COLOR_GREEN" "$@"; }
warn() { print_line "WARN" "$COLOR_YELLOW" "$@"; }
fail() { print_line "FAIL" "$COLOR_RED" "$@"; }

header() {
  printf "\n%b== %s ==%b\n" "$COLOR_GRAY" "$*" "$COLOR_RESET"
}

env_value() {
  local key="$1"
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  awk -F= -v key="$key" '$1 == key {print $2}' "$ENV_FILE" | tail -n1 | tr -d '"' | tr -d "'"
}

is_wsl() {
  grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null
}

use_local_override() {
  [[ "${MODE}" == "dev" ]]
}

compose() {
  if use_local_override && [[ -f "$COMPOSE_FILE_LOCAL" ]]; then
    docker compose -f "$COMPOSE_FILE_PROD" -f "$COMPOSE_FILE_LOCAL" "$@"
  else
    docker compose -f "$COMPOSE_FILE_PROD" "$@"
  fi
}

require_command() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    fail "Missing required command: $bin"
    exit 1
  fi
}

ensure_docker_available() {
  require_command docker
  if ! docker info >/dev/null 2>&1; then
    fail "Docker is not running."
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose plugin not available"
    exit 1
  fi
}

service_container_id() {
  local service="$1"
  compose ps -q "$service" 2>/dev/null || true
}

service_status() {
  local service="$1"
  local cid state health
  cid="$(service_container_id "$service")"
  if [[ -z "$cid" ]]; then
    printf "missing|missing\n"
    return
  fi
  state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "unknown")"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo "unknown")"
  printf "%s|%s\n" "$state" "$health"
}

syslog_enabled() {
  if [[ -n "$SYSLOG_ENABLED_CACHE" ]]; then
    [[ "$SYSLOG_ENABLED_CACHE" == "true" ]]
    return
  fi
  local val
  val="$(env_value "SYSLOG_ENABLED" | tr '[:upper:]' '[:lower:]')"
  if [[ "$val" == "true" || "$val" == "1" || "$val" == "yes" ]]; then
    SYSLOG_ENABLED_CACHE="true"
  else
    SYSLOG_ENABLED_CACHE="false"
  fi
  [[ "$SYSLOG_ENABLED_CACHE" == "true" ]]
}
