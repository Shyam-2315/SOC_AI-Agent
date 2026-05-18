#!/usr/bin/env bash
set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LIB_DIR/common.sh"

require_docker_runtime() {
  require_command docker
  if ! docker info >/dev/null 2>&1; then
    fail "Docker is not running."
    exit 1
  fi
  ok "Docker engine reachable"
}

require_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    fail "docker compose plugin not available"
    exit 1
  fi
  ok "Docker Compose available"
}

check_wsl_compat() {
  if is_wsl; then
    ok "WSL environment detected"
  else
    info "Running on Linux (non-WSL)"
  fi
}

port_occupied_by_stack() {
  local port="$1"
  docker ps --format '{{.Names}} {{.Ports}}' | grep -E "[:.]${port}->" | grep -q "ai-soc-platform" 2>/dev/null
}

check_port_free() {
  local port="$1"
  if ss -ltn "( sport = :$port )" | awk 'NR>1 {print}' | grep -q .; then
    if port_occupied_by_stack "$port"; then
      warn "Port $port already in use by existing stack"
      return
    fi
    fail "Port $port is already in use"
    return 1
  fi
  ok "Port $port is free"
}

check_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    fail "Missing $ENV_FILE (copy from backend/.env.example)"
    return 1
  fi
  ok "Environment file found"
}

check_required_directories() {
  local required=("$BACKEND_DIR" "$FRONTEND_DIR" "$BACKEND_DIR/docker" "$BACKEND_DIR/scripts")
  local missing=0
  local dir=""
  for dir in "${required[@]}"; do
    if [[ ! -d "$dir" ]]; then
      fail "Missing directory: $dir"
      missing=1
    fi
  done
  if [[ "$missing" -eq 1 ]]; then
    return 1
  fi
  ok "Required directories are present"
}

check_frontend_dependencies() {
  if [[ ! -f "$FRONTEND_DIR/package.json" ]]; then
    fail "Missing frontend/package.json"
    return 1
  fi
  if [[ -d "$FRONTEND_DIR/node_modules" ]]; then
    ok "Frontend dependencies directory exists"
  else
    warn "frontend/node_modules missing (Docker build installs dependencies)"
  fi
}

check_backend_venv_if_used() {
  if [[ -d "$BACKEND_DIR/.venv" ]]; then
    if [[ -x "$BACKEND_DIR/.venv/bin/python" ]]; then
      ok "Backend virtualenv detected"
    else
      warn "backend/.venv exists but python binary missing"
    fi
  else
    info "No backend virtualenv detected (container runtime path)"
  fi
}

run_prechecks() {
  header "Prechecks"
  require_docker_runtime
  require_compose
  check_wsl_compat
  check_env_file
  check_required_directories
  check_frontend_dependencies
  check_backend_venv_if_used
  check_port_free 8080
  check_port_free 8000
  check_port_free 27017
  check_port_free 6379
}
