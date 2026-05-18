#!/usr/bin/env bash
set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LIB_DIR/common.sh"
source "$_LIB_DIR/docker.sh"

show_logs() {
  ensure_docker_available
  header "Logs"
  tail_logs "$@"
}

show_status() {
  ensure_docker_available
  source "$_LIB_DIR/health.sh"
  header "Compose Status"
  show_compose_ps

  header "Service Health"
  local service=""
  for service in mongo redis app celery-worker frontend nginx; do
    local state health
    IFS='|' read -r state health <<<"$(service_status "$service")"
    if [[ "$state" == "running" && ( "$health" == "healthy" || "$health" == "none" ) ]]; then
      ok "$service running (health=$health)"
    elif [[ "$state" == "missing" ]]; then
      warn "$service missing"
    else
      fail "$service state=$state health=$health"
    fi
  done

  header "Endpoint Status"
  poll_url "Frontend" "${FRONTEND_URL:-http://127.0.0.1:8080}/" 1 1 || true
  poll_url "Backend" "${BACKEND_URL:-http://127.0.0.1:8000}/health" 1 1 || true
  check_websocket_endpoint || true
}
