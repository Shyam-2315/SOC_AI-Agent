#!/usr/bin/env bash
set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LIB_DIR/common.sh"

start_stack() {
  local build="${1:-0}"
  local no_deps="${2:-0}"
  local services=("${@:3}")
  local args=(up -d)
  if [[ "$build" -eq 1 ]]; then
    args+=(--build)
  fi
  if [[ "$no_deps" -eq 1 ]]; then
    args+=(--no-deps)
  fi
  if [[ "${#services[@]}" -gt 0 ]]; then
    args+=("${services[@]}")
  fi
  info "Starting services: ${services[*]:-all}"
  compose "${args[@]}"
}

stop_stack() {
  info "Stopping stack"
  compose stop
}

down_stack() {
  info "Stopping and removing containers"
  compose down
}

reset_stack() {
  local remove_volumes="${1:-0}"
  down_stack
  if [[ "$remove_volumes" -eq 1 ]]; then
    warn "Removing volumes for full reset"
    compose down -v --remove-orphans
  fi
}

seed_demo_data() {
  info "Seeding demo data"
  compose exec -T app python scripts/seed_demo.py
  ok "Demo data seeded"
}

clean_local_artifacts() {
  header "Cleanup"
  info "Pruning dangling Docker resources"
  docker image prune -f >/dev/null
  docker container prune -f >/dev/null
  docker network prune -f >/dev/null
  if [[ -d "$FRONTEND_DIR/node_modules/.vite" ]]; then
    rm -rf "$FRONTEND_DIR/node_modules/.vite"
    ok "Cleared frontend Vite cache"
  else
    info "No frontend Vite cache found"
  fi
}

tail_logs() {
  if [[ "$#" -gt 0 ]]; then
    compose logs -f --tail=200 "$@"
  else
    compose logs -f --tail=200
  fi
}

show_compose_ps() {
  compose ps
}
