#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scripts/common.sh"
source "$SCRIPT_DIR/scripts/validate.sh"
source "$SCRIPT_DIR/scripts/docker.sh"
source "$SCRIPT_DIR/scripts/health.sh"
source "$SCRIPT_DIR/scripts/logs.sh"

BUILD=0
DEBUG=0
DO_RESET=0
DO_LOGS=0
DO_STATUS=0
DO_STOP=0
DO_CLEAN=0
FRONTEND_ONLY=0
BACKEND_ONLY=0
REMOVE_VOLUMES=0
SEED_DEMO=0

usage() {
  cat <<'EOF'
Usage: ./start.sh [options]

Options:
  --build          Rebuild Docker images and frontend build
  --debug          Enable verbose startup/debug output
  --reset          Stop stack, remove containers, reseed demo data
  --reset-volumes  Same as --reset, also remove volumes
  --logs           Tail logs for all services
  --status         Show service/container and endpoint status
  --stop           Stop services safely
  --clean          Remove temp/cache/dangling resources
  --frontend-only  Start frontend service only
  --backend-only   Start backend services only (no frontend)
  --dev            Use prod compose + local override
  --prod           Use production compose only (default)
  -h, --help       Show help
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --build) BUILD=1 ;;
    --debug) DEBUG=1 ;;
    --reset) DO_RESET=1; SEED_DEMO=1 ;;
    --reset-volumes) DO_RESET=1; REMOVE_VOLUMES=1; SEED_DEMO=1 ;;
    --logs) DO_LOGS=1 ;;
    --status) DO_STATUS=1 ;;
    --stop) DO_STOP=1 ;;
    --clean) DO_CLEAN=1 ;;
    --frontend-only) FRONTEND_ONLY=1 ;;
    --backend-only) BACKEND_ONLY=1 ;;
    --dev) MODE="dev" ;;
    --prod) MODE="prod" ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

if [[ "$FRONTEND_ONLY" -eq 1 && "$BACKEND_ONLY" -eq 1 ]]; then
  fail "--frontend-only and --backend-only are mutually exclusive"
  exit 1
fi

if [[ "$DO_LOGS" -eq 1 ]]; then
  show_logs
  exit 0
fi

if [[ "$DO_STATUS" -eq 1 ]]; then
  show_status
  exit 0
fi

if [[ "$DO_STOP" -eq 1 ]]; then
  stop_stack
  ok "Services stopped"
  exit 0
fi

if [[ "$DO_CLEAN" -eq 1 ]]; then
  clean_local_artifacts
  ok "Clean completed"
  exit 0
fi

if [[ "$DO_RESET" -eq 1 ]]; then
  header "Reset"
  reset_stack "$REMOVE_VOLUMES"
  start_stack "$BUILD" 0
  run_health_suite
  if [[ "$SEED_DEMO" -eq 1 ]]; then
    seed_demo_data
  fi
  ok "Reset completed"
  exit 0
fi

start_ts="$(date +%s)"
run_prechecks

services=()
no_deps=0
if [[ "$FRONTEND_ONLY" -eq 1 ]]; then
  services=(frontend)
  no_deps=1
elif [[ "$BACKEND_ONLY" -eq 1 ]]; then
  services=(mongo redis app celery-worker nginx syslog-receiver)
fi

if [[ "$DEBUG" -eq 1 ]]; then
  header "Debug Mode"
  info "Compose mode: $MODE"
  info "Build enabled: $BUILD"
  info "Services target: ${services[*]:-all}"
fi

start_stack "$BUILD" "$no_deps" "${services[@]}"
hard_fail=0
wait_for_core_services || hard_fail=1

if [[ "$FRONTEND_ONLY" -ne 1 ]]; then
  check_mongo || hard_fail=1
  check_redis || hard_fail=1
fi
run_health_suite || hard_fail=1

if [[ "$DEBUG" -eq 1 ]]; then
  auto_detect_failures || hard_fail=1
  show_status
fi

duration=$(( "$(date +%s)" - start_ts ))
header "Startup Summary"
info "Mode: $MODE"
info "Frontend URL: http://127.0.0.1:8080"
info "Backend URL: http://127.0.0.1"
info "Elapsed: ${duration}s"
if [[ "$hard_fail" -eq 1 ]]; then
  fail "HARD FAIL: stack broken (strict health checks failed)"
elif [[ "${HEALTH_WARN:-0}" -eq 1 ]]; then
  warn "WARN: stack healthy with non-blocking route/auth warnings"
else
  ok "OK: stack healthy"
fi
info "Use ./start.sh --status or ./start.sh --logs"
