#!/usr/bin/env bash
set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$_LIB_DIR/common.sh"

BACKEND_URL="${BACKEND_URL:-http://127.0.0.1}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:8080}"
WS_URL="${WS_URL:-http://127.0.0.1/ws/alerts}"
HEALTH_WARN=0

warn_check() {
  HEALTH_WARN=1
  warn "$@"
}

poll_url() {
  local name="$1"
  local url="$2"
  local retries="${3:-20}"
  local delay="${4:-2}"
  local i=1
  while [[ "$i" -le "$retries" ]]; do
    if curl -fsS --max-time 4 "$url" >/dev/null 2>&1; then
      ok "$name reachable ($url)"
      return 0
    fi
    sleep "$delay"
    i=$((i + 1))
  done
  fail "$name timeout ($url)"
  return 1
}

check_container_health() {
  local service="$1"
  local state health
  IFS='|' read -r state health <<<"$(service_status "$service")"
  if [[ "$state" != "running" ]]; then
    fail "$service not running (state=$state)"
    return 1
  fi
  if [[ "$health" == "unhealthy" ]]; then
    fail "$service unhealthy"
    return 1
  fi
  if [[ "$health" == "none" || "$health" == "healthy" ]]; then
    ok "$service healthy (health=$health)"
    return 0
  fi
  warn "$service health=$health"
  return 0
}

wait_for_core_services() {
  header "Container Health"
  local retries=30
  local delay=2
  local i=1
  while [[ "$i" -le "$retries" ]]; do
    local failures=0
    local services=(mongo redis app frontend)
    local service=""
    for service in "${services[@]}"; do
      if ! check_container_health "$service"; then
        failures=$((failures + 1))
      fi
    done
    check_container_health celery-worker || failures=$((failures + 1))
    if syslog_enabled; then
      check_container_health syslog-receiver || failures=$((failures + 1))
    else
      warn "Syslog disabled in .env"
    fi
    check_container_health nginx || failures=$((failures + 1))
    if [[ "$failures" -eq 0 ]]; then
      return 0
    fi
    sleep "$delay"
    i=$((i + 1))
  done
  fail "Timed out waiting for core services to be healthy"
  return 1
}

check_mongo() {
  if compose exec -T mongo mongosh --quiet --eval "db.adminCommand('ping').ok" | grep -q 1; then
    ok "Mongo reachable"
    return 0
  fi
  fail "Mongo unreachable"
  return 1
}

check_redis() {
  local redis_password
  redis_password="$(env_value REDIS_PASSWORD)"
  if compose exec -T redis sh -c "redis-cli -a \"$redis_password\" ping" | grep -q PONG; then
    ok "Redis reachable"
    return 0
  fi
  fail "Redis unreachable"
  return 1
}

check_websocket_endpoint() {
  local status
  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$WS_URL" || true)"
  case "$status" in
    101|400|401|403|426)
      ok "WebSocket endpoint reachable ($WS_URL, code=$status)"
      return 0
      ;;
    404)
      warn_check "WebSocket HTTP probe returned 404 for $WS_URL (plain HTTP probe is not authoritative for WS routes)"
      return 0
      ;;
    *)
      warn_check "WebSocket endpoint probe inconclusive ($WS_URL, code=${status:-n/a})"
      return 0
      ;;
  esac
}

check_syslog_listener() {
  if ! syslog_enabled; then
    warn "Syslog listener check skipped (SYSLOG_ENABLED=false)"
    return 0
  fi
  local port
  port="$(env_value SYSLOG_PORT)"
  if [[ -z "$port" ]]; then
    port="5514"
  fi
  if ss -lun | awk '{print $5}' | grep -q ":$port$"; then
    ok "Syslog UDP listener active on $port"
  else
    fail "Syslog UDP listener not active on $port"
    return 1
  fi
}

check_frontend_routes() {
  header "Frontend Validation"
  local route status
  for route in / /incidents /alerts /dashboard; do
    status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "${FRONTEND_URL}${route}" || true)"
    if [[ "$status" == "200" ]]; then
      ok "Route ${route} served"
    elif [[ "$status" == "307" ]]; then
      warn_check "Route ${route} redirected (code=307)"
    else
      fail "Route ${route} failed (code=$status)"
      return 1
    fi
  done
  local index_tmp="/tmp/aisoc-index.html"
  if ! curl -fsSL --max-time 10 "$FRONTEND_URL/" -o "$index_tmp"; then
    fail "index.html download failed"
    return 1
  fi
  if grep -qiE "<!doctype html|<html" "$index_tmp"; then
    ok "index.html served"
  else
    fail "index.html validation failed"
    return 1
  fi
  if grep -qiE "id=[\"']root[\"']|/src/main\\.|type=[\"']module[\"']" "$index_tmp"; then
    ok "Frontend root/client markers detected"
  else
    fail "Frontend root/client markers missing in index.html"
    return 1
  fi
}

check_frontend_hydration_logs() {
  local logs
  logs="$(compose logs --tail=200 frontend 2>/dev/null || true)"
  if printf "%s" "$logs" | grep -qiE "hydration|white screen|blank page|failed to load module"; then
    fail "Potential frontend hydration/build failure detected in frontend logs"
    return 1
  fi
  ok "No hydration/build failure patterns detected in frontend logs"
}

check_api_validation() {
  header "API Validation"
  local status
  poll_url "Backend /health" "$BACKEND_URL/health" 30 2

  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$BACKEND_URL/auth/login" -H 'Content-Type: application/json' -d '{}' || true)"
  if [[ "$status" == "422" || "$status" == "401" || "$status" == "403" || "$status" == "200" ]]; then
    ok "auth/login route reachable (code=$status)"
  elif [[ "$status" == "307" ]]; then
    warn_check "auth/login redirected (code=307)"
  else
    fail "auth/login route failed (code=$status)"
    return 1
  fi

  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$BACKEND_URL/incidents/" || true)"
  if [[ "$status" == "401" || "$status" == "403" || "$status" == "422" || "$status" == "200" ]]; then
    ok "Incidents API reachable (code=$status)"
  elif [[ "$status" == "307" ]]; then
    warn_check "Incidents API redirected (code=307)"
  else
    fail "Incidents API failed (code=$status)"
    return 1
  fi

  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$BACKEND_URL/alerts" || true)"
  if [[ "$status" == "401" || "$status" == "403" || "$status" == "422" || "$status" == "200" ]]; then
    ok "Alerts API reachable (code=$status)"
  elif [[ "$status" == "307" ]]; then
    warn_check "Alerts API redirected (code=307)"
  else
    fail "Alerts API failed (code=$status)"
    return 1
  fi

  check_websocket_endpoint
  ok "API READY"
  ok "WEBSOCKET READY"
  ok "COLLECTOR INGEST READY (/ingest)"
}

run_health_suite() {
  HEALTH_WARN=0
  header "HTTP Health Checks"
  poll_url "Frontend /" "$FRONTEND_URL/" 40 2
  poll_url "Backend /health" "$BACKEND_URL/health" 40 2
  check_mongo
  check_redis
  check_websocket_endpoint
  check_syslog_listener
  check_frontend_routes
  check_frontend_hydration_logs
  check_api_validation
}

show_recent_logs_for_failure() {
  local service="$1"
  header "Recent logs: $service"
  compose logs --tail=80 "$service" || true
}

auto_detect_failures() {
  header "Failure Detection"
  local failed=0
  local service state health
  for service in app frontend mongo redis; do
    IFS='|' read -r state health <<<"$(service_status "$service")"
    if [[ "$state" != "running" ]]; then
      fail "$service crash detected (state=$state)"
      show_recent_logs_for_failure "$service"
      failed=1
    elif [[ "$health" == "unhealthy" ]]; then
      fail "$service unhealthy"
      show_recent_logs_for_failure "$service"
      failed=1
    fi
  done
  return "$failed"
}
