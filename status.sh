#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
COMPOSE_FILE="$BACKEND_DIR/docker-compose.prod.yml"

compose() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is not installed or not on PATH." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running. Start Docker and rerun ./status.sh." >&2
    exit 1
  fi
}

check_url() {
  local name="$1"
  local url="$2"
  if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
    printf "%-16s ok      %s\n" "$name" "$url"
  else
    printf "%-16s failed  %s\n" "$name" "$url"
  fi
}

service_state() {
  local service="$1"
  local cid state health
  cid="$(compose ps -q "$service" 2>/dev/null || true)"
  if [ -z "$cid" ]; then
    printf "%-16s missing\n" "$service"
    return
  fi
  state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || true)"
  printf "%-16s %-8s health=%s\n" "$service" "$state" "$health"
}

require_docker

echo "Docker Compose services:"
compose ps

echo
echo "Service health:"
for service in mongo redis app celery-worker nginx frontend; do
  service_state "$service"
done

echo
echo "HTTP health checks:"
check_url "backend" "http://127.0.0.1/health/ready"
check_url "nginx" "http://127.0.0.1/nginx-health"
check_url "frontend" "http://127.0.0.1:8080/"
