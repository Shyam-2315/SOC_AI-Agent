#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
ENV_FILE="$BACKEND_DIR/.env"
COMPOSE_FILES=(-f "$BACKEND_DIR/docker-compose.prod.yml")
SEED_DEMO=false
MODE="prod"

usage() {
  cat <<'EOF'
Usage: ./start.sh [--build] [--seed-demo] [--local] [--prod]

Options:
  --build       Rebuild images before starting. start.sh builds by default.
  --seed-demo   Seed demo data after services are healthy.
  --local       Include local compose override for MongoDB and Redis host ports.
  --prod        Use production compose only. This is the default.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --build)
      ;;
    --seed-demo)
      SEED_DEMO=true
      ;;
    --local)
      MODE="local"
      COMPOSE_FILES=(-f "$BACKEND_DIR/docker-compose.prod.yml" -f "$BACKEND_DIR/docker-compose.local.yml")
      ;;
    --prod)
      MODE="prod"
      COMPOSE_FILES=(-f "$BACKEND_DIR/docker-compose.prod.yml")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      usage
      exit 1
      ;;
  esac
done

compose() {
  docker compose "${COMPOSE_FILES[@]}" "$@"
}

env_value() {
  local key="$1"
  if [ ! -f "$ENV_FILE" ]; then
    return 0
  fi
  grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | tr -d '"' | tr -d "'"
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is not installed or not on PATH." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running. Start Docker and rerun ./start.sh." >&2
    exit 1
  fi
}

wait_for_stack() {
  local services=(mongo redis app celery-worker syslog-receiver nginx frontend)
  local deadline=$((SECONDS + 240))
  echo "Waiting for services to become healthy..."
  while [ "$SECONDS" -lt "$deadline" ]; do
    local ready=true
    for service in "${services[@]}"; do
      local cid
      cid="$(compose ps -q "$service" 2>/dev/null || true)"
      if [ -z "$cid" ]; then
        ready=false
        break
      fi
      local state health
      state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
      health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || true)"
      if [ "$state" != "running" ]; then
        ready=false
        break
      fi
      if [ "$health" != "healthy" ] && [ "$health" != "none" ]; then
        ready=false
        break
      fi
    done
    if [ "$ready" = true ]; then
      echo "All services are running."
      return 0
    fi
    sleep 3
  done
  echo "Timed out waiting for services. Run ./status.sh and ./logs.sh for details." >&2
  compose ps
  return 1
}

print_urls() {
  local docs_enabled frontend_url backend_url health_url docs_url
  docs_enabled="$(env_value DOCS_ENABLED)"
  frontend_url="${FRONTEND_URL:-http://127.0.0.1:8080}"
  backend_url="${BACKEND_API_URL:-http://127.0.0.1}"
  health_url="${HEALTH_URL:-http://127.0.0.1/health/ready}"
  docs_url="${API_DOCS_URL:-http://127.0.0.1/docs}"

  echo
  echo "AI SOC Platform is running ($MODE mode)"
  echo "Frontend URL:   $frontend_url"
  echo "Nginx UI URL:   http://127.0.0.1"
  echo "Backend API:    $backend_url"
  echo "Health URL:     $health_url"
  if [ "$docs_enabled" = "true" ]; then
    echo "API Docs URL:   $docs_url"
  else
    echo "API Docs URL:   disabled (DOCS_ENABLED=false)"
  fi
  echo
  if [ "$SEED_DEMO" = true ] || [ "$(env_value DEMO_MODE)" = "true" ]; then
    echo "Demo login:"
    echo "  Email:    $(env_value DEMO_ADMIN_EMAIL)"
    echo "  Password: $(env_value DEMO_ADMIN_PASSWORD)"
    echo "  Collector token: $(env_value DEMO_COLLECTOR_TOKEN)"
    echo
  fi
  echo "Useful commands:"
  echo "  ./status.sh"
  echo "  ./logs.sh app"
  echo "  ./stop.sh"
}

require_docker

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE. Create it from backend/.env.example first:" >&2
  echo "  cp backend/.env.example backend/.env" >&2
  exit 1
fi

echo "Starting AI SOC Platform with Docker Compose..."
compose up -d --build
wait_for_stack

if [ "$SEED_DEMO" = true ] || [ "$(env_value DEMO_MODE)" = "true" ]; then
  echo "Seeding demo data..."
  compose exec -T app python scripts/seed_demo.py
fi

print_urls
