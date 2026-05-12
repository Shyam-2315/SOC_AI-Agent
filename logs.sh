#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
SERVICE="${1:-}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed or not on PATH." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker and rerun ./logs.sh." >&2
  exit 1
fi

if [ -n "$SERVICE" ]; then
  docker compose -f "$BACKEND_DIR/docker-compose.prod.yml" logs -f --tail=200 "$SERVICE"
else
  docker compose -f "$BACKEND_DIR/docker-compose.prod.yml" logs -f --tail=200
fi
