#!/bin/sh
set -eu

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-4}"
LOG_LEVEL="${LOG_LEVEL:-info}"
APP_MODULE="${APP_MODULE:-main:app}"
UVICORN_LOG_LEVEL="$(printf '%s' "$LOG_LEVEL" | tr '[:upper:]' '[:lower:]')"

exec uvicorn "$APP_MODULE" \
  --host "$HOST" \
  --port "$PORT" \
  --workers "$WEB_CONCURRENCY" \
  --proxy-headers \
  --forwarded-allow-ips="*" \
  --timeout-keep-alive 30 \
  --no-server-header \
  --log-level "$UVICORN_LOG_LEVEL"
