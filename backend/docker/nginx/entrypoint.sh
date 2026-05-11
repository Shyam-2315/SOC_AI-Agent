#!/bin/sh
set -eu

: "${NGINX_SERVER_NAME:=_}"
: "${NGINX_CLIENT_MAX_BODY_SIZE:=10m}"
: "${NGINX_SSL_ENABLED:=false}"
: "${NGINX_SSL_CERT_PATH:=/etc/nginx/certs/server.crt}"
: "${NGINX_SSL_KEY_PATH:=/etc/nginx/certs/server.key}"

template="/etc/nginx/templates/http.conf.template"

if [ "$NGINX_SSL_ENABLED" = "true" ]; then
  if [ ! -f "$NGINX_SSL_CERT_PATH" ] || [ ! -f "$NGINX_SSL_KEY_PATH" ]; then
    echo "Missing TLS certificate or key for nginx" >&2
    exit 1
  fi
  template="/etc/nginx/templates/https.conf.template"
fi

envsubst '${NGINX_SERVER_NAME} ${NGINX_CLIENT_MAX_BODY_SIZE} ${NGINX_SSL_CERT_PATH} ${NGINX_SSL_KEY_PATH}' \
  < "$template" \
  > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
