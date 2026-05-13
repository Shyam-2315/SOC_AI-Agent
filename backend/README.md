# AI SOC Platform

FastAPI backend plus the Lovable-generated React/TanStack frontend for a multi-tenant AI SOC platform.

For full local frontend/backend startup instructions, see `../FRONTEND_BACKEND_RUN.md`.

## Environment

This project uses exactly one active runtime environment file:

- `.env`: active local/production runtime values for Docker Compose and backend startup
- `.env.example`: safe template only; copy it to `.env` and replace placeholders

Do not create `.env.local`, `.env.production`, or additional env variants.

Required variables are grouped in `.env.example` for:

- FastAPI runtime: `APP_NAME`, `APP_VERSION`, `ENVIRONMENT`, `DEBUG`, `DOCS_ENABLED`, `HOST`, `PORT`, `WEB_CONCURRENCY`
- Logging/security: `LOG_LEVEL`, `LOG_JSON`, `TRUSTED_HOSTS`, `HTTPS_REDIRECT`, `CORS_ALLOW_CREDENTIALS`, `CORS_ORIGINS`
- MongoDB: `MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, `MONGO_APP_USERNAME`, `MONGO_APP_PASSWORD`, `MONGO_APP_DATABASE`, `MONGO_URL`, `DATABASE_NAME`, Mongo timeout/pool settings
- Redis/Celery: `REDIS_PASSWORD`, `REDIS_URL`, `ALERT_PROCESSING_MODE`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CELERY_TASK_DEFAULT_QUEUE`, `CELERY_WORKER_CONCURRENCY`
- Realtime/WebSockets: `REALTIME_EVENTS_CHANNEL`, `WEBSOCKET_SEND_QUEUE_SIZE`
- Auth: `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_ISSUER`, `JWT_AUDIENCE`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `PUBLIC_REGISTRATION_ENABLED`
- Demo mode: `DEMO_MODE`, `DEMO_ORG_NAME`, `DEMO_ADMIN_EMAIL`, `DEMO_ADMIN_PASSWORD`, `DEMO_COLLECTOR_TOKEN`
- Frontend: `VITE_API_BASE_URL`, `VITE_WS_BASE_URL`, `VITE_DEMO_MODE`, `VITE_DEMO_ADMIN_EMAIL`, `VITE_DEMO_ADMIN_PASSWORD`, `VITE_DEMO_COLLECTOR_TOKEN`
- Rate limiting: `AUTH_RATE_LIMIT_PER_MINUTE`, `INGESTION_RATE_LIMIT_PER_MINUTE`
- Ingestion: `COLLECTOR_API_KEYS`, `COLLECTOR_BATCH_MAX_SIZE`
- Nginx: `NGINX_SERVER_NAME`, `NGINX_CLIENT_MAX_BODY_SIZE`, `NGINX_SSL_ENABLED`, `NGINX_SSL_CERT_PATH`, `NGINX_SSL_KEY_PATH`

## Structure

- `app/main.py`: application factory, lifespan, middleware, and top-level routes.
- `app/api/`: dependency wiring, router registration, and WebSocket endpoints.
- `app/api/routes/`: thin HTTP handlers grouped by feature.
- `app/services/`: business logic separated from transport concerns.
- `app/db/`: Mongo client setup and index management.
- `app/core/`: configuration, logging, middleware, security, and exception handling.
- `app/schemas/`: request payload models.
- `app/common/`: shared pagination and Mongo serialization helpers.
- `app/realtime/`: tenant-scoped WebSocket connection manager.
- `ai/`: AI/domain helper functions consumed by service modules.
- `scripts/`: local bootstrap and debug helpers.

Legacy module paths under `api/`, `core/`, `models/`, `schemas/`, `websocket/`, and `main.py` remain as compatibility shims so existing imports continue to work during migration.

## Docker Compose

## One-Command Startup

From the project root, start the full platform and seed demo data:

```bash
./start.sh --build --seed-demo
```

This starts:

- `app`: FastAPI backend, REST APIs, WebSocket endpoint
- `frontend`: React/TanStack frontend on port `8080`
- `mongo`: MongoDB
- `redis`: Redis
- `celery-worker`: Celery background worker
- `syslog-receiver`: optional UDP syslog ingestion worker on port `5514`
- `nginx`: reverse proxy for backend API and WebSocket traffic on ports `80` and `443`

Supported commands:

```bash
./start.sh
./start.sh --build
./start.sh --seed-demo
./start.sh --local
./start.sh --prod
./stop.sh
./restart.sh
./status.sh
./logs.sh
./logs.sh app
./logs.sh celery-worker
./logs.sh nginx
./logs.sh mongo
./logs.sh redis
./logs.sh frontend
```

Default URLs:

```text
Frontend:   http://127.0.0.1:8080
Nginx UI:   http://127.0.0.1
Backend:    http://127.0.0.1
Health:     http://127.0.0.1/health/ready
API docs:   http://127.0.0.1/docs when DOCS_ENABLED=true
WebSocket:  ws://127.0.0.1/ws/alerts?token=<jwt>
```

The frontend container is exposed directly on `http://127.0.0.1:8080`. Browser API and WebSocket calls use Nginx on `http://127.0.0.1` and `ws://127.0.0.1/ws/alerts`, so the direct frontend container is only the UI entrypoint.

`VITE_API_BASE_URL` is the frontend source of truth for REST traffic when it is set. For the Docker stack it should stay `http://127.0.0.1`, which prevents stale browser overrides from accidentally sending API calls to the direct frontend UI container on `:8080`.

`./start.sh` verifies Docker is running, verifies `backend/.env` exists, builds images, starts the stack, waits for backend, MongoDB, Redis, Celery, syslog receiver, Nginx and frontend health, prints URLs, and seeds demo data when `DEMO_MODE=true` or `--seed-demo` is passed.

Fresh clone workflow:

```bash
cp backend/.env.example backend/.env
# edit backend/.env secrets and local values
./start.sh --seed-demo
```

Troubleshooting:

```bash
./status.sh
./logs.sh app
./logs.sh frontend
./logs.sh nginx
docker compose -f backend/docker-compose.prod.yml config
curl http://127.0.0.1/health/ready
```

If port `80`, `443`, or `8080` is already in use, stop the conflicting process or change the port mapping in `backend/docker-compose.prod.yml`.

Start the full stack with the active `.env`:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

The production compose file exposes only the required edge services:

- `nginx`: public entrypoint on `80` and `443`
- `frontend`: public frontend on `8080`
- `app`: internal FastAPI service on `8000`
- `celery-worker`: internal background worker for alert processing
- `syslog-receiver`: UDP syslog receiver on `5514/udp` when enabled
- `mongo`: internal authenticated MongoDB with persistent volume `mongo_data`
- `redis`: internal password-protected Redis with persistent volume `redis_data`

For local host access to MongoDB and Redis while keeping the same `.env`, add the local override:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.local.yml up -d mongo redis
```

## Local Backend

When running Uvicorn directly on the host, `.env` is still the only file loaded. If you run the backend outside Docker, update `.env` service URLs to host-accessible values first, for example:

```env
MONGO_URL=mongodb://ai_soc_app:MongoApp123@localhost:27017/ai_soc?authSource=ai_soc
REDIS_URL=redis://:Redis123@localhost:6379/0
CELERY_BROKER_URL=redis://:Redis123@localhost:6379/0
CELERY_RESULT_BACKEND=redis://:Redis123@localhost:6379/0
```

Then run:

```bash
source venv/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

## Verification

```bash
curl http://127.0.0.1/health
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f nginx app celery-worker
```

Run production smoke validation:

```bash
python scripts/production_smoke.py
```

For authenticated API checks:

```bash
SMOKE_EMAIL=admin@example.com SMOKE_PASSWORD='your-password' python scripts/production_smoke.py
```

Open `http://127.0.0.1/docs` only when `DOCS_ENABLED=true`; production defaults keep docs disabled.

## Demo Mode

The demo seed makes the platform ready for investor, mentor, hackathon, and pilot walkthroughs. It is idempotent, so it is safe to run more than once.

Start the stack:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Seed demo data:

```bash
python scripts/seed_demo.py
```

If you run the script inside Docker:

```bash
docker compose -f docker-compose.prod.yml exec app python scripts/seed_demo.py
```

Default demo credentials:

```text
Admin:   demo.admin@aisoc.dev
Analyst: demo.analyst@aisoc.dev
Viewer:  demo.viewer@aisoc.dev
Password: DemoAdmin123!
```

Demo environment variables:

```env
DEMO_MODE=true
DEMO_ORG_NAME=Demo SOC
DEMO_ADMIN_EMAIL=demo.admin@aisoc.dev
DEMO_ADMIN_PASSWORD=DemoAdmin123!
VITE_DEMO_MODE=true
VITE_API_BASE_URL=http://127.0.0.1
VITE_WS_BASE_URL=ws://127.0.0.1
VITE_DEMO_ADMIN_EMAIL=demo.admin@aisoc.dev
VITE_DEMO_ADMIN_PASSWORD=DemoAdmin123!
VITE_DEMO_COLLECTOR_TOKEN=demo-collector-token
```

Frontend demo mode shows the demo credentials on the login screen and adds a quick-fill button for the admin account. It still logs in through `/auth/login` and stores the real JWT in `soc_auth_token`.

Demo walkthrough:

1. Log in as the demo admin.
2. Open Dashboard to show operational totals.
3. Open Alerts and Incidents to show active high-signal detections.
4. Open SOAR to show automated simulated response actions and blocked IPs.
5. Open Threat Hunting to show campaign detection and attack timeline.
6. Open Detection Rules and Rule Packs to show editable detection content and starter packs.
7. Open Collectors to show agent registration and token-based ingestion.
8. Open Realtime to verify the browser WebSocket connects to `/ws/alerts`.
9. Open Log Ingestion and send a test event with the demo collector token.

Demo smoke validation:

```bash
python scripts/production_smoke.py
```

The smoke test logs in with the demo admin, verifies the demo organization, and confirms seeded alerts and incidents exist. Use `SMOKE_SKIP_DEMO=true` to skip demo checks.

## Collectors

Collector registration is organization-scoped and requires an admin JWT with `collectors:read` or `collectors:write` RBAC permissions. Collector ingestion uses `X-Collector-Token`; no JWT is required for `/collector/ingest`. The API returns the plaintext collector token only once during creation and stores only its hash.

Supported collector types:

- `linux`
- `windows`
- `syslog`
- `firewall`
- `cloud`
- `custom`

Create a collector:

```bash
curl -X POST http://127.0.0.1/collectors \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-linux-agent-1","type":"linux"}'
```

Save the `api_key` from the response as the agent token. It is not returned again.

List collectors:

```bash
curl http://127.0.0.1/collectors \
  -H "Authorization: Bearer $JWT"
```

Disable a collector:

```bash
curl -X PATCH http://127.0.0.1/collectors/$COLLECTOR_ID \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"status":"disabled"}'
```

Send a batch from a collector:

```bash
curl -X POST http://127.0.0.1/collector/ingest \
  -H "X-Collector-Token: $COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {
        "source": "linux-agent",
        "event_type": "ssh_login",
        "severity": "low",
        "message": "Accepted SSH login",
        "ip_address": "10.0.0.5"
      }
    ]
  }'
```

Batch size is controlled by `COLLECTOR_BATCH_MAX_SIZE`. Responses include `accepted`, `rejected`, per-log `results`, and per-log validation `errors`.

## Syslog Receiver

The UDP syslog receiver runs as the `syslog-receiver` Docker Compose service and converts syslog datagrams into the existing collector ingest path. It uses a dedicated `SYSLOG_COLLECTOR_TOKEN` because syslog senders cannot attach HTTP headers.

Environment:

```env
SYSLOG_ENABLED=false
SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=5514
SYSLOG_COLLECTOR_TOKEN=
```

Enable local syslog ingestion:

```bash
# Create a collector with type syslog, then copy its one-time api_key.
SYSLOG_ENABLED=true
SYSLOG_COLLECTOR_TOKEN=<syslog-collector-token>
SYSLOG_PORT=5514
```

Send a local test message:

```bash
logger -n 127.0.0.1 -P 5514 "AI SOC syslog test critical event"
```

Syslog conversion:

- `event_type`: `syslog_event`
- `severity`: mapped from syslog priority when present, otherwise `low`
- `source`: parsed hostname, falling back to sender IP
- `message`: parsed timestamp/program/message fields
- `ip_address`: UDP sender IP

Health output includes `checks.syslog_receiver` on `/health/ready`. Docker status is visible with:

```bash
docker compose -f backend/docker-compose.prod.yml ps syslog-receiver
docker compose -f backend/docker-compose.prod.yml logs -f syslog-receiver
```

## Detection Rules

Detection rules are organization-scoped and require JWT auth with `rules:read` or `rules:write` RBAC permissions.

Condition format:

```json
{"field":"message","operator":"contains","value":"failed login"}
```

Supported fields:

- `source`
- `event_type`
- `severity`
- `message`
- `ip_address`

Supported operators:

- `equals`
- `contains`

Example rule:

```json
{
  "name": "SSH Brute Force",
  "description": "Detect repeated failed SSH login activity",
  "severity": "high",
  "event_type": "ssh_attack",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "failed login"}
  ],
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110 - Brute Force",
  "enabled": true
}
```

Create rule:

```bash
curl -X POST http://127.0.0.1/rules \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSH Brute Force",
    "description": "Detect repeated failed SSH login activity",
    "severity": "high",
    "event_type": "ssh_attack",
    "conditions": [
      {"field": "message", "operator": "contains", "value": "failed login"}
    ],
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110 - Brute Force",
    "enabled": true
  }'
```

List rules:

```bash
curl http://127.0.0.1/rules -H "Authorization: Bearer $JWT"
```

Ingest a matching log:

```bash
curl -X POST http://127.0.0.1/ingest/ \
  -H "X-Collector-Token: test-collector-token" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "linux",
    "event_type": "ssh_attack",
    "severity": "medium",
    "message": "failed login from external host",
    "ip_address": "10.0.0.4"
  }'
```

Matching alerts include `matched_rule_id` and `matched_rule_name`.

## Detection Packs

Detection packs group detection rules by category and version. Packs are organization-scoped and use the existing `rules:read` and `rules:write` permissions.

Create an empty pack:

```bash
curl -X POST http://127.0.0.1/rule-packs \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Linux Starter Pack",
    "description": "Linux-focused detections",
    "category": "endpoint",
    "version": "1.0.0",
    "enabled": true
  }'
```

List packs and built-in starter packs:

```bash
curl http://127.0.0.1/rule-packs \
  -H "Authorization: Bearer $JWT"

curl http://127.0.0.1/rule-packs/starter \
  -H "Authorization: Bearer $JWT"
```

Import a built-in starter pack:

```bash
curl -X POST http://127.0.0.1/rule-packs/import \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"starter_pack":"ssh_brute_force"}'
```

Available starter pack keys:

- `ssh_brute_force`
- `malware_execution`
- `ransomware_behavior`
- `suspicious_network_activity`
- `privilege_escalation`

Import Sigma-style JSON:

```bash
curl -X POST http://127.0.0.1/rule-packs/import \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "pack": {
      "name": "Imported SSH Pack",
      "description": "Imported Sigma-style rules",
      "category": "authentication",
      "version": "1.0.0"
    },
    "rules": [
      {
        "title": "SSH failed login",
        "description": "Detect SSH failed logins",
        "level": "high",
        "event_type": "ssh_attack",
        "detection": {
          "selection": {"message|contains": "failed login"},
          "condition": "selection"
        },
        "tags": ["attack.credential_access", "attack.t1110"]
      }
    ]
  }'
```

Import Sigma-style YAML:

```bash
curl -X POST http://127.0.0.1/rule-packs/import \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @sigma-pack.yml
```

Disable or enable a pack. This cascades to every linked detection rule:

```bash
curl -X PATCH http://127.0.0.1/rule-packs/$PACK_ID \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}'
```

Export pack rules:

```bash
curl http://127.0.0.1/rule-packs/$PACK_ID/export?format=json \
  -H "Authorization: Bearer $JWT"

curl http://127.0.0.1/rule-packs/$PACK_ID/export?format=yaml \
  -H "Authorization: Bearer $JWT"
```
