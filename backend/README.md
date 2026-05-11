# AI SOC Backend

FastAPI backend for a multi-tenant AI SOC platform.

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
- Rate limiting: `AUTH_RATE_LIMIT_PER_MINUTE`, `INGESTION_RATE_LIMIT_PER_MINUTE`
- Ingestion: `COLLECTOR_API_KEYS`
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

Start the full stack with the active `.env`:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Only Nginx is exposed publicly by the production compose file:

- `nginx`: public entrypoint on `80` and `443`
- `app`: internal FastAPI service on `8000`
- `celery-worker`: internal background worker for alert processing
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

Open `http://127.0.0.1:8000/docs` only when `DOCS_ENABLED=true`; production defaults keep docs disabled.
