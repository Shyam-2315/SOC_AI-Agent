# AI SOC Backend

FastAPI backend for a multi-tenant AI SOC platform.

## Structure

- `main.py`: FastAPI app, middleware, router registration, health checks, WebSocket endpoint.
- `api/routes/`: HTTP route handlers.
- `core/`: settings, database, auth, and shared dependencies.
- `models/`: request models for domain objects.
- `schemas/`: shared API schemas.
- `ai/`: threat classification, MITRE mapping, correlation, and copilot helpers.
- `websocket/`: tenant-scoped WebSocket connection manager.
- `scripts/`: local bootstrap and debug helpers.

## Required Environment

Copy `.env.example` to `.env`, then update values:

```env
MONGO_URL=mongodb://localhost:27018
DATABASE_NAME=ai_soc
JWT_SECRET=change-me-to-a-long-random-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
COLLECTOR_API_KEYS=test-collector-token:replace-with-organization-id
REDIS_URL=redis://localhost:6379/0
```

Use `scripts/bootstrap.py` to create the first organization and admin user.
