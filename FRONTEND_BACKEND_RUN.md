# AI SOC Platform Local Run Guide

The project uses one active environment file: `backend/.env`.

## 1. Start MongoDB and Redis

For local host access to MongoDB and Redis:

```bash
cd /home/shyam2315/Projects/ai-soc-platform/backend
docker compose -f docker-compose.prod.yml -f docker-compose.local.yml up -d mongo redis
```

If running the backend directly on the host, make sure `backend/.env` uses host URLs:

```env
MONGO_URL=mongodb://ai_soc_app:MongoApp123@localhost:27017/ai_soc?authSource=ai_soc
REDIS_URL=redis://:Redis123@localhost:6379/0
CELERY_BROKER_URL=redis://:Redis123@localhost:6379/0
CELERY_RESULT_BACKEND=redis://:Redis123@localhost:6379/0
```

## 2. Start The Backend API

```bash
cd /home/shyam2315/Projects/ai-soc-platform/backend
source venv/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Verify:

```bash
curl http://127.0.0.1:8000/
curl http://127.0.0.1:8000/health
```

## 3. Start The Celery Worker

Use this when `ALERT_PROCESSING_MODE=celery`.

```bash
cd /home/shyam2315/Projects/ai-soc-platform/backend
source venv/bin/activate
celery -A app.workers.celery_app.celery_app worker --loglevel=info -Q alert-processing
```

## 4. Start The Full Docker Stack

From the project root, the complete connected platform starts with one command:

```bash
cd /home/shyam2315/Projects/ai-soc-platform
./start.sh --build --seed-demo
```

This starts FastAPI, MongoDB, Redis, Celery, Nginx, the Lovable frontend, WebSockets, and the demo seed.

Open:

```text
Frontend direct UI: http://127.0.0.1:8080
Nginx UI/API:       http://127.0.0.1
API readiness:      http://127.0.0.1/health/ready
WebSocket:          ws://127.0.0.1/ws/alerts?token=<jwt>
```

The frontend direct container on `:8080` is only the browser UI. Browser REST and WebSocket traffic should go through Nginx on `http://127.0.0.1` and `ws://127.0.0.1`.

```bash
cd /home/shyam2315/Projects/ai-soc-platform/backend
docker compose -f docker-compose.prod.yml up -d --build
```

Check services:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f nginx app celery-worker
```

Run smoke validation:

```bash
python scripts/production_smoke.py
```

## 5. Start The Frontend

The connected frontend defaults are:

```text
API: http://127.0.0.1
WS:  ws://127.0.0.1
```

Start it with:

```bash
cd /home/shyam2315/Projects/ai-soc-platform/frontend
npm install
npm run dev
```

Open the Vite URL, normally:

```text
http://localhost:5173
```

If you intentionally run FastAPI directly without Nginx, override the frontend environment before starting Vite:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000 VITE_WS_BASE_URL=ws://127.0.0.1:8000 npm run dev
```

## 6. Test Log Ingestion

Use the collector token configured in `backend/.env`:

```text
X-Collector-Token: <collector-token>
```

For the current local `.env`, the default token is:

```text
test-collector-token
```

## 7. Test Realtime WebSocket

The frontend connects to:

```text
ws://127.0.0.1/ws/alerts?token=<jwt>
```

Ingest a critical or malicious log and confirm live events:

```text
soc.alert.created
soc.incident.created
soc.response_action.created
```
