# 🛡️ SOC AI Agent - Enterprise Security Operations Center Platform

An intelligent, AI-powered Security Operations Center (SOC) platform featuring real-time threat detection, automated incident response, and advanced threat hunting capabilities. Built with a modern React/TypeScript frontend and FastAPI backend.

<div align="center">

[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-61DAFB?logo=react&logoColor=white)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?logo=redis&logoColor=white)](https://redis.io/)

</div>

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

SOC AI Agent is an enterprise-grade security operations center platform that combines **AI-driven threat intelligence** with **automated incident response** to help security teams detect, investigate, and respond to threats in real-time.

The platform provides:
- **Real-time Alert Management** - Intelligent alert correlation and deduplication
- **Threat Intelligence Integration** - Automated threat classification and attribution
- **Incident Orchestration** - SOAR-like capabilities for automated response actions
- **Threat Hunting** - Campaign detection and attack timeline visualization
- **Multi-tenant Architecture** - Built for enterprise deployments
- **Live WebSocket Updates** - Real-time event streaming to dashboards

## ✨ Key Features

### 🤖 AI & Threat Detection
- **Anomaly Detection** - ML-based outlier detection for unusual patterns
- **Threat Classification** - Automatic severity and threat assessment
- **Campaign Detection** - Identify coordinated attack patterns
- **MITRE ATT&CK Mapping** - Automatic tactic and technique mapping
- **Threat Intelligence Correlation** - External threat intel integration
- **AI Security Copilot Core** - Deterministic alert triage, incident summaries, false-positive scoring, recommended actions, and natural-language SOC query parsing without external AI APIs
- **AI Attack Correlation & Threat Story Engine** - Tenant-scoped attack chains that correlate related alerts into timelines, MITRE ATT&CK techniques, risk scores, summaries, actions, and graph data

### 🎯 Alert & Incident Management
- **Smart Alert Routing** - Intelligent grouping and correlation
- **Real-time Alerts** - WebSocket-based live alert streaming
- **Incident Lifecycle** - Investigation, closure, and audit trails
- **Attack Graph Visualization** - Incident-level graphing across IPs, hosts, endpoints, alerts, MITRE, and SOAR actions
- **Alert Status Tracking** - Open, acknowledged, resolved states
- **Custom Detection Rules** - Rule builder with field-based conditions

### 🤖 Automated Response (SOAR)
- **Response Action Orchestration** - Chainable automated actions
- **Block/Remediate Actions** - IP blocking, user isolation, etc.
- **Action Status Tracking** - Success/failure monitoring
- **Audit Logging** - Complete action history

### 🔍 Threat Hunting
- **Campaign Detection** - Identify multi-alert attack patterns
- **Attack Timeline** - Visual attack progression
- **Event Correlation** - Connect related security events
- **Historical Analysis** - Forensic investigation capabilities

## AI Attack Correlation & Threat Story Engine

The Attack Chains feature builds a full threat story from recent alerts in the same organization. It groups alerts by shared host, user, source IP, destination IP, process/session context, and close event timing, then stores the result in the `attack_chains` MongoDB collection.

### API Endpoints

- `POST /attack-chains/generate?lookback_hours=24` - correlate recent alerts and create or update attack chains.
- `GET /attack-chains/` - list tenant-scoped attack chains.
- `GET /attack-chains/{chain_id}` - get the full attack chain.
- `PATCH /attack-chains/{chain_id}/status` - update `open`, `investigating`, `contained`, or `resolved`.
- `GET /attack-chains/{chain_id}/story` - return timeline, AI summary, and recommended actions.
- `GET /attack-chains/{chain_id}/graph` - return node/edge data for frontend visualization.

All endpoints use the authenticated user's `organization_id` and RBAC permissions, so cross-tenant access returns `404` or `403` depending on the failure mode.

### Risk Score

Risk is calculated on a 0-10 scale from alert count, severity weights, affected host/user spread, credential access, lateral movement, exfiltration, and compressed timing. Critical alerts, credential dumping, remote services/lateral movement, and exfiltration all increase the score.

### MITRE Mapping Examples

- PowerShell, `cmd.exe`, bash, shell, script, or `EncodedCommand` maps to `T1059 Command and Scripting Interpreter`.
- Mimikatz, LSASS access, credential dump, or hash dump maps to `T1003 OS Credential Dumping`.
- RDP, SSH, SMB, WinRM, remote login, or lateral movement maps to `T1021 Remote Services`.
- Scheduled task, cron, or startup folder maps to `T1053 Scheduled Task/Job`.
- Data upload, exfiltration, or large outbound transfer maps to `T1041 Exfiltration Over C2 Channel`.
- Suspicious download, payload download, curl, or wget maps to `T1105 Ingress Tool Transfer`.

### Demo Flow

Run the backend, seed demo alerts, then open the frontend `Attack Chains` navigation item:

```bash
cd backend
.venv/bin/python scripts/seed_attack_chain_demo.py
```

The demo creates a suspicious login, PowerShell execution, credential dumping, lateral movement, and data exfiltration sequence for `demo-org`, then generates a complete attack chain.

### Frontend Usage

The React console includes `Attack Chains` in the Operations navigation. The page can generate chains from a selected lookback window, show risk/severity badges, display affected hosts/users and MITRE badges, render the threat story and timeline, list recommended actions, and show a node-edge graph fallback when React Flow is not installed.

### 🔐 Security & Multi-Tenancy
- **JWT Authentication** - Secure token-based auth with configurable expiry
- **Role-Based Access Control (RBAC)** - Admin, Analyst, Viewer roles
- **Multi-Tenant Isolation** - Complete data separation per organization
- **Collector Token Auth** - Secure agent registration and ingestion
- **Rate Limiting** - Per-minute limits on auth and ingestion
- **DoS/DDoS Traffic Detection** - Request-rate, error-rate, and endpoint fan-out monitoring
- **Safe Internal Blocking** - Application-level IP blocklist with optional auto-blocking

### 📊 Integration & Data Collection
- **Collector Framework** - Agent-based log collection
- **Multi-Source Support** - Linux, Windows, Firewall, Cloud, Custom
- **Batch Ingestion** - Efficient log batching with size limits
- **Validation & Rejection** - Per-log error reporting
- **Detection Rule Packs** - Pre-built and custom rule bundles

## 🏗️ Technology Stack

### Backend
- **Framework**: FastAPI 0.136+
- **Server**: Uvicorn with async support
- **Database**: MongoDB 4.4+ (async with Motor)
- **Cache/Queue**: Redis 6+ with Celery workers
- **Auth**: Python-jose (JWT) with bcrypt hashing
- **ML/AI**: scikit-learn, numpy
- **Validation**: Pydantic
- **Async**: asyncio, websockets

### Frontend
- **Framework**: React 19.2 with TypeScript
- **Routing**: TanStack Router (type-safe)
- **State**: TanStack Query (data fetching)
- **UI Framework**: TanStack Start with Cloudflare Workers
- **Styling**: Tailwind CSS 4.2 with animations
- **Components**: Radix UI (accessible primitives)
- **Forms**: React Hook Form with Zod validation
- **Charts**: Recharts for real-time analytics

### Infrastructure
- **Containerization**: Docker & Docker Compose
- **Reverse Proxy**: Nginx with SSL/TLS support
- **Orchestration**: Docker Compose (production-ready)
- **Persistence**: Volumes for MongoDB and Redis

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                       │
│              TanStack Router + TanStack Query               │
│            Cloudflare Workers (SSR Support)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │ REST API & WebSocket (Nginx)  │
         └───────────────┬───────────────┘
                         │
┌─────────────────────────▼────────────────────────────────────┐
│                   FastAPI Backend                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ API Routes (HTTP)                                    │   │
│  │ - Auth (login, register, JWT refresh)               │   │
│  │ - Alerts (CRUD, correlation, status)                │   │
│  │ - Incidents (lifecycle management)                  │   │
│  │ - Detections (rules, packs, imports)                │   │
│  │ - Collectors (agent registration, ingestion)        │   │
│  │ - Response Actions (SOAR orchestration)             │   │
│  │ - Threat Hunting (campaigns, timelines)             │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ WebSocket Endpoint (/ws/alerts)                      │   │
│  │ - Real-time event streaming                         │   │
│  │ - Tenant-scoped connections                         │   │
│  │ - Event types: alert.created, incident.created, etc │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ AI/ML Services                                       │   │
│  │ - Anomaly Detection (scikit-learn)                  │   │
│  │ - Threat Classification & Scoring                   │   │
│  │ - Campaign Detection (pattern matching)             │   │
│  │ - MITRE ATT&CK Mapping                              │   │
│  │ - Correlation Engine                                │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Business Logic Services                              │   │
│  │ - Alert Management & Correlation                    │   │
│  │ - Incident Lifecycle                                │   │
│  │ - Response Action Execution                         │   │
│  │ - Collector Management                              │   │
│  │ - Rule & Pack Management                            │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Background Workers (Celery)                          │   │
│  │ - Alert Processing Pipeline                         │   │
│  │ - Threat Intelligence Updates                       │   │
│  │ - Campaign Detection Jobs                           │   │
│  │ - Scheduled Maintenance Tasks                       │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────┬─────────────┬──────────────┬─────────────────┘
               │             │              │
               ▼             ▼              ▼
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │ MongoDB  │  │ Redis    │  │ Celery   │
         │ (Data)   │  │ (Cache)  │  │ (Tasks)  │
         └──────────┘  └──────────┘  └──────────┘
```

### Key Components

**Backend Structure**
```
backend/
├── app/
│   ├── main.py              # Application factory & lifespan
│   ├── api/
│   │   ├── router.py        # Route registration
│   │   ├── dependencies.py  # Dependency injection
│   │   ├── routes/          # Feature-based route handlers
│   │   └── websockets.py    # WebSocket endpoint
│   ├── services/            # Business logic layer
│   ├── db/                  # MongoDB client & indexes
│   ├── core/                # Config, logging, middleware, security
│   ├── schemas/             # Pydantic request/response models
│   ├── realtime/            # WebSocket connection manager
│   └── common/              # Shared utilities
├── ai/                      # AI/ML domain modules
├── scripts/                 # Bootstrap & debug helpers
└── requirements.txt         # Python dependencies
```

**Frontend Structure**
```
frontend/
├── src/
│   ├── router.tsx          # TanStack Router setup
│   ├── server.ts           # Cloudflare Workers entry (SSR)
│   ├── lib/
│   │   ├── api.ts          # API client & token management
│   │   ├── auth.tsx        # Auth context & hooks
│   │   └── error-*.ts      # Error handling
│   ├── routes/             # Page components (file-based routing)
│   └── components/         # Reusable UI components
├── package.json            # Dependencies & scripts
├── vite.config.ts          # Vite/TanStack Start config
├── eslint.config.js        # Linting rules
└── tailwind.config.js      # Tailwind customization
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose 2.0+
- Node.js 18+ (for local frontend dev)
- Python 3.10+ (for local backend dev)
- Git

### Clean Docker Compose Startup

The root `docker-compose.yml` is the recommended new-laptop path. It starts the required development stack only: FastAPI backend, React/Vite frontend, MongoDB, and Redis.

```bash
# From the project root
cp .env.example .env
docker compose config
docker compose build
docker compose up
```

Service URLs:

```text
Backend:   http://localhost:8000
Frontend:  http://localhost:3000
API docs:  http://localhost:8000/docs
MongoDB:   mongodb://localhost:27017
Redis:     redis://localhost:6379/0
```

Useful troubleshooting commands:

```bash
docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f mongo
docker compose logs -f redis
docker compose down
docker compose down -v
```

## AI Security Copilot Phase 1

The Phase 1 copilot is deterministic and explainable. It does not call external AI APIs. It scores and summarizes from tenant-scoped alerts, incidents, MITRE mappings, SOAR history, and block context already stored by the platform.

### Features

- Alert triage with `risk_score`, priority, reasoning, recommended action, and MITRE mappings
- Incident summary with executive summary, root-cause guess, affected assets, attack timeline, recommended actions, and analyst next steps
- False-positive scoring with confidence, reasons, and suggested status
- Recommended incident actions: `block_ip`, `isolate_host`, `escalate_to_admin`, `monitor_only`, `close_false_positive`, `open_investigation`, `run_threat_hunt`
- Natural-language SOC query parser for failed logins, high-severity alerts, recent incidents, blocked IPs, DoS/DDoS activity, host alerts, and MITRE technique activity

### Endpoints

- `GET /api/ai/alerts/{alert_id}/triage`
- `GET /api/ai/alerts/{alert_id}/false-positive-score`
- `GET /api/ai/incidents/{incident_id}/summary`
- `GET /api/ai/incidents/{incident_id}/recommended-actions`
- `POST /api/ai/copilot/query`

All endpoints require JWT authentication and enforce organization isolation through the authenticated user's `organization_id`.

### Test Commands

```bash
cd backend && python -m pytest tests/test_ai_copilot.py
cd frontend && npm test -- --run src/lib/api.test.ts src/routes/_app.copilot.test.tsx src/components/soc/AiCopilotPanels.test.tsx
```

### Demo Script

1. Sign in as an analyst or admin.
2. Open Copilot and click `Show failed logins`.
3. Review the parsed intent, filters, suggested backend query, explanation, and preview.
4. Open Alerts and review the AI alert triage panel for the latest alert.
5. Open an incident detail page and review the AI incident summary and recommended actions.

## Threat Intelligence Engine Phase 2

Phase 2 adds deterministic IOC reputation, alert enrichment, incident enrichment, and Copilot threat lookup without paid or external intelligence APIs. The built-in demo feed is local, explainable, and safe for repeatable tests.

### Features

- IOC lookup for `ip`, `domain`, `url`, `hash`, and `email`
- Deterministic internal demo feed with malicious IPs, suspicious domains, phishing URLs, malware hashes, and brute-force source examples
- IOC normalization with exact matching, URL domain extraction, domain normalization, IP parsing, and hash parsing
- Alert enrichment from IOC-like fields such as `source_ip`, `destination_ip`, `domain`, `url`, `file_hash`, `hash`, and `email`
- Incident threat enrichment across correlated alerts
- Copilot threat parsing for IOC checks and threat feed questions

### Endpoints

- `GET /api/threat-intel/lookup?indicator={indicator}`
- `POST /api/threat-intel/bulk-lookup`
- `GET /api/threat-intel/feed`
- `POST /api/threat-intel/enrich-alert/{alert_id}`
- `POST /api/threat-intel/enrich-incident/{incident_id}`

All enrichment endpoints require JWT authentication and enforce organization isolation before reading alert or incident data.

### Demo Indicators

- `203.0.113.10` - malicious brute-force source IP
- `198.51.100.23` - malicious DoS/scanner source IP
- `evil.example` - malicious command-and-control domain
- `suspicious-login.example` - suspicious login infrastructure domain
- `https://phish.example/login` - malicious phishing URL
- `44d88612fea8a8f36de82e1278abb02f` - malware hash example
- `8.8.8.8` - clean IP example

### Example Copilot Questions

- `is 203.0.113.10 malicious?`
- `check ip 198.51.100.23`
- `lookup domain evil.example`
- `check hash 44d88612fea8a8f36de82e1278abb02f`
- `show malicious indicators`
- `show threat feed`

### Test Commands

```bash
cd backend && python -m pytest tests/test_threat_intel.py
cd backend && python -m pytest tests/test_ai_copilot.py
cd frontend && npm run test
cd frontend && npx tsc --noEmit
cd frontend && npm run build
```

## 🕸️ Attack Graph Visualization

Incident Investigation includes an **Attack Graph** section that reconstructs deterministic relationships from existing incident data. It helps analysts quickly understand how a source IP, target host or endpoint, alert chain, incident record, MITRE mapping, and SOAR response are connected.

Purpose:

- Visualize investigation context without changing the incident model
- Make DoS/DDoS response flow easy to inspect from the incident page
- Show how alerts, infrastructure context, MITRE techniques, and SOAR actions relate

Flow examples:

- **DoS/DDoS**: `Source IP -> Target Endpoint -> Alert -> Incident -> SOAR Action`
- **Brute force/auth**: `Source IP -> Host/User -> Alert -> Incident -> MITRE Technique`

The backend endpoint is:

```text
GET /api/v1/incidents/{incident_id}/attack-graph
```

### Screenshot Checklist

- Incident investigation page with the **Attack Graph** section visible
- DoS/DDoS example showing `source_ip`, `endpoint`, `alert`, `incident`, and `soar_action`
- Brute force/auth example showing `source_ip`, `host` or `user`, `alert`, `incident`, and `mitre_technique`
- Incident with a linked MITRE technique node rendered in gray
- Incident page loading, error, and no-data states verified

### Collector Lifecycle (Windows + Linux)

Windows (Admin PowerShell):

```powershell
cd C:\ai-soc-windows-collector
.\install.ps1
.\install.ps1 -Repair
.\install.ps1 -Status
.\install.ps1 -Test
Get-Service AISOCWindowsCollector
Restart-Service AISOCWindowsCollector
```

Linux:

```bash
cd collector-agent/linux
sudo bash install.sh
sudo bash install.sh --repair
sudo bash install.sh --status
sudo bash install.sh --test
sudo systemctl restart ai-soc-linux-collector
sudo bash uninstall.sh
```

Expected:
- Windows service `AISOCWindowsCollector` is `Automatic` and `Running`.
- Linux service `ai-soc-linux-collector` is `enabled` and `active`.
- Test events are accepted with:
  - `windows_collector_test`
  - `linux_collector_test`
  - `source = configured source_name`
  - `severity = low`

### One-Command Startup (Docker)

```bash
# Clone the repository
git clone https://github.com/Shyam-2315/SOC_AI-Agent.git
cd SOC_AI-Agent

# Copy environment template and configure
cp backend/.env.example backend/.env
# Edit backend/.env with your configuration

# Start the full stack with demo data
./start.sh --build --seed-demo
```

This command:
- Starts all services (FastAPI, React, MongoDB, Redis, Celery, Nginx)
- Seeds demo data with sample alerts and incidents
- Prints service URLs and default credentials

**Access the Platform**
```
Frontend:   http://localhost:8080
Nginx UI:   http://localhost
API Docs:   http://localhost/docs (if DOCS_ENABLED=true)
WebSocket:  ws://localhost/ws/alerts?token=<jwt>

Demo Credentials:
Email:    demo.admin@aisoc.dev
Password: DemoAdmin123!
```

### Local Development

**Backend (Uvicorn)**
```bash
cd backend

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start MongoDB and Redis
docker compose -f docker-compose.prod.yml -f docker-compose.local.yml up -d mongo redis

# Update .env for local host access
export MONGO_URL=mongodb://ai_soc_app:MongoApp123@localhost:27017/ai_soc?authSource=ai_soc
export REDIS_URL=redis://:Redis123@localhost:6379/0

# Start the backend API
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

**Frontend (Vite)**
```bash
cd frontend
npm install
npm run dev
```

**Start Celery Worker (for background tasks)**
```bash
cd backend
source venv/bin/activate
celery -A app.workers.celery_app.celery_app worker --loglevel=info -Q alert-processing
```

### Useful Commands

```bash
# View service status
./status.sh

# View logs
./logs.sh                 # All services
./logs.sh app             # Backend only
./logs.sh frontend        # Frontend only
./logs.sh nginx           # Reverse proxy

# Restart services
./restart.sh

# Stop all services
./stop.sh

# Seed demo data (after startup)
docker compose -f backend/docker-compose.prod.yml exec app python scripts/seed_demo.py

# Run smoke tests
python backend/scripts/production_smoke.py
```

## 📁 Project Structure

### Root Level
```
SOC_AI-Agent/
├── backend/                      # FastAPI backend
│   ├── app/                      # Application code
│   ├── ai/                       # AI/ML modules
│   ├── scripts/                  # Setup & utility scripts
│   ├── docker-compose.*.yml      # Compose files
│   ├── requirements.txt          # Python packages
│   ├── .env.example              # Configuration template
│   └── README.md                 # Backend-specific docs
│
├── frontend/                     # React/TypeScript frontend
│   ├── src/                      # Source code
│   ├── package.json              # Node dependencies
│   ├── vite.config.ts            # Build configuration
│   └── tsconfig.json             # TypeScript config
│
├── docker/                       # Dockerfile definitions
├── FRONTEND_BACKEND_RUN.md       # Local development guide
├── start.sh                      # Start all services
├── stop.sh                       # Stop services
├── restart.sh                    # Restart services
├── status.sh                     # Check service health
├── logs.sh                       # View logs
└── README.md                     # This file
```

## 🔌 API Documentation

### Authentication
```bash
# Login
curl -X POST http://localhost/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 3600
}

# Use JWT in subsequent requests
curl -X GET http://localhost/alerts \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Alert Ingestion
```bash
# Create a collector (requires JWT)
curl -X POST http://localhost/collectors \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-linux-1","type":"linux"}'

# Ingest logs (uses collector token)
curl -X POST http://localhost/collector/ingest \
  -H "X-Collector-Token: $COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{
      "source": "linux",
      "event_type": "ssh_attack",
      "severity": "high",
      "message": "failed login from 192.168.1.100",
      "ip_address": "192.168.1.100"
    }]
  }'
```

### Detection Rules
```bash
# Create a detection rule
curl -X POST http://localhost/rules \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSH Brute Force",
    "description": "Multiple failed SSH attempts",
    "severity": "high",
    "conditions": [
      {"field": "message", "operator": "contains", "value": "failed login"}
    ],
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110 - Brute Force",
    "enabled": true
  }'

# List rules
curl http://localhost/rules -H "Authorization: Bearer $JWT"
```

### Real-time WebSocket
```bash
# Connect to alert stream
ws://localhost/ws/alerts?token=$JWT_TOKEN

# Listen for events
{
  "event_type": "soc.alert.created",
  "data": {
    "id": "alert_123",
    "title": "SSH Brute Force Detected",
    "severity": "high",
    "status": "open"
  }
}
```

**Supported Events**
- `soc.alert.created` - New alert triggered
- `soc.alert.updated` - Alert status changed
- `soc.incident.created` - Incident created
- `soc.response_action.created` - Automated action executed

See the full [Backend README](backend/README.md) for detailed API documentation.

## ⚙️ Configuration

### Environment Variables

Create `backend/.env` from `backend/.env.example`:

```env
# FastAPI
APP_NAME=SOC AI Agent
APP_VERSION=1.0.0
ENVIRONMENT=production
DEBUG=false
DOCS_ENABLED=false

# Database
MONGO_URL=mongodb://ai_soc_app:MongoApp123@mongo:27017/ai_soc?authSource=ai_soc
DATABASE_NAME=ai_soc

# Cache & Messaging
REDIS_URL=redis://:Redis123@redis:6379/0
CELERY_BROKER_URL=redis://:Redis123@redis:6379/0

# Authentication
JWT_SECRET=your-super-secret-key-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Collector Ingestion
COLLECTOR_API_KEYS=test-collector-token
COLLECTOR_BATCH_MAX_SIZE=100

# DoS / DDoS protection
DOS_IP_REQUESTS_PER_MINUTE=100
DOS_IP_ERRORS_PER_MINUTE=30
DDOS_ENDPOINT_REQUESTS_PER_MINUTE=1000
DDOS_ENDPOINT_UNIQUE_IPS_PER_MINUTE=50
AUTO_BLOCK_DOS_IPS=false

# Frontend
VITE_API_BASE_URL=http://localhost
VITE_WS_BASE_URL=ws://localhost

# CORS
CORS_ORIGINS=["http://localhost:8080","http://localhost"]
CORS_ALLOW_CREDENTIALS=true

# Demo Mode
DEMO_MODE=false
DEMO_ORG_NAME=Demo SOC
DEMO_ADMIN_EMAIL=demo.admin@aisoc.dev
DEMO_ADMIN_PASSWORD=DemoAdmin123!
```

See `backend/.env.example` for the complete configuration reference.

### DoS / DDoS Detection Architecture

The platform now includes a traffic security layer for **safe, internal DoS/DDoS detection and blocking**:

- Every HTTP request is tracked with source IP, path, method, status code, user agent, and tenant when available
- Redis-backed 1-minute counters detect:
  - single-IP request floods
  - single-IP error-rate abuse
  - endpoint request spikes
  - many unique IPs targeting the same endpoint
- Detections create:
  - SOC alerts
  - incidents
  - SOAR response actions
  - realtime events
- Blocking is **application-level only**
  - no `iptables`
  - no OS firewall mutation
  - health endpoints remain accessible even for blocked IPs

Tracked Redis keys:

```text
traffic:ip:{source_ip}:1m
traffic:ip:{source_ip}:errors:1m
traffic:endpoint:{path}:1m
traffic:endpoint:{path}:unique_ips
blocklist:ip:{ip}
```

Security APIs:

```text
GET  /security/traffic/summary
GET  /security/blocked-ips
POST /security/block-ip
POST /security/unblock-ip
```

Compatibility aliases are also exposed under `/api/v1/security/...`.

### DoS / DDoS Demo

Example single-IP flood simulation against the existing health endpoint:

```bash
for i in {1..120}; do curl -s http://localhost/health > /dev/null; done
```

Expected result:

- traffic counters increase
- a `dos_attack` alert appears
- a DoS incident is created
- a SOAR block recommendation appears
- if `AUTO_BLOCK_DOS_IPS=true`, the source IP is internally blocked for 15 minutes

Example endpoint fan-out simulation:

```bash
for ip in 10.0.0.11 10.0.0.12 10.0.0.13 10.0.0.14; do
  curl -s http://localhost/alerts/ -H "X-Forwarded-For: $ip" > /dev/null
done
```

Expected result:

- targeted endpoint counters increase
- a `ddos_attack` alert appears
- a `DDoS Activity Targeting /alerts/` incident is created
- the security dashboard shows the targeted endpoint and recent detections

### Screenshot Checklist

- Traffic Security page with requests/minute and top source IPs
- Recent DoS detection with evidence counts
- Recent DDoS detection with targeted endpoint
- Blocked IP list
- SOAR action showing recommended or simulated IP block

### Docker Compose Files

- `backend/docker-compose.prod.yml` - Production-ready configuration
- `backend/docker-compose.local.yml` - Local overrides (host access)
- `start.sh` - Orchestrates multiple compose files

## 🚢 Deployment

### Docker Stack
```bash
# Build images
docker compose -f backend/docker-compose.prod.yml build

# Start with persistent volumes
docker compose -f backend/docker-compose.prod.yml up -d

# Verify health
curl http://localhost/health/ready

# View logs
docker compose -f backend/docker-compose.prod.yml logs -f
```

### Kubernetes (Helm)
For production Kubernetes deployments, additional Helm charts would be needed. The Docker Compose setup provides a solid foundation for containerized deployments.

### Nginx Configuration
- Frontend served on port 8080
- API proxied through Nginx on ports 80/443
- SSL/TLS support via `NGINX_SSL_ENABLED` and certificate paths
- Client body size limits configurable

### Security Considerations
- **Keep JWT_SECRET secure** - Use environment-specific values
- **Enable HTTPS_REDIRECT** in production
- **Configure TRUSTED_HOSTS** appropriately
- **Implement rate limiting** via AUTH_RATE_LIMIT_PER_MINUTE
- **Use strong database passwords**
- **Enable RBAC** - Don't use overly permissive roles
- **Audit collector tokens** - Rotate regularly

## 💻 Development

### Code Style
```bash
# Frontend
cd frontend
npm run lint      # Check code quality
npm run format    # Format with Prettier

# Backend
cd backend
# Use pyright (configured in VSCode)
# Or: pip install pyright && pyright .
```

### Local Testing
```bash
# Backend unit tests (add when ready)
pytest backend/app/tests/

# Frontend tests
npm run test

# Smoke tests
python backend/scripts/production_smoke.py
```

### Extending the Platform

**Adding a New Detection Rule Type**
1. Add condition type to `backend/app/schemas/rule.py`
2. Implement evaluation logic in `backend/app/ai/rule_evaluator.py`
3. Update the frontend rule builder component

**Adding a New AI Module**
1. Create `backend/ai/your_module.py`
2. Implement async-compatible functions
3. Import in `backend/ai/__init__.py`
4. Wire into service layer in `backend/app/services/`

**Adding a New API Endpoint**
1. Create route file in `backend/app/api/routes/`
2. Register in `backend/app/api/router.py`
3. Define Pydantic schemas in `backend/app/schemas/`
4. Implement business logic in `backend/app/services/`

## 📚 Additional Resources

- [Backend README](backend/README.md) - Detailed backend documentation
- [Frontend Backend Run Guide](FRONTEND_BACKEND_RUN.md) - Local development setup
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [TanStack Documentation](https://tanstack.com/)
- [MongoDB Manual](https://docs.mongodb.com/manual/)
- [Redis Documentation](https://redis.io/documentation)

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Check which process is using ports 80, 443, or 8080
lsof -i :80
lsof -i :443
lsof -i :8080

# Or update port mappings in backend/docker-compose.prod.yml
```

### MongoDB Connection Issues
```bash
# Test MongoDB connectivity
docker compose -f backend/docker-compose.prod.yml logs mongo

# Verify credentials in .env
# Check MongoDB is running
docker compose -f backend/docker-compose.prod.yml ps
```

### Frontend Not Loading
```bash
# Check frontend container logs
./logs.sh frontend

# Verify VITE_API_BASE_URL is set correctly
# Clear browser cache and refresh
```

### WebSocket Connection Failed
```bash
# Ensure WS endpoint is properly configured
# Check JWT token validity (24 hour default expiry)
# Verify WEBSOCKET_SEND_QUEUE_SIZE in .env
# Check Nginx proxy_pass for WebSocket upgrade headers
```

## 📄 License

This project is provided as-is. Refer to your organization's policies for licensing and distribution.

## 👥 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For issues, questions, or feedback:
- Check existing issues: https://github.com/Shyam-2315/SOC_AI-Agent/issues
- Review the documentation in `backend/README.md` and `FRONTEND_BACKEND_RUN.md`
- Check service health with `./status.sh`

---

<div align="center">

**Built with ❤️ for modern security operations**

[⬆ back to top](#-soc-ai-agent---enterprise-security-operations-center-platform)

</div>
