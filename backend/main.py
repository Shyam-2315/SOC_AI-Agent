from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.routes.alerts import router as alerts_router
from api.routes.auth import router as auth_router
from api.routes.copilot import router as copilot_router
from api.routes.incidents import router as incidents_router
from api.routes.ingestion import router as ingestion_router
from api.routes.logs import router as logs_router
from api.routes.organizations import router as organizations_router
from api.routes.soar import router as soar_router
from api.routes.threat_hunting import router as threat_hunting_router
from core.config import settings
from core.database import close_database, create_indexes, ping_database
from core.dependencies import get_websocket_user
from websocket.manager import manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ping_database()
    await create_indexes()
    yield
    await close_database()


app = FastAPI(
    title="AI SOC Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion_router)
app.include_router(auth_router)
app.include_router(organizations_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(soar_router)
app.include_router(threat_hunting_router)
app.include_router(copilot_router)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    user = await get_websocket_user(websocket)
    if user is None:
        return

    organization_id = user["organization_id"]
    await manager.connect(websocket, organization_id)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, organization_id)


@app.get("/")
def root():
    return {
        "message": "AI SOC Platform Running",
    }


@app.get("/health")
async def health():
    await ping_database()
    return {
        "status": "healthy",
    }
