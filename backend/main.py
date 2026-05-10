from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.ingestion import router as ingestion_router
from api.routes.auth import router as auth_router
from api.routes.incidents import router as incidents_router

app = FastAPI(
    title="AI SOC Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion_router)
app.include_router(auth_router)
app.include_router(incidents_router)


@app.get("/")
def root():

    return {
        "message": "AI SOC Platform Running"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }