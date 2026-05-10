from motor.motor_asyncio import AsyncIOMotorClient
from core.config import MONGO_URL, DATABASE_NAME
import os

MONGO_URL = os.getenv("MONGO_URL")

try:
    client = AsyncIOMotorClient(MONGO_URL)

    db = client["ai_soc"]

    logs_collection = db["logs"]
    alerts_collection = db["alerts"]
    incidents_collection = db["incidents"]
    users_collection = db["users"]

    print("✅ MongoDB Connected Successfully")

except Exception as e:
    print("❌ MongoDB Connection Failed")
    print(e)