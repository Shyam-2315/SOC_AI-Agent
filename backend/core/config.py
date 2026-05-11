from app.core.config import Environment, Settings, settings

MONGO_URL = settings.mongo_url
DATABASE_NAME = settings.database_name
JWT_SECRET = settings.jwt_secret
REDIS_URL = settings.redis_url
CELERY_BROKER_URL = settings.celery_broker_url

__all__ = [
    "CELERY_BROKER_URL",
    "DATABASE_NAME",
    "Environment",
    "JWT_SECRET",
    "MONGO_URL",
    "REDIS_URL",
    "Settings",
    "settings",
]
