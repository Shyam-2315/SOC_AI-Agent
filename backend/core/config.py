from dataclasses import dataclass
import os
from typing import Dict, List, Optional

from dotenv import load_dotenv


load_dotenv()


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _csv_env(name: str, default: str = "") -> List[str]:
    return [
        item.strip()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    ]


def _collector_keys(raw_value: Optional[str]) -> Dict[str, str]:
    keys: Dict[str, str] = {}
    if not raw_value:
        return keys

    for item in raw_value.split(","):
        item = item.strip()
        if not item:
            continue

        token, separator, organization_id = item.partition(":")
        if not separator or not token or not organization_id:
            raise RuntimeError(
                "COLLECTOR_API_KEYS must use token:organization_id entries"
            )

        keys[token] = organization_id

    return keys


@dataclass(frozen=True)
class Settings:
    mongo_url: str
    database_name: str
    jwt_secret: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    cors_origins: List[str]
    redis_url: Optional[str]
    collector_api_keys: Dict[str, str]


settings = Settings(
    mongo_url=_required_env("MONGO_URL"),
    database_name=_required_env("DATABASE_NAME"),
    jwt_secret=_required_env("JWT_SECRET"),
    jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
    access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")),
    cors_origins=_csv_env(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ),
    redis_url=os.getenv("REDIS_URL"),
    collector_api_keys=_collector_keys(os.getenv("COLLECTOR_API_KEYS")),
)


MONGO_URL = settings.mongo_url
DATABASE_NAME = settings.database_name
JWT_SECRET = settings.jwt_secret
REDIS_URL = settings.redis_url
