from dataclasses import dataclass
from enum import Enum
import os
from typing import Optional

from dotenv import load_dotenv


def _load_environment_files() -> None:
    load_dotenv(".env")


_load_environment_files()


class Environment(str, Enum):
    development = "development"
    staging = "staging"
    production = "production"


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _csv_env(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    raise RuntimeError(f"{name} must be a boolean value")


def _int_env(
    name: str,
    default: int,
    *,
    minimum: Optional[int] = None,
) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        value = default
    else:
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise RuntimeError(f"{name} must be an integer") from exc

    if minimum is not None and value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")

    return value


def _optional_env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None

    stripped = value.strip()
    return stripped or None


def _collector_keys(raw_value: Optional[str]) -> dict[str, str]:
    keys: dict[str, str] = {}
    if not raw_value:
        return keys

    for item in raw_value.split(","):
        entry = item.strip()
        if not entry:
            continue

        token, separator, organization_id = entry.partition(":")
        if not separator or not token or not organization_id:
            raise RuntimeError(
                "COLLECTOR_API_KEYS must use token:organization_id entries"
            )

        keys[token] = organization_id

    return keys


def _environment() -> Environment:
    raw_value = os.getenv("ENVIRONMENT", Environment.development.value).strip().lower()
    try:
        return Environment(raw_value)
    except ValueError as exc:
        allowed = ", ".join(environment.value for environment in Environment)
        raise RuntimeError(f"ENVIRONMENT must be one of: {allowed}") from exc


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_version: str
    environment: Environment
    debug: bool
    docs_enabled: bool
    log_level: str
    log_json: bool
    trusted_hosts: list[str]
    https_redirect: bool
    cors_origins: list[str]
    cors_allow_credentials: bool
    mongo_url: str
    database_name: str
    mongo_server_selection_timeout_ms: int
    mongo_connect_timeout_ms: int
    mongo_socket_timeout_ms: int
    mongo_max_pool_size: int
    mongo_min_pool_size: int
    jwt_secret: str
    jwt_algorithm: str
    jwt_issuer: Optional[str]
    jwt_audience: Optional[str]
    access_token_expire_minutes: int
    public_registration_enabled: bool
    redis_url: Optional[str]
    alert_processing_mode: str
    celery_broker_url: Optional[str]
    celery_result_backend: Optional[str]
    celery_task_default_queue: str
    celery_worker_concurrency: int
    realtime_events_channel: str
    websocket_send_queue_size: int
    collector_api_keys: dict[str, str]
    collector_batch_max_size: int
    syslog_enabled: bool
    syslog_host: str
    syslog_port: int
    syslog_collector_token: Optional[str]
    auth_rate_limit_per_minute: int
    ingestion_rate_limit_per_minute: int

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.production

    @property
    def celery_enabled(self) -> bool:
        return self.alert_processing_mode == "celery"

    def validate(self) -> None:
        if self.log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise RuntimeError(
                "LOG_LEVEL must be one of: CRITICAL, ERROR, WARNING, INFO, DEBUG"
            )

        if self.cors_allow_credentials and "*" in self.cors_origins:
            raise RuntimeError(
                "CORS_ORIGINS cannot contain '*' when CORS_ALLOW_CREDENTIALS is enabled"
            )

        if len(self.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET must be at least 32 characters long")

        if self.alert_processing_mode not in {"sync", "celery"}:
            raise RuntimeError("ALERT_PROCESSING_MODE must be either 'sync' or 'celery'")

        if self.celery_enabled and not self.redis_url:
            raise RuntimeError(
                "REDIS_URL is required when ALERT_PROCESSING_MODE=celery"
            )

        if self.celery_enabled and not self.celery_broker_url:
            raise RuntimeError(
                "CELERY_BROKER_URL is required when ALERT_PROCESSING_MODE=celery"
            )

        if self.syslog_enabled and self.is_production and not self.syslog_collector_token:
            raise RuntimeError(
                "SYSLOG_COLLECTOR_TOKEN is required when SYSLOG_ENABLED=true in production"
            )

        if self.is_production:
            required_production_vars = (
                "COLLECTOR_API_KEYS",
                "MONGO_INITDB_ROOT_PASSWORD",
                "MONGO_APP_PASSWORD",
                "REDIS_PASSWORD",
                "NGINX_SERVER_NAME",
            )
            for name in required_production_vars:
                value = os.getenv(name, "").strip()
                if not value or value.startswith("replace-with"):
                    raise RuntimeError(f"{name} must be set for production")

            if self.docs_enabled:
                raise RuntimeError("DOCS_ENABLED must be false in production")


environment = _environment()
default_docs_enabled = environment != Environment.production
redis_url = _optional_env("REDIS_URL")
celery_broker_url = _optional_env("CELERY_BROKER_URL") or redis_url
celery_result_backend = _optional_env("CELERY_RESULT_BACKEND") or celery_broker_url

settings = Settings(
    app_name=os.getenv("APP_NAME", "AI SOC Platform").strip() or "AI SOC Platform",
    app_version=os.getenv("APP_VERSION", "1.0.0").strip() or "1.0.0",
    environment=environment,
    debug=_bool_env("DEBUG", environment != Environment.production),
    docs_enabled=_bool_env("DOCS_ENABLED", default_docs_enabled),
    log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO",
    log_json=_bool_env("LOG_JSON", environment == Environment.production),
    trusted_hosts=_csv_env("TRUSTED_HOSTS", "localhost,127.0.0.1,testserver"),
    https_redirect=_bool_env("HTTPS_REDIRECT", environment == Environment.production),
    cors_origins=_csv_env(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ),
    cors_allow_credentials=_bool_env("CORS_ALLOW_CREDENTIALS", True),
    mongo_url=_required_env("MONGO_URL"),
    database_name=_required_env("DATABASE_NAME"),
    mongo_server_selection_timeout_ms=_int_env(
        "MONGO_SERVER_SELECTION_TIMEOUT_MS",
        5000,
        minimum=1000,
    ),
    mongo_connect_timeout_ms=_int_env(
        "MONGO_CONNECT_TIMEOUT_MS",
        5000,
        minimum=1000,
    ),
    mongo_socket_timeout_ms=_int_env(
        "MONGO_SOCKET_TIMEOUT_MS",
        10000,
        minimum=1000,
    ),
    mongo_max_pool_size=_int_env("MONGO_MAX_POOL_SIZE", 100, minimum=1),
    mongo_min_pool_size=_int_env("MONGO_MIN_POOL_SIZE", 0, minimum=0),
    jwt_secret=_required_env("JWT_SECRET"),
    jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256").strip().upper() or "HS256",
    jwt_issuer=_optional_env("JWT_ISSUER"),
    jwt_audience=_optional_env("JWT_AUDIENCE"),
    access_token_expire_minutes=_int_env(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        60,
        minimum=1,
    ),
    public_registration_enabled=_bool_env(
        "PUBLIC_REGISTRATION_ENABLED",
        environment != Environment.production,
    ),
    redis_url=redis_url,
    alert_processing_mode=os.getenv("ALERT_PROCESSING_MODE", "sync").strip().lower()
    or "sync",
    celery_broker_url=celery_broker_url,
    celery_result_backend=celery_result_backend,
    celery_task_default_queue=os.getenv(
        "CELERY_TASK_DEFAULT_QUEUE",
        "alert-processing",
    ).strip()
    or "alert-processing",
    celery_worker_concurrency=_int_env("CELERY_WORKER_CONCURRENCY", 4, minimum=1),
    realtime_events_channel=(
        os.getenv("REALTIME_EVENTS_CHANNEL")
        or os.getenv("ALERT_EVENTS_CHANNEL")
        or "realtime-events"
    ).strip(),
    websocket_send_queue_size=_int_env("WEBSOCKET_SEND_QUEUE_SIZE", 500, minimum=10),
    collector_api_keys=_collector_keys(os.getenv("COLLECTOR_API_KEYS")),
    collector_batch_max_size=_int_env(
        "COLLECTOR_BATCH_MAX_SIZE",
        100,
        minimum=1,
    ),
    syslog_enabled=_bool_env("SYSLOG_ENABLED", False),
    syslog_host=os.getenv("SYSLOG_HOST", "0.0.0.0").strip() or "0.0.0.0",
    syslog_port=_int_env("SYSLOG_PORT", 5514, minimum=1),
    syslog_collector_token=_optional_env("SYSLOG_COLLECTOR_TOKEN"),
    auth_rate_limit_per_minute=_int_env("AUTH_RATE_LIMIT_PER_MINUTE", 20, minimum=1),
    ingestion_rate_limit_per_minute=_int_env(
        "INGESTION_RATE_LIMIT_PER_MINUTE",
        120,
        minimum=1,
    ),
)

settings.validate()
