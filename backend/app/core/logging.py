from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
from logging.config import dictConfig

from app.core.config import Settings


request_id_context: ContextVar[str] = ContextVar("request_id", default="-")


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_context.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }

        for attribute in (
            "method",
            "path",
            "status_code",
            "duration_ms",
            "client_ip",
            "environment",
            "user_id",
            "organization_id",
            "event_type",
        ):
            value = getattr(record, attribute, None)
            if value is not None:
                payload[attribute] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def configure_logging(settings: Settings) -> None:
    formatter_name = "json" if settings.log_json else "standard"
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "request_context": {
                    "()": RequestContextFilter,
                }
            },
            "formatters": {
                "standard": {
                    "format": (
                        "%(asctime)s %(levelname)s [%(name)s] "
                        "[request_id=%(request_id)s] %(message)s"
                    )
                },
                "json": {
                    "()": JsonFormatter,
                },
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "formatter": formatter_name,
                    "filters": ["request_context"],
                }
            },
            "root": {
                "handlers": ["default"],
                "level": settings.log_level,
            },
        }
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
