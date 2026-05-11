from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


REALTIME_EVENT_VERSION = "1.0"
DEFAULT_EVENT_TYPE = "soc.alert.created"


def build_realtime_event(
    *,
    event_type: str,
    organization_id: str,
    payload: dict[str, Any],
    event_id: str | None = None,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    timestamp = occurred_at or datetime.now(timezone.utc)
    return {
        "event_id": event_id or str(uuid4()),
        "event_type": event_type,
        "organization_id": organization_id,
        "occurred_at": timestamp.isoformat(),
        "version": REALTIME_EVENT_VERSION,
        "payload": payload,
    }


def build_system_message(
    *,
    event_type: str,
    organization_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return build_realtime_event(
        event_type=event_type,
        organization_id=organization_id,
        payload=payload,
    )
