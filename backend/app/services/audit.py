from datetime import datetime, timezone
from typing import Any
import asyncio

from app.core.logging import get_logger
from app.db.client import audit_events_collection


logger = get_logger(__name__)


async def write_audit_event(
    *,
    event_type: str,
    actor: dict[str, Any] | None = None,
    organization_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "success",
    metadata: dict[str, Any] | None = None,
) -> None:
    document = {
        "event_type": event_type,
        "organization_id": organization_id or (actor or {}).get("organization_id"),
        "actor_user_id": (actor or {}).get("user_id"),
        "actor_email": (actor or {}).get("email"),
        "actor_role": (actor or {}).get("role"),
        "target_type": target_type,
        "target_id": target_id,
        "outcome": outcome,
        "metadata": metadata or {},
        "timestamp": datetime.now(timezone.utc),
    }
    try:
        await asyncio.wait_for(
            audit_events_collection.insert_one(document),
            timeout=2.0,
        )
    except Exception:
        logger.exception(
            "failed to write audit event",
            extra={"event_type": event_type, "organization_id": document["organization_id"]},
        )
