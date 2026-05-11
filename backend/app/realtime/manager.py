import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import DefaultDict
from uuid import uuid4

from fastapi import WebSocket

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


@dataclass
class ConnectionSession:
    connection_id: str
    organization_id: str
    websocket: WebSocket
    subscriptions: set[str] = field(default_factory=lambda: {"*"})
    send_queue: asyncio.Queue[dict] = field(
        default_factory=lambda: asyncio.Queue(maxsize=settings.websocket_send_queue_size)
    )
    writer_task: asyncio.Task | None = None


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: DefaultDict[str, dict[str, ConnectionSession]] = (
            defaultdict(dict)
        )

    async def connect(
        self,
        websocket: WebSocket,
        organization_id: str,
    ) -> ConnectionSession:
        await websocket.accept()
        session = ConnectionSession(
            connection_id=str(uuid4()),
            organization_id=organization_id,
            websocket=websocket,
        )
        session.writer_task = asyncio.create_task(self._writer(session))
        self.active_connections[organization_id][session.connection_id] = session
        return session

    def disconnect(
        self,
        session: ConnectionSession,
    ) -> None:
        organization_id = session.organization_id
        connections = self.active_connections.get(organization_id, {})
        connections.pop(session.connection_id, None)
        if (
            session.writer_task is not None
            and session.writer_task is not asyncio.current_task()
        ):
            session.writer_task.cancel()
        if not connections and organization_id in self.active_connections:
            del self.active_connections[organization_id]

    def update_subscriptions(
        self,
        session: ConnectionSession,
        event_types: list[str],
        *,
        replace: bool = False,
    ) -> set[str]:
        normalized = {
            event_type.strip()
            for event_type in event_types
            if isinstance(event_type, str) and event_type.strip()
        }

        if not normalized:
            return set(session.subscriptions)

        if replace:
            session.subscriptions = normalized
        else:
            session.subscriptions.update(normalized)

        return set(session.subscriptions)

    def remove_subscriptions(
        self,
        session: ConnectionSession,
        event_types: list[str],
    ) -> set[str]:
        for event_type in event_types:
            if isinstance(event_type, str):
                session.subscriptions.discard(event_type.strip())

        if not session.subscriptions:
            session.subscriptions = {"*"}

        return set(session.subscriptions)

    async def publish(
        self,
        event: dict,
    ) -> None:
        organization_id = event["organization_id"]
        event_type = event["event_type"]
        stale_connections: list[ConnectionSession] = []
        for session in self.active_connections.get(organization_id, {}).values():
            if not self._is_subscribed(session, event_type):
                continue
            try:
                session.send_queue.put_nowait(event)
            except Exception:
                stale_connections.append(session)

        for session in stale_connections:
            logger.warning(
                "disconnecting websocket due to send queue pressure",
                extra={
                    "organization_id": organization_id,
                    "connection_id": session.connection_id,
                },
            )
            self.disconnect(session)

    def get_connection_stats(self) -> dict[str, int]:
        organizations = len(self.active_connections)
        connections = sum(
            len(organization_connections)
            for organization_connections in self.active_connections.values()
        )
        return {
            "organizations": organizations,
            "connections": connections,
        }

    async def _writer(self, session: ConnectionSession) -> None:
        try:
            while True:
                event = await session.send_queue.get()
                await session.websocket.send_json(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "websocket writer failed",
                extra={
                    "organization_id": session.organization_id,
                    "connection_id": session.connection_id,
                },
            )
        finally:
            self.disconnect(session)

    @staticmethod
    def _is_subscribed(
        session: ConnectionSession,
        event_type: str,
    ) -> bool:
        subscriptions = session.subscriptions
        return "*" in subscriptions or event_type in subscriptions


manager = ConnectionManager()
