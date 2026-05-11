import json

from fastapi import WebSocket, WebSocketDisconnect

from app.api.dependencies import get_websocket_user
from app.realtime.events import build_system_message
from app.realtime.manager import manager


def _system_event(
    *,
    organization_id: str,
    event_type: str,
    payload: dict,
) -> dict:
    return build_system_message(
        event_type=event_type,
        organization_id=organization_id,
        payload=payload,
    )


async def websocket_alerts(websocket: WebSocket) -> None:
    user = await get_websocket_user(websocket)
    if user is None:
        return

    organization_id = user["organization_id"]
    session = await manager.connect(websocket, organization_id)
    await session.send_queue.put(
        _system_event(
            organization_id=organization_id,
            event_type="system.connected",
            payload={
                "connection_id": session.connection_id,
                "subscriptions": sorted(session.subscriptions),
            },
        )
    )

    try:
        while True:
            raw_message = await websocket.receive_text()
            await _handle_client_message(
                raw_message=raw_message,
                organization_id=organization_id,
                session=session,
            )
    except WebSocketDisconnect:
        manager.disconnect(session)


async def _handle_client_message(
    *,
    raw_message: str,
    organization_id: str,
    session,
) -> None:
    message = raw_message.strip()
    if not message:
        return

    if message.lower() == "ping":
        await session.send_queue.put(
            _system_event(
                organization_id=organization_id,
                event_type="system.pong",
                payload={},
            )
        )
        return

    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        return

    action = payload.get("action")
    event_types = payload.get("event_types", [])

    if action == "subscribe":
        subscriptions = manager.update_subscriptions(
            session,
            event_types,
            replace=bool(payload.get("replace")),
        )
        await session.send_queue.put(
            _system_event(
                organization_id=organization_id,
                event_type="system.subscriptions.updated",
                payload={"subscriptions": sorted(subscriptions)},
            )
        )
        return

    if action == "unsubscribe":
        subscriptions = manager.remove_subscriptions(session, event_types)
        await session.send_queue.put(
            _system_event(
                organization_id=organization_id,
                event_type="system.subscriptions.updated",
                payload={"subscriptions": sorted(subscriptions)},
            )
        )
        return
