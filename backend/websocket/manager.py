from collections import defaultdict
from typing import DefaultDict, List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: DefaultDict[str, List[WebSocket]] = defaultdict(list)

    async def connect(
        self,
        websocket: WebSocket,
        organization_id: str,
    ):
        await websocket.accept()
        self.active_connections[organization_id].append(websocket)

    def disconnect(
        self,
        websocket: WebSocket,
        organization_id: str,
    ):
        connections = self.active_connections.get(organization_id, [])
        if websocket in connections:
            connections.remove(websocket)
        if not connections and organization_id in self.active_connections:
            del self.active_connections[organization_id]

    async def broadcast(
        self,
        message: dict,
        organization_id: str,
    ):
        stale_connections = []

        for connection in self.active_connections.get(organization_id, []):
            try:
                await connection.send_json(message)
            except Exception:
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(connection, organization_id)


manager = ConnectionManager()
