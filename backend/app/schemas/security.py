from app.schemas.base import APIModel


class SecurityBlockRequest(APIModel):
    ip: str
    reason: str | None = None
    duration_minutes: int = 15

