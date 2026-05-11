from collections import defaultdict, deque
from time import monotonic

from fastapi import HTTPException, Request, status


_REQUESTS: dict[str, deque[float]] = defaultdict(deque)


def client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def check_rate_limit(
    *,
    key: str,
    limit: int,
    window_seconds: int = 60,
) -> None:
    now = monotonic()
    bucket = _REQUESTS[key]
    while bucket and now - bucket[0] >= window_seconds:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )
    bucket.append(now)
