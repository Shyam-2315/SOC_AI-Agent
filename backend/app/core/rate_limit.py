from collections import defaultdict, deque
from time import monotonic

from fastapi import HTTPException, Request, status

from app.core.config import settings


_REQUESTS: dict[str, deque[float]] = defaultdict(deque)
_LAST_SEEN: dict[str, float] = {}
_CLEANUP_INTERVAL_SECONDS = 30
_MAX_TRACKED_KEYS = 10_000
_last_cleanup_at = 0.0


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
    global _last_cleanup_at
    now = monotonic()
    if now - _last_cleanup_at >= _CLEANUP_INTERVAL_SECONDS:
        stale_before = now - max(window_seconds, settings.rate_limit_window_seconds)
        for bucket_key in list(_REQUESTS.keys()):
            bucket = _REQUESTS[bucket_key]
            while bucket and now - bucket[0] >= window_seconds:
                bucket.popleft()
            if not bucket and _LAST_SEEN.get(bucket_key, stale_before) <= stale_before:
                _REQUESTS.pop(bucket_key, None)
                _LAST_SEEN.pop(bucket_key, None)
        if len(_REQUESTS) > _MAX_TRACKED_KEYS:
            for bucket_key, _ in sorted(_LAST_SEEN.items(), key=lambda item: item[1])[
                : len(_REQUESTS) - _MAX_TRACKED_KEYS
            ]:
                _REQUESTS.pop(bucket_key, None)
                _LAST_SEEN.pop(bucket_key, None)
        _last_cleanup_at = now

    bucket = _REQUESTS[key]
    while bucket and now - bucket[0] >= window_seconds:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "rate_limit_exceeded",
                "message": "Rate limit exceeded",
                "details": {
                    "limit": limit,
                    "window_seconds": window_seconds,
                },
            },
            headers={"Retry-After": str(window_seconds)},
        )
    bucket.append(now)
    _LAST_SEEN[key] = now
