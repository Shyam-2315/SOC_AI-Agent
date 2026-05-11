from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from fastapi import HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "sub": str(data.get("user_id", "")),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    if settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer
    if settings.jwt_audience:
        payload["aud"] = settings.jwt_audience
    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def verify_token(token: str) -> dict[str, Any]:
    try:
        decode_kwargs: dict[str, Any] = {
            "key": settings.jwt_secret,
            "algorithms": [settings.jwt_algorithm],
        }
        if settings.jwt_issuer:
            decode_kwargs["issuer"] = settings.jwt_issuer
        if settings.jwt_audience:
            decode_kwargs["audience"] = settings.jwt_audience

        payload = jwt.decode(token, **decode_kwargs)
        required_claims = ("user_id", "email", "role", "organization_id")
        if any(not payload.get(claim) for claim in required_claims):
            raise HTTPException(
                status_code=401,
                detail="Invalid token claims",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
