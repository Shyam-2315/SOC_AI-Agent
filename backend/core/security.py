from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict

from fastapi import HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings


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
    return pwd_context.verify(
        plain_password,
        hashed_password,
    )


def create_access_token(data: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }

    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def verify_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )

        required_claims = ("user_id", "email", "role", "organization_id")
        if any(not payload.get(claim) for claim in required_claims):
            raise HTTPException(
                status_code=401,
                detail="Invalid token claims",
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
        )
