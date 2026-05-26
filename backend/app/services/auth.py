from datetime import datetime, timezone

from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id
from app.common.pagination import Pagination
from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import (
    UserRole,
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.client import organizations_collection, users_collection
from app.realtime.pubsub import get_redis_client
from app.schemas.user import UserCreate, UserLogin, UserRegister, UserUpdate
from app.services.audit import write_audit_event

logger = get_logger(__name__)
_FAILED_LOGINS: dict[str, tuple[int, float]] = {}
_FAILED_LOGIN_LIMIT = 10
_FAILED_LOGIN_TTL_SECONDS = 900


def _public_user(user: dict) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "organization_id": user["organization_id"],
        "disabled": user.get("disabled", False),
        "created_at": user.get("created_at"),
    }


async def _login_attempt_key(email: str, source_ip: str | None) -> str:
    return f"auth:login-failure:{(source_ip or 'unknown').strip().lower()}:{email.strip().lower()}"


async def _enforce_login_throttle(email: str, source_ip: str | None) -> None:
    key = await _login_attempt_key(email, source_ip)
    redis_client = await get_redis_client()
    if redis_client is not None:
        try:
            attempts = await redis_client.get(key)
            if attempts is not None and int(attempts) >= _FAILED_LOGIN_LIMIT:
                raise HTTPException(status_code=429, detail="Too many failed login attempts")
            return
        except HTTPException:
            raise
        except Exception:
            logger.exception("failed to read login throttle from redis", extra={"client_ip": source_ip})

    import time

    count, expires_at = _FAILED_LOGINS.get(key, (0, 0.0))
    now = time.time()
    if expires_at <= now:
        _FAILED_LOGINS.pop(key, None)
        return
    if count >= _FAILED_LOGIN_LIMIT:
        raise HTTPException(status_code=429, detail="Too many failed login attempts")


async def _record_failed_login(email: str, source_ip: str | None) -> None:
    key = await _login_attempt_key(email, source_ip)
    redis_client = await get_redis_client()
    if redis_client is not None:
        try:
            attempts = await redis_client.incr(key)
            await redis_client.expire(key, _FAILED_LOGIN_TTL_SECONDS)
            logger.warning(
                "login failed",
                extra={"client_ip": source_ip, "event_type": "auth.login.failure", "user_id": email},
            )
            if attempts >= _FAILED_LOGIN_LIMIT:
                raise HTTPException(status_code=429, detail="Too many failed login attempts")
            return
        except HTTPException:
            raise
        except Exception:
            logger.exception("failed to write login throttle to redis", extra={"client_ip": source_ip})

    import time

    now = time.time()
    count, expires_at = _FAILED_LOGINS.get(key, (0, now + _FAILED_LOGIN_TTL_SECONDS))
    if expires_at <= now:
        count = 0
        expires_at = now + _FAILED_LOGIN_TTL_SECONDS
    count += 1
    _FAILED_LOGINS[key] = (count, expires_at)
    if count >= _FAILED_LOGIN_LIMIT:
        raise HTTPException(status_code=429, detail="Too many failed login attempts")


async def _clear_failed_login(email: str, source_ip: str | None) -> None:
    key = await _login_attempt_key(email, source_ip)
    redis_client = await get_redis_client()
    if redis_client is not None:
        try:
            await redis_client.delete(key)
            return
        except Exception:
            logger.exception("failed to clear login throttle in redis", extra={"client_ip": source_ip})
    _FAILED_LOGINS.pop(key, None)


async def register_user(user: UserRegister) -> dict:
    if not settings.public_registration_enabled:
        await write_audit_event(
            event_type="auth.register.blocked",
            organization_id=user.organization_id,
            outcome="blocked",
            metadata={"email": user.email},
        )
        raise HTTPException(status_code=404, detail="Registration is disabled")

    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    organization_object_id = parse_object_id(user.organization_id, "organization")
    organization = await organizations_collection.find_one(
        {"_id": organization_object_id}
    )
    if not organization:
        raise HTTPException(status_code=400, detail="Organization not found")

    existing_org_users = await users_collection.count_documents(
        {"organization_id": user.organization_id}
    )
    if existing_org_users > 0:
        raise HTTPException(
            status_code=403,
            detail="Organization already has an admin; invite users from the console",
        )
    role = UserRole.admin.value

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "role": role,
        "organization_id": user.organization_id,
        "disabled": False,
        "created_at": datetime.now(timezone.utc),
    }
    result = await users_collection.insert_one(user_data)
    await write_audit_event(
        event_type="auth.register.success",
        organization_id=user.organization_id,
        target_type="user",
        target_id=str(result.inserted_id),
        metadata={"email": user.email},
    )
    return {
        "message": "User registered",
        "user_id": str(result.inserted_id),
        "role": role,
    }


async def login_user(user: UserLogin, *, source_ip: str | None = None) -> dict:
    await _enforce_login_throttle(user.email, source_ip)
    existing_user = await users_collection.find_one({"email": user.email})
    if not existing_user or not verify_password(user.password, existing_user["password"]):
        await write_audit_event(
            event_type="auth.login.failure",
            outcome="failure",
            metadata={"email": user.email},
        )
        await _record_failed_login(user.email, source_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if existing_user.get("disabled"):
        await write_audit_event(
            event_type="auth.login.disabled",
            organization_id=existing_user.get("organization_id"),
            outcome="blocked",
            metadata={"email": user.email},
        )
        raise HTTPException(status_code=403, detail="User is disabled")

    await _clear_failed_login(user.email, source_ip)
    token = create_access_token(
        {
            "user_id": str(existing_user["_id"]),
            "email": existing_user["email"],
            "role": existing_user["role"],
            "organization_id": existing_user["organization_id"],
        }
    )
    await write_audit_event(
        event_type="auth.login.success",
        actor={
            "user_id": str(existing_user["_id"]),
            "email": existing_user["email"],
            "role": existing_user["role"],
            "organization_id": existing_user["organization_id"],
        },
    )
    logger.info(
        "login succeeded",
        extra={
            "client_ip": source_ip,
            "organization_id": existing_user["organization_id"],
            "user_id": str(existing_user["_id"]),
            "event_type": "auth.login.success",
        },
    )
    return {
        "access_token": token,
        "token_type": "bearer",
    }


async def create_user(
    user: UserCreate,
    current_user: dict,
) -> dict:
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "role": user.role.value,
        "organization_id": current_user["organization_id"],
        "disabled": False,
        "created_at": datetime.now(timezone.utc),
        "created_by": current_user["email"],
    }
    result = await users_collection.insert_one(user_data)
    user_data["_id"] = result.inserted_id
    await write_audit_event(
        event_type="auth.user.created",
        actor=current_user,
        target_type="user",
        target_id=str(result.inserted_id),
        metadata={"email": user.email, "role": user.role.value},
    )

    return {
        "message": "User created",
        "user": _public_user(user_data),
    }


async def list_users(
    pagination: Pagination,
    current_user: dict,
) -> dict:
    query = {"organization_id": current_user["organization_id"]}
    items = []
    cursor = (
        users_collection.find(query)
        .sort("created_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for user in cursor:
        items.append(_public_user(user))

    total = await users_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def update_user(
    user_id: str,
    update: UserUpdate,
    current_user: dict,
) -> dict:
    object_id = parse_object_id(user_id, "user")
    update_data = {
        key: value.value if isinstance(value, UserRole) else value
        for key, value in update.model_dump(exclude_none=True).items()
    }
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")

    result = await users_collection.update_one(
        {
            "_id": object_id,
            "organization_id": current_user["organization_id"],
        },
        {"$set": update_data},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    await write_audit_event(
        event_type="auth.user.updated",
        actor=current_user,
        target_type="user",
        target_id=user_id,
        metadata={"fields": sorted(update_data.keys())},
    )
    return {"message": "User updated"}
