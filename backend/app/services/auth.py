from datetime import datetime, timezone

from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id
from app.common.pagination import Pagination
from app.core.config import settings
from app.core.security import (
    UserRole,
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.client import organizations_collection, users_collection
from app.schemas.user import UserCreate, UserLogin, UserRegister, UserUpdate
from app.services.audit import write_audit_event


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


async def login_user(user: UserLogin) -> dict:
    existing_user = await users_collection.find_one({"email": user.email})
    if not existing_user or not verify_password(user.password, existing_user["password"]):
        await write_audit_event(
            event_type="auth.login.failure",
            outcome="failure",
            metadata={"email": user.email},
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if existing_user.get("disabled"):
        await write_audit_event(
            event_type="auth.login.disabled",
            organization_id=existing_user.get("organization_id"),
            outcome="blocked",
            metadata={"email": user.email},
        )
        raise HTTPException(status_code=403, detail="User is disabled")

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
