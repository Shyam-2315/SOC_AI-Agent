from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status

from core.database import organizations_collection, users_collection
from core.dependencies import Pagination, pagination_params, require_admin
from core.security import UserRole, create_access_token, hash_password, verify_password
from models.user_model import UserCreate, UserLogin, UserRegister, UserUpdate


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


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


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    existing_user = await users_collection.find_one({
        "email": user.email,
    })
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User already exists",
        )

    try:
        organization_object_id = ObjectId(user.organization_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid organization id",
        )

    organization = await organizations_collection.find_one({
        "_id": organization_object_id,
    })
    if not organization:
        raise HTTPException(
            status_code=400,
            detail="Organization not found",
        )

    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "role": UserRole.analyst.value,
        "organization_id": user.organization_id,
        "disabled": False,
        "created_at": datetime.now(timezone.utc),
    }

    result = await users_collection.insert_one(user_data)

    return {
        "message": "User registered",
        "user_id": str(result.inserted_id),
    }


@router.post("/login")
async def login(user: UserLogin):
    existing_user = await users_collection.find_one({
        "email": user.email,
    })

    if not existing_user or not verify_password(
        user.password,
        existing_user["password"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    if existing_user.get("disabled"):
        raise HTTPException(
            status_code=403,
            detail="User is disabled",
        )

    token = create_access_token({
        "user_id": str(existing_user["_id"]),
        "email": existing_user["email"],
        "role": existing_user["role"],
        "organization_id": existing_user["organization_id"],
    })

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    current_user=Depends(require_admin),
):
    existing_user = await users_collection.find_one({
        "email": user.email,
    })
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User already exists",
        )

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

    return {
        "message": "User created",
        "user": _public_user(user_data),
    }


@router.get("/users")
async def list_users(
    pagination: Pagination = Depends(pagination_params),
    current_user=Depends(require_admin),
):
    users = []
    cursor = (
        users_collection.find({
            "organization_id": current_user["organization_id"],
        })
        .sort("created_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for user in cursor:
        users.append(_public_user(user))

    total = await users_collection.count_documents({
        "organization_id": current_user["organization_id"],
    })

    return {
        "items": users,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    update: UserUpdate,
    current_user=Depends(require_admin),
):
    try:
        object_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid user id",
        )

    update_data = {
        key: value.value if isinstance(value, UserRole) else value
        for key, value in update.model_dump(exclude_none=True).items()
    }
    if not update_data:
        raise HTTPException(
            status_code=400,
            detail="No updates provided",
        )

    result = await users_collection.update_one(
        {
            "_id": object_id,
            "organization_id": current_user["organization_id"],
        },
        {"$set": update_data},
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return {
        "message": "User updated",
    }
