from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    Pagination,
    auth_rate_limit,
    pagination_params,
    require_permission,
)
from app.schemas.user import UserCreate, UserLogin, UserRegister, UserUpdate
from app.services.auth import (
    create_user,
    list_users,
    login_user,
    register_user,
    update_user,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister, _: None = Depends(auth_rate_limit)):
    return await register_user(user)


@router.post("/login")
async def login(user: UserLogin, _: None = Depends(auth_rate_limit)):
    return await login_user(user)


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user_endpoint(
    user: UserCreate,
    current_user=Depends(require_permission("users:write")),
):
    return await create_user(user, current_user)


@router.get("/users")
async def list_users_endpoint(
    pagination: Pagination = Depends(pagination_params),
    current_user=Depends(require_permission("users:read")),
):
    return await list_users(pagination, current_user)


@router.patch("/users/{user_id}")
async def update_user_endpoint(
    user_id: str,
    update: UserUpdate,
    current_user=Depends(require_permission("users:write")),
):
    return await update_user(user_id, update, current_user)
