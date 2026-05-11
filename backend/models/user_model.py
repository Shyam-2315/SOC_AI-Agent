from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from core.security import UserRole


class UserRegister(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    organization_id: str


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.analyst


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    role: Optional[UserRole] = None
    disabled: Optional[bool] = None
