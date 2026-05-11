from typing import Optional

from bson import ObjectId
from pydantic import EmailStr, Field, field_validator

from app.core.security import UserRole
from app.schemas.base import APIModel


class UserRegister(APIModel):
    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    organization_id: str

    @field_validator("organization_id")
    @classmethod
    def validate_organization_id(cls, value: str) -> str:
        normalized = value.strip()
        if not ObjectId.is_valid(normalized):
            raise ValueError("organization_id must be a valid ObjectId")
        return normalized


class UserCreate(APIModel):
    username: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.analyst


class UserLogin(APIModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserUpdate(APIModel):
    role: Optional[UserRole] = None
    disabled: Optional[bool] = None
