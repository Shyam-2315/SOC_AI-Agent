from fastapi import APIRouter, HTTPException

from schemas.user_schema import (
    UserRegister,
    UserLogin
)

from core.database import users_collection

from core.security import (
    hash_password,
    verify_password,
    create_access_token
)

router = APIRouter(prefix="/auth")


@router.post("/register")
async def register(user: UserRegister):

    existing_user = await users_collection.find_one({
        "email": user.email
    })

    if existing_user:

        raise HTTPException(
            status_code=400,
            detail="User already exists"
        )

    hashed_password = hash_password(
        user.password
    )

    user_dict = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "role": "analyst"
    }

    result = await users_collection.insert_one(
        user_dict
    )

    user_dict["_id"] = str(result.inserted_id)

    return {
        "message": "User registered",
        "user": user_dict
    }


@router.post("/login")
async def login(user: UserLogin):

    db_user = await users_collection.find_one({
        "email": user.email
    })

    if not db_user:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    valid_password = verify_password(
        user.password,
        db_user["password"]
    )

    if not valid_password:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token({
        "user_id": str(db_user["_id"]),
        "email": db_user["email"],
        "role": db_user["role"]
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }