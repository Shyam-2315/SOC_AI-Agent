import argparse
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys


if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db import (
    close_database,
    create_indexes,
    organizations_collection,
    users_collection,
)
from app.core.security import UserRole, hash_password


async def bootstrap(
    organization_name: str,
    username: str,
    email: str,
    password: str,
    collector_token: str,
) -> None:
    await create_indexes()

    organization = await organizations_collection.find_one({
        "name": organization_name,
    })
    if organization is None:
        result = await organizations_collection.insert_one({
            "name": organization_name,
            "created_at": datetime.now(timezone.utc),
            "created_by": "bootstrap",
        })
        organization_id = str(result.inserted_id)
    else:
        organization_id = str(organization["_id"])

    existing_user = await users_collection.find_one({
        "email": email,
    })
    user_data = {
        "username": username,
        "email": email,
        "role": UserRole.admin.value,
        "organization_id": organization_id,
        "disabled": False,
        "updated_at": datetime.now(timezone.utc),
    }

    if existing_user is None:
        user_data.update({
            "password": hash_password(password),
            "created_at": datetime.now(timezone.utc),
            "created_by": "bootstrap",
        })
        await users_collection.insert_one(user_data)
    else:
        await users_collection.update_one(
            {"email": email},
            {"$set": user_data},
        )

    print("Bootstrap complete")
    print(f"organization_id={organization_id}")
    print(f"admin_email={email}")
    print(f"COLLECTOR_API_KEYS={collector_token}:{organization_id}")


def parse_args():
    parser = argparse.ArgumentParser(description="Bootstrap the first SOC tenant.")
    parser.add_argument("--org", default="Demo SOC")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--password", default="longpassword12")
    parser.add_argument("--collector-token", default="test-collector-token")
    return parser.parse_args()


async def main():
    args = parse_args()
    try:
        await bootstrap(
            organization_name=args.org,
            username=args.username,
            email=args.email,
            password=args.password,
            collector_token=args.collector_token,
        )
    finally:
        await close_database()


if __name__ == "__main__":
    asyncio.run(main())
