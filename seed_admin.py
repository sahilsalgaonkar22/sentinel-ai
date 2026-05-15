"""Quick admin user seeder."""
import asyncio
from backend.common.database import AsyncSessionLocal, init_db
from backend.services.identity.models import User, Organization
from backend.services.identity.auth import get_password_hash
from sqlalchemy.future import select
import sys

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def seed():
    await init_db()
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == "admin@sentinel.ai"))
        if result.scalar_one_or_none():
            print("Admin user already exists")
            return

        org = Organization(
            id="aaaaaaaa-0000-4000-8000-000000000001",
            name="Sentinel HQ",
            slug="sentinel-hq",
            plan="enterprise"
        )
        db.add(org)
        await db.flush()

        user = User(
            id="bbbbbbbb-0000-4000-8000-000000000001",
            email="admin@sentinel.ai",
            username="admin",
            hashed_password=get_password_hash("admin123"),
            full_name="Admin",
            role="admin",
            org_id=org.id,
            is_active=True
        )
        db.add(user)
        await db.commit()
        print("Admin user seeded successfully")

asyncio.run(seed())
