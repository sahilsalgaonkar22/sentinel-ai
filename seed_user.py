"""Seed the admin user with a properly hashed password."""
import asyncio
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def main():
    import asyncpg
    conn = await asyncpg.connect(
        host="sentinel-postgres",
        port=5432,
        user="sentinel",
        password="112b9e911121581e235ba665429b0a4edc29ce7242e005e2433a08240cb6839e",
        database="sentinel",
    )
    hashed = pwd_context.hash("Admin@1234")
    print(f"Generated hash: {hashed}")
    await conn.execute(
        "UPDATE users SET hashed_password=$1 WHERE email='admin@sentinel.ai'",
        hashed,
    )
    # Verify
    row = await conn.fetchrow("SELECT email, hashed_password FROM users WHERE email='admin@sentinel.ai'")
    print(f"Stored: {row['email']} -> {row['hashed_password'][:30]}...")
    ok = pwd_context.verify("Admin@1234", row["hashed_password"])
    print(f"Verify: {ok}")
    await conn.close()

asyncio.run(main())
