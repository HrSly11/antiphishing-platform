import asyncio
import sys

import asyncpg

PASSWORD = "12345"


async def reset(name: str) -> None:
    conn = await asyncpg.connect(user="postgres", password=PASSWORD, host="127.0.0.1", port=5432, database="postgres")
    await conn.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", name
    )
    await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    await conn.execute(f'CREATE DATABASE "{name}"')
    await conn.close()
    app_conn = await asyncpg.connect(user="postgres", password=PASSWORD, host="127.0.0.1", port=5432, database=name)
    await app_conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    await app_conn.close()
    print(f"database '{name}' recreated with pg_trgm")


if __name__ == "__main__":
    asyncio.run(reset(sys.argv[1] if len(sys.argv) > 1 else "antiphishing_db"))
