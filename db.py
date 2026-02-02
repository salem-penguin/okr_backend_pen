import os
import asyncpg
from dotenv import load_dotenv
from typing import Any, Optional
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Put it in .env")

_pool: asyncpg.Pool | None = None

async def init_db_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=1,
            max_size=10,
            command_timeout=30,
        )
    return _pool
async def fetchrow(query: str, *args) -> Optional[asyncpg.Record]:
    # print("\n=== SQL EXEC (fetchrow) ===")
    # print(query)
    # print("ARGS:", args)
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(query, *args)

async def fetch(query: str, *args) -> list[asyncpg.Record]:
    # print("\n=== SQL EXEC (fetch) ===")
    # print(query)
    # print("ARGS:", args)
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        return await conn.fetch(query, *args)
async def fetchval(sql: str, *args):
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        val = await conn.fetchval(sql, *args)
    return val

async def execute(sql: str, *args):
    pool = await init_db_pool()
    async with pool.acquire() as conn:
        return await conn.execute(sql, *args)

def record_to_dict(r: asyncpg.Record) -> dict[str, Any]:
    return dict(r)

async def close_db_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
