"""PostgreSQL connection pool and schema bootstrap."""
import asyncio

import asyncpg

from .config import DATABASE_URL

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_keys (
    tenant_id   TEXT        NOT NULL,
    key_id      TEXT        NOT NULL,
    role        TEXT        NOT NULL CHECK (role IN ('current', 'candidate', 'retiring', 'retired')),
    public_key  BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id)
);

-- Invariants, enforced at the storage layer: per tenant at most one key per
-- in-use role. 'retired' is unbounded.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_current
    ON tenant_keys (tenant_id) WHERE role = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_candidate
    ON tenant_keys (tenant_id) WHERE role = 'candidate';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_retiring
    ON tenant_keys (tenant_id) WHERE role = 'retiring';

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id  UUID        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    key_id      TEXT        NOT NULL,
    body_sha256 BYTEA       NOT NULL,
    body_size   BIGINT      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS receipts_by_tenant ON receipts (tenant_id, created_at);
"""

pool: asyncpg.Pool | None = None


async def init() -> None:
    """Create the pool and apply the schema, waiting for Postgres to come up."""
    global pool
    last_error: Exception | None = None
    for _ in range(30):
        candidate: asyncpg.Pool | None = None
        try:
            candidate = await asyncpg.create_pool(dsn=DATABASE_URL, min_size=1, max_size=10)
            async with candidate.acquire() as conn:
                await conn.execute(SCHEMA)
            pool = candidate
            return
        except Exception as exc:  # Postgres not ready yet; retry.
            if candidate is not None:
                await candidate.close()
            last_error = exc
            await asyncio.sleep(1)
    raise RuntimeError(f"database did not become ready: {last_error}")


async def close() -> None:
    global pool
    if pool is not None:
        await pool.close()
        pool = None
