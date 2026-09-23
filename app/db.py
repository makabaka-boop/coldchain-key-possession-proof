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

-- Tenant-level switches. Absence of a row means the feature is off, so old
-- tenants keep their historical register/promote/verify behavior.
CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id                TEXT PRIMARY KEY,
    require_promotion_proof  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant monotone generation of the current key. Bumped once per
-- successful promotion; a proof binds to the generation it was issued against.
CREATE TABLE IF NOT EXISTS tenant_state (
    tenant_id           TEXT PRIMARY KEY,
    current_generation  BIGINT NOT NULL CHECK (current_generation >= 1)
);

-- One-shot challenges issued for a candidate key while it is still candidate.
-- The challenge bytes, the candidate keyId and the then-current generation are
-- all bound; expires_at is computed against the (possibly virtual) service clock.
CREATE TABLE IF NOT EXISTS promotion_challenges (
    challenge_id       UUID        PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    candidate_key_id   TEXT        NOT NULL,
    current_generation BIGINT      NOT NULL,
    challenge          BYTEA       NOT NULL,
    created_clock      TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS promotion_challenges_tenant
    ON promotion_challenges (tenant_id, created_clock);

-- A registered proof of possession. At most one proof per challenge; once
-- consumed by a promotion the row stays on as the audit trail.
CREATE TABLE IF NOT EXISTS promotion_proofs (
    proof_id           UUID        PRIMARY KEY,
    challenge_id       UUID        NOT NULL UNIQUE,
    tenant_id          TEXT        NOT NULL,
    candidate_key_id   TEXT        NOT NULL,
    current_generation BIGINT      NOT NULL,
    presented_at       TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS promotion_proofs_live
    ON promotion_proofs (tenant_id, candidate_key_id) WHERE consumed_at IS NULL;

-- Deterministic service clock: a single offset added to clock_timestamp().
-- Stays at zero unless moved via the (test-only) clock-control API.
CREATE TABLE IF NOT EXISTS service_clock (
    id      INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    offset_seconds BIGINT NOT NULL DEFAULT 0
);
INSERT INTO service_clock (id, offset_seconds) VALUES (1, 0)
    ON CONFLICT (id) DO NOTHING;

-- Backfill generation state for tenants created before this migration: their
-- existing current key is generation 1.
INSERT INTO tenant_state (tenant_id, current_generation)
SELECT DISTINCT tenant_id, 1 FROM tenant_keys
    ON CONFLICT (tenant_id) DO NOTHING;
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
