"""Service clock: real time plus an admin-controlled offset (tests only).

Every deadline/validity check in the service reads `now()` so that all API
instances sharing the database share the same deterministic clock.
"""
import asyncpg


async def now(conn: asyncpg.Connection):
    """Current service time: clock_timestamp() plus the stored offset."""
    return await conn.fetchval(
        "SELECT clock_timestamp() + make_interval(secs => offset_seconds)"
        " FROM service_clock WHERE id = 1"
    )


async def advance(conn: asyncpg.Connection, seconds: int) -> None:
    await conn.execute(
        "UPDATE service_clock SET offset_seconds = offset_seconds + $1 WHERE id = 1",
        seconds,
    )


async def reset(conn: asyncpg.Connection) -> None:
    await conn.execute("UPDATE service_clock SET offset_seconds = 0 WHERE id = 1")
