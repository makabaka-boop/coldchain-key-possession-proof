"""Test-only deterministic clock control.

Mounted solely when ENABLE_CLOCK_CONTROL is set. The offset lives in the
database, so every horizontally scaled API instance observes the same moved
clock. Only forwards moves are accepted; the clock never runs backwards.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from . import clock, db
from .auth import require

router = APIRouter(tags=["internal"])


class AdvanceClockRequest(BaseModel):
    seconds: int = Field(strict=True, ge=0, le=60 * 60 * 24 * 365)


@router.post("/internal/clock/advance")
async def advance_clock(
    body: AdvanceClockRequest,
    _: None = Depends(require("keys:manage")),
):
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await clock.advance(conn, body.seconds)
            value = await clock.now(conn)
    return {"now": value.isoformat()}


@router.post("/internal/clock/reset")
async def reset_clock(_: None = Depends(require("keys:manage"))):
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await clock.reset(conn)
            value = await clock.now(conn)
    return {"now": value.isoformat()}
