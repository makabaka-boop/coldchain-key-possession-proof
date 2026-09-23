"""Tenant-level optional policies (e.g. pre-promotion proof of possession).

Default-off: a tenant without a row is treated as if every optional policy is
disabled, preserving the historical register/promote/verify behavior.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from . import db
from .auth import require
from .validation import check_ids

router = APIRouter(tags=["policies"])


class PolicyRequest(BaseModel):
    requirePromotionProof: bool


async def proof_required(conn, tenant_id: str) -> bool:
    return await conn.fetchval(
        "SELECT require_promotion_proof FROM tenant_policies WHERE tenant_id = $1",
        tenant_id,
    ) is True


@router.put("/tenants/{tenant_id}/policy")
async def put_policy(
    tenant_id: str,
    body: PolicyRequest,
    _: None = Depends(require("keys:manage")),
):
    """Enable/disable the optional pre-promotion proof policy.

    Toggling the policy never changes key roles: outstanding challenges and
    proofs are simply ignored while the policy is off.
    """
    check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO tenant_policies (tenant_id, require_promotion_proof, updated_at)"
                " VALUES ($1, $2, now())"
                " ON CONFLICT (tenant_id) DO UPDATE"
                " SET require_promotion_proof = EXCLUDED.require_promotion_proof,"
                "     updated_at = now()",
                tenant_id, body.requirePromotionProof,
            )
    return {
        "tenantId": tenant_id,
        "requirePromotionProof": body.requirePromotionProof,
    }


@router.get("/tenants/{tenant_id}/policy")
async def get_policy(
    tenant_id: str,
    _: None = Depends(require("keys:manage")),
):
    check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        enabled = await proof_required(conn, tenant_id)
    return {"tenantId": tenant_id, "requirePromotionProof": enabled}
