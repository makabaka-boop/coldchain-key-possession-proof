"""Tenant key lifecycle: register, promote, retire, inspect."""
import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from . import clock, db
from .auth import require
from .errors import ApiError
from .policies import proof_required
from .util import b64url_decode_unpadded
from .validation import check_ids as _check_ids

router = APIRouter(tags=["keys"])

_ACTIVE_ROLES = ("current", "candidate", "retiring")


class RegisterKeyRequest(BaseModel):
    keyId: str
    publicKey: str


def _roles_from_rows(rows):
    roles = {role: None for role in _ACTIVE_ROLES}
    retired = []
    for row in rows:
        if row["role"] == "retired":
            retired.append(row["key_id"])
        else:
            roles[row["role"]] = row["key_id"]
    return roles, retired


async def _fetch_roles(conn, tenant_id: str):
    rows = await conn.fetch(
        "SELECT key_id, role FROM tenant_keys WHERE tenant_id = $1 ORDER BY created_at, key_id",
        tenant_id,
    )
    return _roles_from_rows(rows)


async def _fetch_generation(conn, tenant_id: str) -> int:
    return await conn.fetchval(
        "SELECT current_generation FROM tenant_state WHERE tenant_id = $1",
        tenant_id,
    )


async def _lock_tenant(conn, tenant_id: str) -> None:
    # Serialize every key-state transition for this tenant within the
    # transaction; the partial unique indexes are the backstop.
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtext('tenant_keys'), hashtext($1))",
        tenant_id,
    )


@router.post("/tenants/{tenant_id}/keys", status_code=201)
async def register_key(
    tenant_id: str,
    body: RegisterKeyRequest,
    _: None = Depends(require("keys:manage")),
):
    """First key becomes current; a second becomes candidate; anything else
    while a candidate or retiring key exists is an illegal transition."""
    _check_ids(tenant_id, body.keyId)
    public_key = b64url_decode_unpadded(body.publicKey, error_code="BAD_PUBLIC_KEY")
    if len(public_key) != 32:
        raise ApiError(400, "BAD_PUBLIC_KEY", detail="Ed25519 public keys must be 32 bytes")

    try:
        async with db.pool.acquire() as conn:
            async with conn.transaction():
                await _lock_tenant(conn, tenant_id)
                rows = await conn.fetch(
                    "SELECT key_id, role FROM tenant_keys WHERE tenant_id = $1 FOR UPDATE",
                    tenant_id,
                )
                roles, _ = _roles_from_rows(rows)
                if any(row["key_id"] == body.keyId for row in rows):
                    raise ApiError(409, "KEY_ALREADY_EXISTS", roles=roles)
                if not rows:
                    role = "current"
                elif roles["candidate"] is None and roles["retiring"] is None:
                    role = "candidate"
                else:
                    raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
                await conn.execute(
                    "INSERT INTO tenant_keys (tenant_id, key_id, role, public_key)"
                    " VALUES ($1, $2, $3, $4)",
                    tenant_id, body.keyId, role, public_key,
                )
                if role == "current":
                    # First key of the tenant: generation 1.
                    await conn.execute(
                        "INSERT INTO tenant_state (tenant_id, current_generation)"
                        " VALUES ($1, 1) ON CONFLICT (tenant_id) DO NOTHING",
                        tenant_id,
                    )
                roles[role] = body.keyId
                generation = await _fetch_generation(conn, tenant_id)
                return {
                    "tenantId": tenant_id,
                    "keyId": body.keyId,
                    "role": role,
                    "currentGeneration": generation,
                    "roles": roles,
                }
    except asyncpg.UniqueViolationError:
        # Lost a race against a concurrent transition; answer with the
        # authoritative roles so the caller can resync.
        async with db.pool.acquire() as conn:
            roles, _ = await _fetch_roles(conn, tenant_id)
        raise ApiError(409, "KEY_ALREADY_EXISTS", roles=roles) from None


async def _consume_promotion_proof(conn, tenant_id: str, candidate: str,
                                   generation: int, roles: dict, now_value):
    """Atomically consume a usable proof for this exact binding.

    A proof is usable only when every binding still matches at promotion time:
    same tenant, same candidate keyId, same current-key generation, not yet
    consumed and not expired. A candidate may carry several proof rows (e.g. a
    fresh proof after an expired one), so the usable row is picked directly;
    failure attribution then scans the same-generation rows and reports the
    most specific reason: PROOF_CONSUMED > PROOF_EXPIRED > PROOF_MISSING.
    """

    def fail(code: str):
        raise ApiError(409, code, roles=roles)

    consumed = await conn.fetchval(
        "WITH pick AS ("
        "  SELECT proof_id FROM promotion_proofs"
        "  WHERE tenant_id = $1 AND candidate_key_id = $2 AND current_generation = $3"
        "    AND consumed_at IS NULL AND expires_at > $4"
        "  ORDER BY presented_at DESC, proof_id DESC"
        "  LIMIT 1"
        ")"
        " UPDATE promotion_proofs p SET consumed_at = $4"
        " FROM pick WHERE p.proof_id = pick.proof_id"
        " RETURNING p.proof_id",
        tenant_id, candidate, generation, now_value,
    )
    if consumed is not None:
        return consumed

    stats = await conn.fetchrow(
        "SELECT count(*) AS n,"
        "       bool_or(consumed_at IS NOT NULL) AS any_consumed,"
        "       bool_or(expires_at <= $4) AS any_expired"
        " FROM promotion_proofs"
        " WHERE tenant_id = $1 AND candidate_key_id = $2 AND current_generation = $3",
        tenant_id, candidate, generation, now_value,
    )
    if stats["n"] == 0:
        fail("PROOF_MISSING")        # never proved, or bound to another generation
    if stats["any_consumed"]:
        fail("PROOF_CONSUMED")       # a matching proof already bought a promotion
    if stats["any_expired"]:
        fail("PROOF_EXPIRED")        # proof(s) outlived their TTL
    fail("PROOF_MISSING")


@router.post("/tenants/{tenant_id}/keys/promote")
async def promote_key(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Atomically: candidate -> current, old current -> retiring.

    When the tenant's pre-promotion proof policy is enabled, a still-valid,
    unconsumed proof bound to (tenant, candidate keyId, current generation)
    must exist and is consumed inside this same transaction.
    """
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            roles, _ = await _fetch_roles(conn, tenant_id)
            if roles["candidate"] is None or roles["retiring"] is not None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)

            consumed_proof_id = None
            if await proof_required(conn, tenant_id):
                now_value = await clock.now(conn)
                generation = await _fetch_generation(conn, tenant_id)
                consumed_proof_id = str(await _consume_promotion_proof(
                    conn, tenant_id, roles["candidate"], generation, roles, now_value
                ))

            # Order matters: the partial unique indexes admit only one row per
            # role, so the old current must move out first.
            await conn.execute(
                "UPDATE tenant_keys SET role = 'retiring', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'current'",
                tenant_id,
            )
            await conn.execute(
                "UPDATE tenant_keys SET role = 'current', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'candidate'",
                tenant_id,
            )
            generation = await conn.fetchval(
                "UPDATE tenant_state SET current_generation = current_generation + 1"
                " WHERE tenant_id = $1 RETURNING current_generation",
                tenant_id,
            )
            roles["retiring"] = roles["current"]
            roles["current"] = roles["candidate"]
            roles["candidate"] = None
            return {
                "tenantId": tenant_id,
                "roles": roles,
                "currentGeneration": generation,
                "consumedProofId": consumed_proof_id,
            }


@router.post("/tenants/{tenant_id}/keys/retire")
async def retire_key(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Retiring -> retired (irreversible)."""
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            roles, retired = await _fetch_roles(conn, tenant_id)
            if roles["retiring"] is None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
            await conn.execute(
                "UPDATE tenant_keys SET role = 'retired', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'retiring'",
                tenant_id,
            )
            retired.append(roles["retiring"])
            roles["retiring"] = None
            return {"tenantId": tenant_id, "roles": roles, "retired": retired}


@router.get("/tenants/{tenant_id}/keys")
async def list_keys(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Authoritative role view for a tenant."""
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        roles, retired = await _fetch_roles(conn, tenant_id)
        generation = await _fetch_generation(conn, tenant_id)
    return {
        "tenantId": tenant_id,
        "roles": roles,
        "retired": retired,
        "currentGeneration": generation,
    }


@router.get("/tenants/{tenant_id}/receipts")
async def list_receipts(tenant_id: str, _: None = Depends(require("keys:manage"))):
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT receipt_id, key_id, body_size, encode(body_sha256, 'hex') AS sha256, created_at"
            " FROM receipts WHERE tenant_id = $1 ORDER BY created_at, receipt_id",
            tenant_id,
        )
    return {
        "tenantId": tenant_id,
        "receipts": [
            {
                "receiptId": str(row["receipt_id"]),
                "keyId": row["key_id"],
                "size": row["body_size"],
                "sha256": row["sha256"],
                "createdAt": row["created_at"].isoformat(),
            }
            for row in rows
        ],
    }
