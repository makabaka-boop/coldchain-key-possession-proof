"""Pre-promotion proof of possession: one-shot challenges for a candidate key.

Flow (only meaningful when the tenant's requirePromotionProof policy is on):

1. Admin requests a challenge for the current candidate key. The service binds
   it to (tenant, candidate keyId, current key generation) and a short expiry.
2. The gateway signs the canonical message with the candidate private key and
   submits the signature. The service verifies against the registered
   candidate public key and records a time-limited, single-use proof.
3. Promotion consumes a still-valid unconsumed proof in the same tenant
   transaction; expired, replayed, re-bound or cross-tenant proofs never pass.

Challenge/proof management never changes key roles.
"""
import secrets
import uuid

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from . import clock, db
from .auth import require
from .config import CHALLENGE_TTL_SECONDS
from .errors import ApiError
from .keys import _fetch_generation, _fetch_roles, _lock_tenant
from .pop import pop_message
from .policies import proof_required
from .util import b64url_decode_unpadded, b64url_encode
from .validation import check_ids

router = APIRouter(tags=["proof"])


class AnswerChallengeRequest(BaseModel):
    signature: str


def _parse_challenge_id(challenge_id: str):
    try:
        return uuid.UUID(challenge_id)
    except (ValueError, AttributeError, TypeError):
        raise ApiError(404, "CHALLENGE_NOT_FOUND") from None


@router.post("/tenants/{tenant_id}/proof/challenge", status_code=201)
async def issue_challenge(
    tenant_id: str,
    _: None = Depends(require("keys:manage")),
):
    """Mint a one-shot random challenge bound to the current candidate key."""
    check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            if not await proof_required(conn, tenant_id):
                # Policy off: challenges are not available. Default-off keeps
                # old tenants on the plain promote path.
                raise ApiError(409, "PROOF_POLICY_DISABLED")
            roles, _ = await _fetch_roles(conn, tenant_id)
            candidate = roles["candidate"]
            if candidate is None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
            generation = await _fetch_generation(conn, tenant_id)
            if generation is None:
                # tenant_state is created with the first key and backfilled on
                # schema bootstrap, so this is unreachable in practice.
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
            now_value = await clock.now(conn)
            challenge_id = uuid.uuid4()
            challenge_bytes = secrets.token_bytes(32)
            expires_at = await conn.fetchval(
                "SELECT $1::timestamptz + make_interval(secs => $2)",
                now_value, CHALLENGE_TTL_SECONDS,
            )
            await conn.execute(
                "INSERT INTO promotion_challenges"
                " (challenge_id, tenant_id, candidate_key_id, current_generation,"
                "  challenge, created_clock, expires_at)"
                " VALUES ($1, $2, $3, $4, $5, $6, $7)",
                challenge_id, tenant_id, candidate, generation,
                challenge_bytes, now_value, expires_at,
            )
    return {
        "tenantId": tenant_id,
        "challengeId": str(challenge_id),
        "candidateKeyId": candidate,
        "currentGeneration": generation,
        "challenge": b64url_encode(challenge_bytes),
        "expiresAt": expires_at.isoformat(),
        "ttlSeconds": CHALLENGE_TTL_SECONDS,
    }


@router.post("/tenants/{tenant_id}/proof/challenge/{challenge_id}/answer", status_code=201)
async def answer_challenge(
    tenant_id: str,
    challenge_id: str,
    body: AnswerChallengeRequest,
    _: None = Depends(require("verify")),
):
    """Verify a candidate-key signature over the challenge and register a proof.

    Exactly one answer per challenge is accepted: a second submission answers
    409 PROOF_ALREADY_REGISTERED even with an identical signature, so a replay
    can never look like a fresh proof. Expired challenges, candidate/current
    drift and cross-tenant reuse are all rejected and never mutate roles.
    """
    check_ids(tenant_id)
    cid = _parse_challenge_id(challenge_id)

    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            # Resolve the challenge first: unknown ids and other tenants'
            # challenges must be indistinguishable (uniform 404) regardless of
            # the submitted body.
            ch = await conn.fetchrow(
                "SELECT challenge_id, tenant_id, candidate_key_id, current_generation,"
                "       challenge, expires_at"
                " FROM promotion_challenges WHERE challenge_id = $1 FOR UPDATE",
                cid,
            )
            if ch is None or ch["tenant_id"] != tenant_id:
                raise ApiError(404, "CHALLENGE_NOT_FOUND")

            signature = b64url_decode_unpadded(body.signature, error_code="BAD_SIGNATURE")
            if len(signature) != 64:
                raise ApiError(400, "BAD_SIGNATURE")

            now_value = await clock.now(conn)
            roles, _ = await _fetch_roles(conn, tenant_id)

            existing = await conn.fetchval(
                "SELECT 1 FROM promotion_proofs WHERE challenge_id = $1 FOR UPDATE",
                cid,
            )
            if existing is not None:
                # One accepted answer per challenge — same or different
                # signature, consumed proof or not, expired or not.
                raise ApiError(409, "PROOF_ALREADY_REGISTERED", roles=roles)

            if now_value >= ch["expires_at"]:
                raise ApiError(410, "CHALLENGE_EXPIRED")

            # Rebind against live state: the bound key must still be the
            # candidate and the current-key generation must not have moved.
            generation = await _fetch_generation(conn, tenant_id)
            if (roles["candidate"] != ch["candidate_key_id"]
                    or generation != ch["current_generation"]):
                raise ApiError(409, "CHALLENGE_STALE", roles=roles)

            row = await conn.fetchrow(
                "SELECT public_key FROM tenant_keys"
                " WHERE tenant_id = $1 AND key_id = $2",
                tenant_id, ch["candidate_key_id"],
            )
            if row is None:
                # Unreachable through the state machine (keys are never
                # deleted); never verify against a phantom key.
                raise ApiError(409, "CHALLENGE_STALE", roles=roles)

            message = pop_message(
                tenant_id,
                ch["candidate_key_id"],
                ch["current_generation"],
                bytes(ch["challenge"]),
                ch["expires_at"].isoformat(),
            )
            try:
                Ed25519PublicKey.from_public_bytes(bytes(row["public_key"])).verify(
                    signature, message
                )
            except InvalidSignature:
                raise ApiError(400, "BAD_SIGNATURE") from None

            proof_id = uuid.uuid4()
            try:
                await conn.execute(
                    "INSERT INTO promotion_proofs"
                    " (proof_id, challenge_id, tenant_id, candidate_key_id,"
                    "  current_generation, presented_at, expires_at, consumed_at)"
                    " VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
                    proof_id, cid, tenant_id, ch["candidate_key_id"],
                    ch["current_generation"], now_value, ch["expires_at"],
                )
            except asyncpg.UniqueViolationError:
                # Backstop for a residual race that beat the FOR UPDATE recheck.
                raise ApiError(409, "PROOF_ALREADY_REGISTERED", roles=roles) from None
            consumed_at = None
    return _proof_response(
        tenant_id, ch["candidate_key_id"], ch["current_generation"],
        proof_id, ch["expires_at"], consumed_at, now_value,
    )


def _proof_response(tenant_id, candidate_key_id, generation, proof_id,
                    expires_at, consumed_at, now_value):
    return {
        "tenantId": tenant_id,
        "proofId": str(proof_id),
        "candidateKeyId": candidate_key_id,
        "currentGeneration": generation,
        "expiresAt": expires_at.isoformat(),
        "consumed": consumed_at is not None,
        "remainingSeconds": max(
            0, int((expires_at - now_value).total_seconds())
        ),
    }
