"""Acceptance: tenant-level, default-off pre-promotion proof of possession."""
import asyncio

import httpx

from conftest import (
    ADMIN_HEADERS,
    BASE2_URL,
    BASE_URL,
    GATEWAY_HEADERS,
    advance_clock,
    answer_challenge,
    b64url,
    b64url_decode,
    get_roles,
    pop_message,
    promote,
    register_key,
    request_challenge,
    retire,
    set_policy,
)

# TTL used to force expiry; derived from the challenge response where the
# clock is advanced, so the suite also works against other deployments.
DEFAULT_CHALLENGE_TTL = 30

def test_policy_defaults_off_and_promote_unchanged(admin_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    assert register_key(admin_client, tenant_id, k1).status_code == 201
    assert register_key(admin_client, tenant_id, k2).status_code == 201

    resp = admin_client.get(f"/v1/tenants/{tenant_id}/policy")
    assert resp.status_code == 200
    assert resp.json()["requirePromotionProof"] is False

    # No proof needed; the plain legacy promote still works.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200
    assert resp.json()["consumedProofId"] is None
    assert resp.json()["currentGeneration"] == 2

    # Challenges are not offered while the policy is off.
    resp = request_challenge(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_POLICY_DISABLED"


def test_first_key_is_generation_one(admin_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    view = get_roles(admin_client, tenant_id)
    assert view["currentGeneration"] == 1


# --- happy path ------------------------------------------------------------

def _enabled_tenant_with_candidate(admin_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    assert set_policy(admin_client, tenant_id, True).status_code == 200
    return k1, k2


def test_challenge_answer_and_promote_happy_path(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)

    resp = request_challenge(admin_client, tenant_id)
    assert resp.status_code == 201, resp.text
    ch = resp.json()
    assert ch["candidateKeyId"] == k2.key_id
    assert ch["currentGeneration"] == 1
    assert len(b64url_decode(ch["challenge"])) == 32
    assert ch["ttlSeconds"] == DEFAULT_CHALLENGE_TTL

    resp = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert resp.status_code == 201, resp.text
    proof = resp.json()
    assert proof["candidateKeyId"] == k2.key_id
    assert proof["currentGeneration"] == 1
    assert proof["consumed"] is False
    assert 0 < proof["remainingSeconds"] <= DEFAULT_CHALLENGE_TTL

    # Promotion consumes the proof in the same transaction and bumps generation.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["roles"] == {"current": k2.key_id, "candidate": None, "retiring": k1.key_id}
    assert body["consumedProofId"] == proof["proofId"]
    assert body["currentGeneration"] == 2


def test_promote_without_proof_is_rejected_with_authoritative_roles(
    admin_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "PROOF_MISSING"
    assert body["roles"] == {"current": k1.key_id, "candidate": k2.key_id, "retiring": None}
    # Rejected promotion changes no roles.
    assert get_roles(admin_client, tenant_id)["roles"] == body["roles"]


# --- signature binding -----------------------------------------------------

def _challenge(admin_client, tenant_id):
    return request_challenge(admin_client, tenant_id).json()


def test_wrong_private_key_is_bad_signature(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)

    # k1 (current) signs, but the challenge is bound to k2 (candidate).
    resp = answer_challenge(gateway_client, tenant_id, ch, k1)
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}

    # The failed attempt must not register a proof or move roles.
    assert promote(admin_client, tenant_id).status_code == 409
    view = get_roles(admin_client, tenant_id)
    assert view["roles"] == {"current": k1.key_id, "candidate": k2.key_id, "retiring": None}


def test_signature_covers_tenant_candidate_generation_and_expiry(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)

    def answer_with_message(message: bytes):
        return gateway_client.post(
            f"/v1/tenants/{tenant_id}/proof/challenge/{ch['challengeId']}/answer",
            json={"signature": b64url(k2.sign_raw(message))},
        )

    raw_challenge = b64url_decode(ch["challenge"])
    # Any mutation of any bound field invalidates the signature.
    mutants = [
        pop_message("other-tenant", k2.key_id, 1, raw_challenge, ch["expiresAt"]),
        pop_message(tenant_id, "k1", 1, raw_challenge, ch["expiresAt"]),
        pop_message(tenant_id, k2.key_id, 99, raw_challenge, ch["expiresAt"]),
        pop_message(tenant_id, k2.key_id, 1, b"\x00" * 32, ch["expiresAt"]),
        pop_message(tenant_id, k2.key_id, 1, raw_challenge, "2000-01-01T00:00:00+00:00"),
        b"",  # empty message is never valid
    ]
    for mutant in mutants:
        resp = answer_with_message(mutant)
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "BAD_SIGNATURE"

    # The exact canonical message verifies.
    resp = answer_with_message(
        pop_message(tenant_id, k2.key_id, 1, raw_challenge, ch["expiresAt"])
    )
    assert resp.status_code == 201, resp.text


def test_malformed_signature_is_400(admin_client, gateway_client, tenant_id, make_key):
    _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    for bad in ("", "!!!", "AAAA", "AAAA" + "=="):
        resp = gateway_client.post(
            f"/v1/tenants/{tenant_id}/proof/challenge/{ch['challengeId']}/answer",
            json={"signature": bad},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "BAD_SIGNATURE"


# --- replay ----------------------------------------------------------------

def test_duplicate_answer_is_rejected_even_with_identical_signature(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    first = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert first.status_code == 201

    second = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert second.status_code == 409
    body = second.json()
    assert body["error"] == "PROOF_ALREADY_REGISTERED"
    assert body["roles"] == {"current": k1.key_id, "candidate": k2.key_id, "retiring": None}

    # The original proof still promotes exactly once.
    assert promote(admin_client, tenant_id).status_code == 200
    third = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert third.status_code == 409
    assert third.json()["error"] == "PROOF_ALREADY_REGISTERED"


def test_consumed_proof_cannot_promote_again(admin_client, gateway_client, tenant_id, make_key):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    answer_challenge(gateway_client, tenant_id, ch, k2)
    assert promote(admin_client, tenant_id).status_code == 200

    # No candidate remains: the next promote is an ordinary illegal transition,
    # and re-arming (retire + new candidate) cannot reuse anything from gen 1.
    assert promote(admin_client, tenant_id).status_code == 409
    assert retire(admin_client, tenant_id).status_code == 200
    k3 = make_key()
    register_key(admin_client, tenant_id, k3)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_MISSING"
    assert resp.json()["roles"]["candidate"] == k3.key_id


# --- expiry via the controllable clock -------------------------------------

def test_expired_proof_blocks_promote_and_fresh_proof_recovers(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    proof = answer_challenge(gateway_client, tenant_id, ch, k2).json()

    advance_clock(admin_client, ch["ttlSeconds"] + 1)

    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "PROOF_EXPIRED"
    assert body["roles"]["candidate"] == k2.key_id

    # Re-answering the already-answered challenge after expiry is a duplicate
    # submission: 409 regardless of expiry, never a second proof.
    resp = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_ALREADY_REGISTERED"
    assert resp.json()["roles"]["candidate"] == k2.key_id

    # A new challenge/proof against the same clock works and promotes.
    ch2 = _challenge(admin_client, tenant_id)
    proof2 = answer_challenge(gateway_client, tenant_id, ch2, k2).json()
    assert proof2["proofId"] != proof["proofId"]
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200
    assert resp.json()["consumedProofId"] == proof2["proofId"]


def test_unanswered_challenge_expires(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    advance_clock(admin_client, ch["ttlSeconds"] + 1)
    resp = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert resp.status_code == 410
    assert resp.json() == {"error": "CHALLENGE_EXPIRED"}
    # Expiry registers nothing: promotion still reports a missing proof.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_MISSING"


# --- role / generation drift -----------------------------------------------

def test_challenge_answered_after_role_change_is_stale(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)

    # Rotate out-of-band by switching the policy off (roles never change by
    # merely toggling), then retire the old key and arm a new candidate.
    set_policy(admin_client, tenant_id, False)
    assert promote(admin_client, tenant_id).status_code == 200
    assert retire(admin_client, tenant_id).status_code == 200
    k3 = make_key()
    register_key(admin_client, tenant_id, k3)
    set_policy(admin_client, tenant_id, True)

    # The old challenge was bound to k2 @ generation 1; candidate is now k3.
    resp = answer_challenge(gateway_client, tenant_id, ch, k2)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "CHALLENGE_STALE"
    assert body["roles"] == {"current": k2.key_id, "candidate": k3.key_id, "retiring": None}

    # A generation-2 challenge for k3 restores the happy path.
    ch2 = _challenge(admin_client, tenant_id)
    assert ch2["currentGeneration"] == 2
    assert ch2["candidateKeyId"] == k3.key_id
    answer_challenge(gateway_client, tenant_id, ch2, k3)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200
    assert resp.json()["currentGeneration"] == 3


def test_proof_bound_to_old_generation_cannot_promote(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    # gen-1 challenge/proof is left unused while the tenant rotates via a
    # policy-off window, then re-arms with a new candidate and re-enables.
    _challenge(admin_client, tenant_id)
    set_policy(admin_client, tenant_id, False)
    promote(admin_client, tenant_id)
    retire(admin_client, tenant_id)
    k3 = make_key()
    register_key(admin_client, tenant_id, k3)
    set_policy(admin_client, tenant_id, True)

    # No gen-2 proof exists; the gen-1 state cannot promote k3.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_MISSING"


# --- cross-tenant isolation ------------------------------------------------

def test_challenge_cannot_be_answered_from_another_tenant(
    admin_client, gateway_client, tenant_id, make_key
):
    import uuid

    other = f"tb-{uuid.uuid4().hex[:10]}"
    _, ka2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    _enabled_tenant_with_candidate(admin_client, other, make_key)
    ch = _challenge(admin_client, tenant_id)

    # Same signature, submitted under the other tenant's namespace.
    resp = answer_challenge(gateway_client, other, ch, ka2)
    assert resp.status_code == 404
    assert resp.json() == {"error": "CHALLENGE_NOT_FOUND"}
    # The other tenant still needs its own proof.
    resp = promote(admin_client, other)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_MISSING"


def test_unknown_challenge_ids_are_uniform_404(admin_client, gateway_client, tenant_id, make_key):
    import uuid

    _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    for cid in ("not-a-uuid", str(uuid.uuid4())):
        resp = gateway_client.post(
            f"/v1/tenants/{tenant_id}/proof/challenge/{cid}/answer",
            json={"signature": "AAAA"},
        )
        assert resp.status_code == 404
        assert resp.json() == {"error": "CHALLENGE_NOT_FOUND"}


# --- authentication / authorization ----------------------------------------

def test_proof_endpoints_require_scopes(tenant_id):
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        # challenge issuance is keys:manage only
        url = f"/v1/tenants/{tenant_id}/proof/challenge"
        assert client.post(url).status_code == 401
        assert client.post(url, headers=GATEWAY_HEADERS).status_code == 403
        assert client.post(url, headers=ADMIN_HEADERS).status_code in (409, 404)

        # policy management is keys:manage only
        purl = f"/v1/tenants/{tenant_id}/policy"
        assert client.put(purl, json={"requirePromotionProof": True}).status_code == 401
        assert client.put(
            purl, json={"requirePromotionProof": True}, headers=GATEWAY_HEADERS
        ).status_code == 403
        assert client.put(
            purl, json={"requirePromotionProof": True}, headers=ADMIN_HEADERS
        ).status_code == 200

    # answering requires authentication (verify scope); unauthenticated -> 401
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        aurl = f"/v1/tenants/{tenant_id}/proof/challenge/{'0'*8}-0000-0000-0000-{'0'*12}/answer"
        assert client.post(aurl, json={"signature": "AAAA"}).status_code == 401
        # admin token carries verify too, so it reaches the 404 lookup.
        assert client.post(
            aurl, json={"signature": "AAAA"}, headers=ADMIN_HEADERS
        ).status_code == 404


# --- retired keys still cannot sign / verify -------------------------------

def test_retired_key_still_rejected_through_verify(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    answer_challenge(gateway_client, tenant_id, ch, k2)
    promote(admin_client, tenant_id)
    retire(admin_client, tenant_id)
    body = b"reading"
    resp = gateway_client.post(
        "/v1/verify",
        content=body,
        headers={
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": k1.key_id,
            "X-Signature": k1.sign(body),
        },
    )
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_RETIRED"}


def test_verify_receipts_unchanged_around_proof_flow(
    admin_client, gateway_client, tenant_id, make_key
):
    import hashlib

    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    answer_challenge(gateway_client, tenant_id, ch, k2)
    body = b"temperature=-19;door=closed"
    resp = gateway_client.post(
        "/v1/verify",
        content=body,
        headers={
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": k2.key_id,
            "X-Signature": k2.sign(body),
        },
    )
    assert resp.status_code == 202
    receipt_id = resp.json()["receiptId"]
    promote(admin_client, tenant_id)

    receipts = admin_client.get(f"/v1/tenants/{tenant_id}/receipts").json()["receipts"]
    assert len(receipts) == 1
    assert receipts[0]["receiptId"] == receipt_id
    assert receipts[0]["keyId"] == k2.key_id
    assert receipts[0]["sha256"] == hashlib.sha256(body).hexdigest()


# --- concurrency across two API instances ----------------------------------

def _race(path: str, n=8):
    async def run():
        clients = []
        tasks = []
        for i in range(n):
            client = httpx.AsyncClient(
                base_url=BASE_URL if i % 2 == 0 else BASE2_URL,
                headers=ADMIN_HEADERS, timeout=30.0,
            )
            clients.append(client)
            tasks.append(client.post(path))
        results = await asyncio.gather(*tasks)
        await asyncio.gather(*[c.aclose() for c in clients])
        return results

    return asyncio.run(run())


def test_concurrent_promote_consumes_proof_once(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    answer_challenge(gateway_client, tenant_id, ch, k2)

    responses = _race(f"/v1/tenants/{tenant_id}/keys/promote", n=8)
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 7
    for r in responses:
        if r.status_code == 409:
            assert "roles" in r.json()
            assert r.json()["error"] in ("PROOF_CONSUMED", "ILLEGAL_TRANSITION")
    view = get_roles(admin_client, tenant_id)
    assert view["roles"] == {"current": k2.key_id, "candidate": None, "retiring": k1.key_id}
    assert view["currentGeneration"] == 2


def test_concurrent_answers_register_single_proof(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)
    ch = _challenge(admin_client, tenant_id)
    message = pop_message(
        tenant_id, k2.key_id, ch["currentGeneration"],
        b64url_decode(ch["challenge"]), ch["expiresAt"],
    )
    signature = k2.sign(message)
    path = f"/v1/tenants/{tenant_id}/proof/challenge/{ch['challengeId']}/answer"

    async def run():
        clients = []
        tasks = []
        for i in range(6):
            client = httpx.AsyncClient(
                base_url=BASE_URL if i % 2 == 0 else BASE2_URL,
                headers=GATEWAY_HEADERS, timeout=30.0,
            )
            clients.append(client)
            tasks.append(client.post(path, json={"signature": signature}))
        results = await asyncio.gather(*tasks)
        await asyncio.gather(*[c.aclose() for c in clients])
        return results

    responses = asyncio.run(run())
    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == 1
    assert statuses.count(409) == 5
    assert all(r.json()["error"] == "PROOF_ALREADY_REGISTERED"
               for r in responses if r.status_code == 409)
    # Roles untouched; the single proof still promotes once.
    view = get_roles(admin_client, tenant_id)
    assert view["roles"] == {"current": k1.key_id, "candidate": k2.key_id, "retiring": None}
    assert promote(admin_client, tenant_id).status_code == 200


def test_cross_instance_clock_and_challenge_flow(
    admin_client, admin_client2, gateway_client, gateway_client2, tenant_id, make_key
):
    k1, k2 = _enabled_tenant_with_candidate(admin_client, tenant_id, make_key)

    # Challenge issued against instance 1...
    ch = request_challenge(admin_client, tenant_id).json()
    # ...answered through instance 2.
    resp = answer_challenge(gateway_client2, tenant_id, ch, k2)
    assert resp.status_code == 201, resp.text

    # Clock moved on instance 1 is observed by instance 2 (offset is in the DB).
    advance_clock(admin_client, ch["ttlSeconds"] + 1)
    resp = promote(admin_client2, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "PROOF_EXPIRED"

    # Recovery also spans both instances.
    ch2 = request_challenge(admin_client2, tenant_id).json()
    answer_challenge(gateway_client, tenant_id, ch2, k2)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200
    assert resp.json()["roles"]["current"] == k2.key_id
