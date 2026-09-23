"""Black-box acceptance fixtures: the API under test is reached over HTTP."""
import base64
import os
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000").rstrip("/")
# A second, independently deployed API instance sharing the same database;
# cross-instance behavior (clock, challenges, races) is exercised against it.
BASE2_URL = os.environ.get("API_BASE2_URL", BASE_URL).rstrip("/")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
GATEWAY_TOKEN = os.environ.get("GATEWAY_TOKEN", "dev-gateway-token")

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
GATEWAY_HEADERS = {"Authorization": f"Bearer {GATEWAY_TOKEN}"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class TenantKey:
    """An Ed25519 keypair identified by a key id."""

    def __init__(self, key_id: str):
        self.key_id = key_id
        self._private = Ed25519PrivateKey.generate()
        self.public_key_b64 = b64url(self._private.public_key().public_bytes_raw())

    def sign(self, body: bytes) -> str:
        return b64url(self._private.sign(body))

    def sign_raw(self, body: bytes) -> bytes:
        return self._private.sign(body)


# Canonical proof-of-possession envelope; must match app/pop.py exactly.
POP_CONTEXT = b"coldchain-gateway:v1:promotion-proof-of-possession"


def pop_message(tenant_id: str, key_id: str, generation: int,
                challenge: bytes, expires_at: str) -> bytes:
    def frame(tag: bytes, data: bytes) -> bytes:
        return tag + b"=" + str(len(data)).encode("ascii") + b":" + data

    return b"|".join([
        b"context=" + str(len(POP_CONTEXT)).encode("ascii") + b":" + POP_CONTEXT,
        frame(b"tenant", tenant_id.encode("utf-8")),
        frame(b"candidate", key_id.encode("utf-8")),
        frame(b"generation", str(generation).encode("ascii")),
        frame(b"challenge", challenge),
        frame(b"expires", expires_at.encode("ascii")),
    ])


@pytest.fixture()
def admin_client():
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def admin_client2():
    with httpx.Client(base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def gateway_client():
    with httpx.Client(base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def gateway_client2():
    with httpx.Client(base_url=BASE2_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def tenant_id():
    return f"t-{uuid.uuid4().hex[:16]}"


@pytest.fixture()
def make_key():
    def _make(key_id: str | None = None) -> TenantKey:
        return TenantKey(key_id or f"k-{uuid.uuid4().hex[:12]}")

    return _make


def register_key(client, tenant_id, key):
    return client.post(
        f"/v1/tenants/{tenant_id}/keys",
        json={"keyId": key.key_id, "publicKey": key.public_key_b64},
    )


def promote(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/promote")


def retire(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/retire")


def get_roles(client, tenant_id):
    resp = client.get(f"/v1/tenants/{tenant_id}/keys")
    assert resp.status_code == 200, resp.text
    return resp.json()


def submit(client, tenant_id, key_id, signature, body):
    return client.post(
        "/v1/verify",
        content=body,
        headers={
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key_id,
            "X-Signature": signature,
        },
    )


# --- proof-of-possession helpers ------------------------------------------

def set_policy(client, tenant_id, enabled: bool):
    return client.put(
        f"/v1/tenants/{tenant_id}/policy",
        json={"requirePromotionProof": enabled},
    )


def request_challenge(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/proof/challenge")


def answer_challenge(client, tenant_id, challenge, key: TenantKey):
    message = pop_message(
        tenant_id, key.key_id, challenge["currentGeneration"],
        b64url_decode(challenge["challenge"]), challenge["expiresAt"],
    )
    return client.post(
        f"/v1/tenants/{tenant_id}/proof/challenge/{challenge['challengeId']}/answer",
        json={"signature": key.sign(message)},
    )


def advance_clock(client, seconds: int):
    return client.post("/v1/internal/clock/advance", json={"seconds": seconds})


def reset_clock(client):
    return client.post("/v1/internal/clock/reset")


@pytest.fixture(autouse=True)
def _reset_service_clock():
    """The deterministic clock is global state; keep each test independent.

    No-op on deployments without the test-only clock endpoint.
    """
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=10.0) as client:
        try:
            client.post("/v1/internal/clock/reset")
        except httpx.HTTPError:
            pass
    yield
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=10.0) as client:
        try:
            client.post("/v1/internal/clock/reset")
        except httpx.HTTPError:
            pass
