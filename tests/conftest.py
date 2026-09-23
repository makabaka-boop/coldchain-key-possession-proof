"""Black-box acceptance fixtures: the API under test is reached over HTTP."""
import base64
import os
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
GATEWAY_TOKEN = os.environ.get("GATEWAY_TOKEN", "dev-gateway-token")

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
GATEWAY_HEADERS = {"Authorization": f"Bearer {GATEWAY_TOKEN}"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class TenantKey:
    """An Ed25519 keypair identified by a key id."""

    def __init__(self, key_id: str):
        self.key_id = key_id
        self._private = Ed25519PrivateKey.generate()
        self.public_key_b64 = b64url(self._private.public_key().public_bytes_raw())

    def sign(self, body: bytes) -> str:
        return b64url(self._private.sign(body))


@pytest.fixture()
def admin_client():
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def gateway_client():
    with httpx.Client(base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
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
