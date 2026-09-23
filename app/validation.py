"""Shared identifier validation."""
import re

from .errors import ApiError

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def check_ids(tenant_id: str, key_id: str | None = None) -> None:
    if not _ID_RE.fullmatch(tenant_id):
        raise ApiError(400, "BAD_REQUEST", field="tenantId")
    if key_id is not None and not _ID_RE.fullmatch(key_id):
        raise ApiError(400, "BAD_REQUEST", field="keyId")
