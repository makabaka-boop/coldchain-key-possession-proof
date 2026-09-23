"""Bearer-token auth: 401 for missing/unknown tokens, 403 for missing scope."""
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import ADMIN_TOKEN, GATEWAY_TOKEN
from .errors import ApiError

_bearer = HTTPBearer(auto_error=False)

# The admin token manages keys and may also verify; the gateway token may only
# verify. Anything authenticated but out of scope is a 403, not a 401.
_TOKEN_SCOPES = {
    ADMIN_TOKEN: frozenset({"keys:manage", "verify"}),
    GATEWAY_TOKEN: frozenset({"verify"}),
}


def require(scope: str):
    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> None:
        if credentials is None:
            raise ApiError(401, "UNAUTHORIZED", headers={"WWW-Authenticate": "Bearer"})
        scopes = _TOKEN_SCOPES.get(credentials.credentials)
        if scopes is None:
            raise ApiError(401, "UNAUTHORIZED", headers={"WWW-Authenticate": "Bearer"})
        if scope not in scopes:
            raise ApiError(403, "FORBIDDEN")

    return dependency
