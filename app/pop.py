"""Canonical message signed by a candidate key during proof of possession.

The domain-separated, length-framed envelope makes the signature unforgeable
from other signature uses (e.g. ordinary /v1/verify traffic) even if a signed
payload happens to contain the same bytes. The service returns the exact
encoded fields (challenge, expiresAt, currentGeneration) so the gateway can
reproduce this byte string.
"""

POP_CONTEXT = b"coldchain-gateway:v1:promotion-proof-of-possession"


def pop_message(tenant_id: str, candidate_key_id: str, current_generation: int,
                challenge: bytes, expires_at_iso: str) -> bytes:
    def frame(tag: bytes, data: bytes) -> bytes:
        return tag + b"=" + str(len(data)).encode("ascii") + b":" + data

    parts = [
        b"context=" + str(len(POP_CONTEXT)).encode("ascii") + b":" + POP_CONTEXT,
        frame(b"tenant", tenant_id.encode("utf-8")),
        frame(b"candidate", candidate_key_id.encode("utf-8")),
        frame(b"generation", str(current_generation).encode("ascii")),
        frame(b"challenge", challenge),
        frame(b"expires", expires_at_iso.encode("ascii")),
    ]
    return b"|".join(parts)
