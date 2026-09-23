"""Runtime configuration from the environment."""
import os

MAX_BODY_BYTES = 1_048_576  # 1 MiB hard limit for gateway payloads

# Lifetime of a one-shot promotion proof-of-possession challenge.
CHALLENGE_TTL_SECONDS = int(os.environ.get("CHALLENGE_TTL_SECONDS", "300"))

# Deterministic test clock: when enabled, admins may move the service clock
# forwards via /v1/internal/clock. Never enable in production.
ENABLE_CLOCK_CONTROL = os.environ.get("ENABLE_CLOCK_CONTROL", "").lower() in (
    "1", "true", "yes", "on",
)


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


DATABASE_URL = _required("DATABASE_URL")
ADMIN_TOKEN = _required("ADMIN_TOKEN")
GATEWAY_TOKEN = _required("GATEWAY_TOKEN")
