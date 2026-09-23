"""Runtime configuration from the environment."""
import os

MAX_BODY_BYTES = 1_048_576  # 1 MiB hard limit for gateway payloads


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


DATABASE_URL = _required("DATABASE_URL")
ADMIN_TOKEN = _required("ADMIN_TOKEN")
GATEWAY_TOKEN = _required("GATEWAY_TOKEN")
