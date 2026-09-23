"""Cold-chain gateway key-rotation and verification service."""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import db
from .config import ENABLE_CLOCK_CONTROL
from .errors import ApiError, api_error_handler
from .internal import router as internal_router
from .keys import router as keys_router
from .policies import router as policies_router
from .proof import router as proof_router
from .verify import router as verify_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init()
    yield
    await db.close()


app = FastAPI(title="coldchain-gateway", version="1.1.0", lifespan=lifespan)
app.add_exception_handler(ApiError, api_error_handler)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(keys_router, prefix="/v1")
app.include_router(policies_router, prefix="/v1")
app.include_router(proof_router, prefix="/v1")
app.include_router(verify_router, prefix="/v1")
if ENABLE_CLOCK_CONTROL:
    app.include_router(internal_router, prefix="/v1")
