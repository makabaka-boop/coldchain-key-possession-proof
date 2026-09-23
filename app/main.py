"""Cold-chain gateway key-rotation and verification service."""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import db
from .errors import ApiError, api_error_handler
from .keys import router as keys_router
from .verify import router as verify_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init()
    yield
    await db.close()


app = FastAPI(title="coldchain-gateway", version="1.0.0", lifespan=lifespan)
app.add_exception_handler(ApiError, api_error_handler)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(keys_router, prefix="/v1")
app.include_router(verify_router, prefix="/v1")
