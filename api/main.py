import logging
from contextlib import asynccontextmanager

import sentry_sdk
from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI, HTTPException
from fastapi.exception_handlers import http_exception_handler

from api.config import config
from api.database import database
from api.logging_conf import configure_logging
from api.routers.post import router as post_router
from api.routers.upload import router as upload_router
from api.routers.users import router as user_router

sentry_sdk.init(dsn=config.SENTRY_DSN, traces_sample_rate=1.0, profiles_sample_rate=1.0)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    await database.connect()
    yield
    await database.disconnect()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CorrelationIdMiddleware)

app.include_router(post_router)
app.include_router(user_router)
app.include_router(upload_router)


@app.exception_handler(HTTPException)
async def http_excption_handle_logging(request, exc):
    logger.error(f"HTTPException: {exc.status_code} {exc.detail}")
    return await http_exception_handler(request, exc)
