"""FastAPI application entrypoint wiring middlewares, exception handlers, metrics, and v1 routers."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware.correlation_id import CorrelationIdMiddleware
from app.api.middleware.error_handler import ErrorHandlerMiddleware
from app.api.middleware.security_headers import SecurityHeadersMiddleware
from app.api.v1 import health
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger

configure_logging()
log = get_logger("main")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("Starting %s (%s)", settings.PROJECT_NAME, settings.APP_ENV)
    yield
    log.info("Shutting down %s", settings.PROJECT_NAME)


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version="2.0.0",
        description=(
            "Enterprise Banking Antiphishing Platform — Hexagonal Architecture, Selective CQRS, "
            "LangChain/Ollama On-Premise AI, n8n SOAR Integration, and Tamper-Evident Audit Trail."
        ),
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
    )

    register_exception_handlers(application)

    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(ErrorHandlerMiddleware)
    application.add_middleware(CorrelationIdMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID", "Content-Disposition", "X-MFA-Required"],
    )

    # Expose probes & Prometheus metrics at root (/health, /ready, /metrics) AND under /api/v1
    application.include_router(health.router, tags=["Health"])
    application.include_router(api_router, prefix=settings.API_V1_STR)
    return application


app = create_app()
