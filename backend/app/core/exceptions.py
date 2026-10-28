"""Maps domain errors to HTTP responses."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.domain.shared.errors import (
    AccountLocked, DomainError, InvalidTransition, PermissionDenied, WeakPassword,
)

_STATUS = {
    InvalidTransition: 409,
    WeakPassword: 422,
    AccountLocked: 423,
    PermissionDenied: 403,
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def domain_error_handler(_: Request, exc: DomainError) -> JSONResponse:
        code = next((c for t, c in _STATUS.items() if isinstance(exc, t)), 400)
        return JSONResponse(status_code=code, content={"detail": str(exc), "type": type(exc).__name__})
