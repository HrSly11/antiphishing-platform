import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.logging import get_logger
from app.core.metrics import HTTP_REQUESTS

log = get_logger("api")


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Last-resort handler: never leak stack traces to clients, always log them, count requests."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
        HTTP_REQUESTS.labels(request.method, str(response.status_code)).inc()
        log.info(
            "%s %s -> %s", request.method, request.url.path, response.status_code,
            extra={"extra_fields": {"ms": round((time.perf_counter() - started) * 1000, 1)}},
        )
        return response
