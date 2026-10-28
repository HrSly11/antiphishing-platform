import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import correlation_id_ctx


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Reuses the caller's X-Correlation-ID or creates one, and echoes it in the response."""

    async def dispatch(self, request: Request, call_next):
        cid = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        token = correlation_id_ctx.set(cid)
        try:
            response = await call_next(request)
        finally:
            correlation_id_ctx.reset(token)
        response.headers["X-Correlation-ID"] = cid
        return response
