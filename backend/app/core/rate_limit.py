"""Sliding-window rate limiter (in-process).

Limitation: state lives in this process. With several API replicas the limit is per replica; the
production design replaces `_hits` with Redis (INCR + EXPIRE). Redis is not available in this lab.
"""
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            retry = max(1, int(self.window - (now - hits[0])))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)

    def reset(self) -> None:
        self._hits.clear()


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def limiter_dependency(limiter: RateLimiter):
    async def _dep(request: Request) -> None:
        limiter.check(client_key(request))

    return _dep
