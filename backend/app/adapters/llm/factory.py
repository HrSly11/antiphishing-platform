"""LLM provider factory with fast Ollama health caching and deterministic fallback."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

import httpx
from langchain_ollama import ChatOllama

from app.core.config import settings

_HEALTH_CACHE_TTL_SECONDS = 30.0
_last_check_ts: float = 0.0
_last_reachable: bool = False


def check_ollama_reachable(force: bool = False, probe_timeout: float = 0.8) -> bool:
    """Fast cached HTTP health check against Ollama (`/api/tags`) so offline mode never blocks."""
    global _last_check_ts, _last_reachable

    if settings.LLM_PROVIDER.lower() != "ollama":
        return False

    now = time.monotonic()
    if not force and (now - _last_check_ts) < _HEALTH_CACHE_TTL_SECONDS:
        return _last_reachable

    url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags"
    reachable = False
    try:
        with httpx.Client(timeout=httpx.Timeout(probe_timeout)) as client:
            resp = client.get(url)
            reachable = resp.status_code == 200
    except Exception:
        reachable = False

    _last_check_ts = now
    _last_reachable = reachable
    return reachable


async def check_ollama_reachable_async(force: bool = False, probe_timeout: float = 0.8) -> bool:
    """Async variant of the cached Ollama health check."""
    global _last_check_ts, _last_reachable

    if settings.LLM_PROVIDER.lower() != "ollama":
        return False

    now = time.monotonic()
    if not force and (now - _last_check_ts) < _HEALTH_CACHE_TTL_SECONDS:
        return _last_reachable

    url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags"
    reachable = False
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(probe_timeout)) as client:
            resp = await client.get(url)
            reachable = resp.status_code == 200
    except Exception:
        reachable = False

    _last_check_ts = now
    _last_reachable = reachable
    return reachable


def get_chat_model(
    temperature: float = 0.0,
    force_probe: bool = False,
) -> Tuple[Optional[ChatOllama], str]:
    """Return `(ChatOllama, 'ollama:<model>')` when reachable, else `(None, 'langchain-deterministic')`."""
    if check_ollama_reachable(force=force_probe):
        model = ChatOllama(
            base_url=settings.OLLAMA_BASE_URL,
            model=settings.OLLAMA_MODEL,
            temperature=temperature,
            num_predict=512,
        )
        return model, f"ollama:{settings.OLLAMA_MODEL}"
    return None, "langchain-deterministic"


def get_llm_status() -> Dict[str, Any]:
    """Structured diagnostic payload for `/health` and SOC diagnostics."""
    reachable = check_ollama_reachable(force=False)
    return {
        "provider": settings.LLM_PROVIDER,
        "base_url": settings.OLLAMA_BASE_URL,
        "model": settings.OLLAMA_MODEL,
        "reachable": reachable,
        "active_engine": f"ollama:{settings.OLLAMA_MODEL}" if reachable else "langchain-deterministic",
    }
