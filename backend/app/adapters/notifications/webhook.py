"""HMAC-SHA256 signed webhook notification dispatcher with idempotency headers."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, Optional

import httpx

from app.core.config import settings


def compute_hmac_signature(secret: str, timestamp: str, raw_body: bytes) -> str:
    """Compute `sha256=<hex>` HMAC over `<timestamp>.<raw_body>`."""
    key = (secret or settings.SECRET_KEY).encode("utf-8")
    signing_input = timestamp.encode("utf-8") + b"." + raw_body
    digest = hmac.new(key, signing_input, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_hmac_signature(
    secret: str,
    timestamp: str,
    raw_body: bytes,
    provided_signature: str,
    max_skew_seconds: int = 300,
) -> bool:
    """Constant-time verification of `X-Antiphish-Signature` and timestamp replay window."""
    if not timestamp or not provided_signature:
        return False
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - ts_int) > max_skew_seconds:
        return False
    expected = compute_hmac_signature(secret, timestamp, raw_body)
    return hmac.compare_digest(expected, provided_signature.strip())


async def send_signed_webhook(
    url: str,
    payload: Dict[str, Any],
    secret: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Dispatch a JSON webhook signed with `X-Antiphish-Signature` and `Idempotency-Key`."""
    ts = str(int(time.time()))
    idem_key = idempotency_key or str(uuid.uuid4())
    raw_body = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    sig = compute_hmac_signature(
        secret if secret is not None else (settings.N8N_WEBHOOK_SECRET or settings.SECRET_KEY),
        ts,
        raw_body,
    )

    headers = {
        "Content-Type": "application/json",
        "X-Antiphish-Signature": sig,
        "X-Antiphish-Timestamp": ts,
        "Idempotency-Key": idem_key,
    }
    if settings.N8N_SERVICE_KEY:
        headers["X-Service-Key"] = settings.N8N_SERVICE_KEY

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(url, content=raw_body, headers=headers)
            ok = 200 <= resp.status_code < 300
            return {
                "delivered": ok,
                "status_code": resp.status_code,
                "signature": sig,
                "timestamp": ts,
                "idempotency_key": idem_key,
                "error": None if ok else f"HTTP {resp.status_code}",
            }
    except Exception as exc:
        return {
            "delivered": False,
            "status_code": None,
            "signature": sig,
            "timestamp": ts,
            "idempotency_key": idem_key,
            "error": f"{type(exc).__name__}: {exc}",
        }
