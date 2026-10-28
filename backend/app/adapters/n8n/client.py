"""n8n SOAR orchestrator client with HMAC-SHA256 signing and durable outbox drain helper."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.notifications.webhook import (
    compute_hmac_signature,
    send_signed_webhook,
    verify_hmac_signature,
)
from app.adapters.persistence.models.notification_outbox import NotificationOutboxModel
from app.core.config import settings

EVENT_PATH_MAP = {
    "incident.created": "phishing-report",
    "phishing.quarantined": "phishing-report",
    "incident.escalated": "incident-escalated",
    "ioc.critical_blocked": "critical-ioc",
}


class N8nClient:
    """Outbound HMAC-SHA256 webhook client targeting self-hosted n8n SOAR workflows."""

    def __init__(
        self,
        base_webhook_url: Optional[str] = None,
        secret: Optional[str] = None,
    ) -> None:
        self.base_url = (base_webhook_url or settings.N8N_WEBHOOK_URL).rstrip("/")
        self.secret = secret if secret is not None else (settings.N8N_WEBHOOK_SECRET or settings.SECRET_KEY)

    def endpoint_for_event(self, event_name: str) -> str:
        slug = EVENT_PATH_MAP.get(event_name, "soc-events")
        return f"{self.base_url}/{slug}"

    async def dispatch_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        timeout: float = 3.5,
    ) -> Dict[str, Any]:
        envelope = {
            "event": event_name,
            "emitted_at": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        return await send_signed_webhook(
            url=self.endpoint_for_event(event_name),
            payload=envelope,
            secret=self.secret,
            idempotency_key=idempotency_key,
            timeout=timeout,
        )

    async def drain_outbox(self, db: AsyncSession, batch_size: int = 25) -> Dict[str, int]:
        """Deliver pending `notification_outbox` events to n8n with retry bookkeeping."""
        stmt = (
            select(NotificationOutboxModel)
            .where(NotificationOutboxModel.status == "PENDING", NotificationOutboxModel.attempts < 5)
            .order_by(NotificationOutboxModel.created_at.asc())
            .limit(batch_size)
        )
        rows = list((await db.scalars(stmt)).all())
        sent = 0
        failed = 0
        for row in rows:
            row.attempts = int(row.attempts or 0) + 1
            res = await self.dispatch_event(
                event_name=row.event_name,
                payload=row.payload or {},
                idempotency_key=row.dedupe_key,
            )
            if res.get("delivered"):
                row.status = "SENT"
                row.sent_at = datetime.now(timezone.utc)
                row.last_error = None
                sent += 1
            else:
                row.last_error = str(res.get("error") or "Webhook delivery failed")[:500]
                if row.attempts >= 5:
                    row.status = "FAILED"
                failed += 1
        await db.flush()
        return {"processed": len(rows), "sent": sent, "failed": failed}


__all__ = ["N8nClient", "compute_hmac_signature", "verify_hmac_signature"]
