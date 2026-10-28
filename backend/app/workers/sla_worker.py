"""SLA breach escalation and durable n8n outbox delivery worker."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.n8n.client import N8nClient
from app.adapters.persistence.database import async_session_factory, engine
from app.adapters.persistence.models.notification_outbox import NotificationOutboxModel
from app.application.commands.transition_incident import escalate_overdue_incidents_command
from app.core.logging import get_logger
from app.core.metrics import OUTBOX_PENDING

log = get_logger("worker.sla")


async def _sweep_session(db: AsyncSession, drain_outbox: bool) -> Dict[str, Any]:
    escalated = await escalate_overdue_incidents_command(
        db=db,
        actor_email="sla-worker@bancocentral.com",
    )
    outbox_result: Dict[str, int] = {"processed": 0, "sent": 0, "failed": 0}
    if drain_outbox:
        outbox_result = await N8nClient().drain_outbox(db, batch_size=25)

    pending_cnt = int(
        await db.scalar(
            select(func.count(NotificationOutboxModel.id)).where(
                NotificationOutboxModel.status == "PENDING"
            )
        )
        or 0
    )
    OUTBOX_PENDING.set(pending_cnt)

    return {
        "escalated_count": len(escalated),
        "incident_ids": [i.id for i in escalated],
        "incident_codes": [i.incident_code for i in escalated],
        "outbox": outbox_result,
        "outbox_pending": pending_cnt,
    }


async def run_sla_sweep(
    db: Optional[AsyncSession] = None,
    drain_outbox: bool = True,
) -> Dict[str, Any]:
    """Escalate overdue incidents and optionally drain outbound n8n notifications."""
    if db is not None:
        return await _sweep_session(db, drain_outbox)

    async with async_session_factory() as session:
        res = await _sweep_session(session, drain_outbox)
        await session.commit()
        return res


async def _cli() -> None:
    try:
        res = await run_sla_sweep(drain_outbox=True)
        log.info("SLA sweep completed: %s", res)
        print(res)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_cli())
