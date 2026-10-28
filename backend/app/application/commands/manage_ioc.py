"""IOC management commands (BLACKLIST & WHITELIST upsert, deactivation, outbox & audit logging)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.notification_outbox import NotificationOutboxModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.application.dto.report_dto import IocCreate


async def upsert_ioc_command(
    db: AsyncSession,
    payload: IocCreate,
    actor_email: str = "system",
    client_ip: str = "",
    ttl_hours: Optional[int] = None,
) -> Tuple[IocModel, bool]:
    repo = IocRepository(db)
    ioc, created = await repo.upsert(
        ioc_type=payload.ioc_type.upper(),
        value=payload.ioc_value,
        list_type=payload.list_type.upper(),
        confidence=payload.confidence_score,
        source=payload.source,
        ttl_days=payload.ttl_days,
        ttl_hours=ttl_hours,
        created_by=actor_email,
    )

    if ioc.list_type == "BLACKLIST" and ioc.confidence_score >= 90:
        outbox_stmt = (
            pg_insert(NotificationOutboxModel)
            .values(
                id=str(uuid.uuid4()),
                dedupe_key=f"ioc.critical_blocked:{ioc.ioc_type}:{ioc.ioc_value}"[:200],
                event_name="ioc.critical_blocked",
                channel="N8N_WEBHOOK",
                payload={
                    "ioc_id": ioc.id,
                    "ioc_type": ioc.ioc_type,
                    "ioc_value": ioc.ioc_value,
                    "list_type": ioc.list_type,
                    "confidence_score": ioc.confidence_score,
                    "source": ioc.source,
                },
                status="PENDING",
                attempts=0,
                created_at=datetime.now(timezone.utc),
            )
            .on_conflict_do_nothing(index_elements=["dedupe_key"])
        )
        await db.execute(outbox_stmt)

    await AuditRepository(db).append(
        user_email=actor_email,
        action="IOC_UPSERTED",
        resource=f"ioc:{ioc.id}",
        payload={
            "ioc_type": ioc.ioc_type,
            "ioc_value": ioc.ioc_value,
            "list_type": ioc.list_type,
            "confidence_score": ioc.confidence_score,
            "created": created,
        },
        client_ip=client_ip,
    )
    return ioc, created


async def deactivate_ioc_command(
    db: AsyncSession,
    ioc_id: str,
    actor_email: str = "system",
    client_ip: str = "",
) -> Optional[IocModel]:
    repo = IocRepository(db)
    ioc = await repo.deactivate(ioc_id)
    if ioc is not None:
        await AuditRepository(db).append(
            user_email=actor_email,
            action="IOC_DEACTIVATED",
            resource=f"ioc:{ioc.id}",
            payload={"ioc_value": ioc.ioc_value, "list_type": ioc.list_type},
            client_ip=client_ip,
        )
    return ioc
