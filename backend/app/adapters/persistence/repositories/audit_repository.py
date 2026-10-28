"""Hash-chained, append-only audit trail (PCI-DSS 10.2/10.3, ISO 27001 A.8.15)."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.audit_log import AuditLogModel

_LOCK_ID = 7001  # serialises appends so the chain has a single, well-defined order


def compute_hash(prev_hash: Optional[str], ts: datetime, user_email: str, client_ip: str,
                 action: str, resource: str, payload: Dict[str, Any]) -> str:
    body = json.dumps(
        {"prev": prev_hash or "", "ts": ts.isoformat(), "user": user_email, "ip": client_ip,
         "action": action, "resource": resource, "payload": payload},
        sort_keys=True, default=str, ensure_ascii=False,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def append(self, user_email: str, action: str, resource: str = "",
                     payload: Optional[Dict[str, Any]] = None, client_ip: str = "") -> AuditLogModel:
        payload = payload or {}
        await self.db.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": _LOCK_ID})
        prev = await self.db.scalar(
            select(AuditLogModel.integrity_hash).order_by(desc(AuditLogModel.id)).limit(1)
        )
        ts = datetime.now(timezone.utc)
        row = AuditLogModel(
            event_timestamp=ts, user_email=user_email, client_ip=client_ip, action=action,
            resource=resource, payload=payload, prev_hash=prev,
            integrity_hash=compute_hash(prev, ts, user_email, client_ip, action, resource, payload),
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def list(self, user_email: Optional[str] = None, action: Optional[str] = None,
                   limit: int = 100, offset: int = 0) -> Tuple[List[AuditLogModel], int]:
        stmt = select(AuditLogModel)
        count = select(func.count(AuditLogModel.id))
        if user_email:
            stmt = stmt.where(AuditLogModel.user_email == user_email)
            count = count.where(AuditLogModel.user_email == user_email)
        if action:
            stmt = stmt.where(AuditLogModel.action == action)
            count = count.where(AuditLogModel.action == action)
        rows = (await self.db.scalars(stmt.order_by(desc(AuditLogModel.id)).limit(limit).offset(offset))).all()
        return list(rows), int(await self.db.scalar(count) or 0)

    async def verify_chain(self) -> Dict[str, Any]:
        """Recompute every hash. Returns where the chain breaks, if it does."""
        rows = (await self.db.scalars(select(AuditLogModel).order_by(AuditLogModel.id))).all()
        prev: Optional[str] = None
        for row in rows:
            expected = compute_hash(prev, row.event_timestamp, row.user_email, row.client_ip,
                                    row.action, row.resource, row.payload)
            if row.prev_hash != prev or row.integrity_hash != expected:
                return {"valid": False, "checked": len(rows), "broken_at_id": row.id}
            prev = row.integrity_hash
        return {"valid": True, "checked": len(rows), "broken_at_id": None}
