from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.ioc import IocModel


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class IocRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def find_entries(self, values: Iterable[str]) -> List[IocModel]:
        """Active entries (any list) whose value matches one of the given values exactly."""
        wanted = {v.strip().lower() for v in values if v}
        if not wanted:
            return []
        stmt = select(IocModel).where(IocModel.is_active.is_(True), func.lower(IocModel.ioc_value).in_(wanted))
        return list((await self.db.scalars(stmt)).all())

    async def list(
        self,
        list_type: Optional[str] = None,
        ioc_type: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = True,
    ) -> Tuple[List[IocModel], int]:
        conditions = []
        if active_only:
            conditions.append(IocModel.is_active.is_(True))
        if list_type:
            conditions.append(IocModel.list_type == list_type.strip().upper())
        if ioc_type:
            conditions.append(IocModel.ioc_type == ioc_type.strip().upper())
        if q:
            conditions.append(IocModel.ioc_value.ilike(f"%{_like_escape(q.strip())}%", escape="\\"))
        rows = (
            await self.db.scalars(
                select(IocModel)
                .where(*conditions)
                .order_by(IocModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        total = await self.db.scalar(select(func.count(IocModel.id)).where(*conditions))
        return list(rows), int(total or 0)

    async def search_fuzzy(
        self,
        q: str,
        limit: int = 20,
        threshold: float = 0.3,
    ) -> List[Tuple[IocModel, float]]:
        """Trigram similarity search (pg_trgm): finds look-alike domains such as banc0central.com."""
        q_clean = q.strip().lower()
        sim = func.similarity(IocModel.ioc_value, q_clean)
        min_sim = max(0.05, min(float(threshold), 1.0))
        stmt = (
            select(IocModel, sim.label("sim"))
            .where(
                IocModel.is_active.is_(True),
                or_(
                    IocModel.ioc_value.ilike(f"%{_like_escape(q_clean)}%", escape="\\"),
                    sim > min_sim,
                ),
            )
            .order_by(sim.desc(), IocModel.created_at.desc())
            .limit(max(1, min(int(limit), 200)))
        )
        return [(row[0], float(row[1])) for row in (await self.db.execute(stmt)).all()]

    async def upsert(
        self,
        ioc_type: str,
        value: str,
        list_type: str,
        confidence: int,
        source: str,
        ttl_days: Optional[int],
        created_by: str,
        ttl_hours: Optional[int] = None,
    ) -> Tuple[IocModel, bool]:
        value = value.strip().lower()
        existing = await self.db.scalar(
            select(IocModel).where(IocModel.ioc_value == value, IocModel.list_type == list_type)
        )
        expires: Optional[datetime] = None
        if ttl_hours:
            expires = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        elif ttl_days:
            expires = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        if existing:
            existing.is_active = True
            existing.confidence_score = max(existing.confidence_score, confidence)
            existing.expires_at = expires
            if source:
                existing.source = source[:100]
            await self.db.flush()
            return existing, False
        row = IocModel(
            ioc_type=ioc_type,
            ioc_value=value,
            list_type=list_type,
            confidence_score=confidence,
            source=source[:100],
            expires_at=expires,
            created_by=created_by,
        )
        self.db.add(row)
        await self.db.flush()
        return row, True

    async def deactivate(self, ioc_id: str) -> Optional[IocModel]:
        row = await self.db.scalar(select(IocModel).where(IocModel.id == ioc_id))
        if row:
            row.is_active = False
            await self.db.flush()
        return row

    async def count_active(self) -> int:
        return int(await self.db.scalar(select(func.count(IocModel.id)).where(IocModel.is_active.is_(True))) or 0)
