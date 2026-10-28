"""Scheduled executive & operational report generation and delivery worker."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.database import async_session_factory, engine
from app.adapters.persistence.models.report_schedule import ReportScheduleModel
from app.application.commands.generate_report import generate_report_command
from app.core.logging import get_logger

log = get_logger("worker.reports")


async def _execute_due_on_session(db: AsyncSession, force_all: bool = False) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    conditions = [ReportScheduleModel.is_active.is_(True)]
    if not force_all:
        conditions.append(ReportScheduleModel.next_run_at <= now)

    rows = list(
        (
            await db.scalars(
                select(ReportScheduleModel)
                .where(*conditions)
                .order_by(ReportScheduleModel.next_run_at.asc())
            )
        ).all()
    )

    executed: List[Dict[str, Any]] = []
    for sched in rows:
        filters = dict(sched.filters or {})
        template = str(filters.get("template") or "management")
        window_days = int(filters.get("window_days") or (1 if sched.frequency == "DAILY" else 7))
        verdict = filters.get("verdict")
        channel = filters.get("channel")

        try:
            raw_bytes, _, filename = await generate_report_command(
                db=db,
                report_format=sched.report_format,
                template=template,
                window_days=window_days,
                verdict=verdict,
                channel=channel,
                recipient_email=sched.recipients,
                actor_email="report-worker@bancocentral.com",
            )
            sched.last_run_at = now
            delta = timedelta(days=1) if sched.frequency.upper() == "DAILY" else timedelta(days=7)
            sched.next_run_at = now + delta
            sched.last_status = f"DELIVERED ({filename}, {len(raw_bytes)} bytes)"
            executed.append(
                {
                    "schedule_id": sched.id,
                    "name": sched.name,
                    "format": sched.report_format,
                    "filename": filename,
                    "bytes": len(raw_bytes),
                    "status": sched.last_status,
                }
            )
        except Exception as exc:  # noqa: BLE001
            sched.last_run_at = now
            sched.last_status = f"FAILED: {type(exc).__name__}: {exc}"[:300]
            log.warning("Scheduled report '%s' failed: %s", sched.name, exc)
            executed.append(
                {
                    "schedule_id": sched.id,
                    "name": sched.name,
                    "format": sched.report_format,
                    "status": sched.last_status,
                }
            )

    await db.flush()
    return {"executed_count": len(executed), "schedules": executed}


async def run_due_report_schedules(
    db: Optional[AsyncSession] = None,
    force_all: bool = False,
) -> Dict[str, Any]:
    """Execute all active report schedules whose `next_run_at` has elapsed."""
    if db is not None:
        return await _execute_due_on_session(db, force_all=force_all)

    async with async_session_factory() as session:
        res = await _execute_due_on_session(session, force_all=force_all)
        await session.commit()
        return res


async def _cli() -> None:
    try:
        res = await run_due_report_schedules()
        print(res)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_cli())
