"""Multi-format report generation (PDF, DOCX, XLSX) and automated schedule CRUD endpoints."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.report_schedule import ReportScheduleModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.api.deps import ActorPrincipal, allow_service_or_permission, get_client_ip, get_db
from app.application.commands.generate_report import generate_report_command
from app.application.dto.report_dto import ScheduleOut
from app.domain.iam.rbac import REPORTS_MANAGE, REPORTS_READ
from app.workers.report_worker import run_due_report_schedules

router = APIRouter()


class GenerateReportPayload(BaseModel):
    report_format: str = Field(default="pdf", pattern="^(pdf|docx|xlsx)$")
    template: str = Field(default="operational", pattern="^(executive|management|operational|compliance)$")
    window_days: int = Field(default=30, ge=1, le=365)
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    verdict: Optional[str] = Field(default=None, pattern="^(CLEAN|SUSPICIOUS|MALICIOUS)$")
    channel: Optional[str] = Field(default=None, pattern="^(EMAIL|SMS|WEB|QR)$")
    recipient_email: Optional[str] = Field(default=None, max_length=500)


class ScheduleCreatePayload(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    report_format: str = Field(default="pdf", pattern="^(pdf|docx|xlsx)$")
    frequency: str = Field(default="DAILY", pattern="^(DAILY|WEEKLY)$")
    recipients: List[str] = Field(..., min_length=1, max_length=20)
    template: str = Field(default="management", pattern="^(executive|management|operational|compliance)$")
    window_days: Optional[int] = Field(default=None, ge=1, le=365)


def _serialize_schedule(row: ReportScheduleModel) -> ScheduleOut:
    filters = dict(row.filters or {})
    recipients_list = [r.strip() for r in (row.recipients or "").split(",") if r.strip()]
    return ScheduleOut(
        id=row.id,
        name=row.name,
        report_format=row.report_format,
        frequency=row.frequency,
        recipients=recipients_list,
        template=str(filters.get("template") or "management"),
        is_active=row.is_active,
        next_run_at=row.next_run_at.isoformat() if row.next_run_at else "",
        last_run_at=row.last_run_at.isoformat() if row.last_run_at else None,
        last_status=row.last_status,
    )


@router.get("/export/{fmt}")
async def export_report(
    request: Request,
    fmt: str = Path(..., pattern="^(pdf|docx|xlsx)$"),
    template: str = Query(default="executive", pattern="^(executive|management|operational|compliance)$"),
    window_days: int = Query(default=30, ge=1, le=365),
    date_from: Optional[date] = Query(default=None),
    date_to: Optional[date] = Query(default=None),
    verdict: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    recipient_email: Optional[str] = Query(default=None),
    actor: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Stream a freshly rendered PDF, DOCX, or XLSX report directly from live PostgreSQL telemetry."""
    raw_bytes, mime_type, filename = await generate_report_command(
        db=db,
        report_format=fmt,
        template=template,
        window_days=window_days,
        date_from=date_from,
        date_to=date_to,
        verdict=verdict,
        channel=channel,
        recipient_email=recipient_email,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return Response(
        content=raw_bytes,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/generate")
async def generate_report(
    payload: GenerateReportPayload,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate a PDF, DOCX, or XLSX report from JSON criteria (used by SOC UI and n8n daily_report)."""
    raw_bytes, mime_type, filename = await generate_report_command(
        db=db,
        report_format=payload.report_format,
        template=payload.template,
        window_days=payload.window_days,
        date_from=payload.date_from,
        date_to=payload.date_to,
        verdict=payload.verdict,
        channel=payload.channel,
        recipient_email=payload.recipient_email,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return Response(
        content=raw_bytes,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/schedules", response_model=List[ScheduleOut])
async def list_schedules(
    _: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> List[ScheduleOut]:
    """List configured recurring report schedules."""
    rows = (
        await db.scalars(select(ReportScheduleModel).order_by(desc(ReportScheduleModel.created_at)))
    ).all()
    return [_serialize_schedule(r) for r in rows]


@router.post("/schedules", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreatePayload,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> ScheduleOut:
    """Create a recurring DAILY or WEEKLY report schedule."""
    now = datetime.now(timezone.utc)
    default_window = payload.window_days or (1 if payload.frequency == "DAILY" else 7)
    next_run = now + (timedelta(days=1) if payload.frequency == "DAILY" else timedelta(days=7))

    sched = ReportScheduleModel(
        id=str(uuid.uuid4()),
        name=payload.name.strip(),
        report_format=payload.report_format,
        frequency=payload.frequency,
        recipients=",".join(r.strip() for r in payload.recipients if r.strip()),
        filters={"template": payload.template, "window_days": default_window},
        is_active=True,
        next_run_at=next_run,
        created_by=actor.email,
        created_at=now,
    )
    db.add(sched)
    await db.flush()

    await AuditRepository(db).append(
        user_email=actor.email,
        action="REPORT_SCHEDULE_CREATED",
        resource=f"report_schedule:{sched.id}",
        payload={"name": sched.name, "format": sched.report_format, "frequency": sched.frequency},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return _serialize_schedule(sched)


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Deactivate and remove a report schedule."""
    sched = await db.scalar(select(ReportScheduleModel).where(ReportScheduleModel.id == schedule_id))
    if sched is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report schedule not found")

    await db.delete(sched)
    await AuditRepository(db).append(
        user_email=actor.email,
        action="REPORT_SCHEDULE_DELETED",
        resource=f"report_schedule:{schedule_id}",
        payload={"name": sched.name},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {"id": schedule_id, "status": "deleted"}


@router.post("/schedules/run-due")
async def trigger_due_schedules(
    force_all: bool = Query(default=False),
    _: ActorPrincipal = Depends(allow_service_or_permission(REPORTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Execute all due report schedules (or all active schedules when `force_all=true`)."""
    res = await run_due_report_schedules(db=db, force_all=force_all)
    await db.commit()
    return res
