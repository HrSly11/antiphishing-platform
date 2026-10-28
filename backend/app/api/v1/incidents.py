"""SOC Incident lifecycle management, timeline notes, AI briefing, and SLA escalation endpoints."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.llm.langchain.incident_summarizer import summarize_incident
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.api.deps import (
    ActorPrincipal,
    allow_service_or_permission,
    get_client_ip,
    get_db,
    require_permission,
)
from app.application.commands.transition_incident import (
    add_incident_note_command,
    assign_incident_command,
    escalate_overdue_incidents_command,
    transition_incident_command,
)
from app.application.dto.incident_dto import IncidentPage, NoteRequest
from app.domain.iam.rbac import INCIDENTS_READ, INCIDENTS_WRITE

router = APIRouter()


class ManualIncidentCreateRequest(BaseModel):
    severity: str = Field(default="HIGH", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    subject: str = Field(..., min_length=3, max_length=500)
    sender_email: str = Field(default="unknown@external.invalid", max_length=255)
    recipient_email: str = Field(default="soc@bancocentral.com", max_length=255)
    summary: str = Field(default="Manual SOC incident opened by analyst.", max_length=1000)
    verdict_id: Optional[str] = Field(default=None, max_length=36)
    ioc_ids: List[str] = Field(default_factory=list)
    notes: Optional[str] = Field(default=None, max_length=2000)
    channel: str = Field(default="EMAIL", pattern="^(EMAIL|SMS|WEB|QR)$")
    risk_score: int = Field(default=85, ge=0, le=100)


class IncidentTransitionPayload(BaseModel):
    new_status: str = Field(..., min_length=2, max_length=20)
    resolution: Optional[str] = Field(default=None, max_length=40)
    note: Optional[str] = Field(default=None, max_length=2000)
    notes: Optional[str] = Field(default=None, max_length=2000)


class IncidentAssignPayload(BaseModel):
    assignee_id: Optional[str] = Field(default=None, max_length=255)
    user_id: Optional[str] = Field(default=None, max_length=255)


def _clean_detail(detail: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = {
        k: v
        for k, v in detail.items()
        if k not in {"incident_model", "verdict_model"}
    }
    cleaned.setdefault("summary", detail.get("verdict_summary") or "")
    cleaned.setdefault("summary_engine", "verdict-baseline")
    return cleaned


@router.get("", response_model=IncidentPage)
@router.get("/", response_model=IncidentPage, include_in_schema=False)
async def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = Query(default=None),
    overdue_only: bool = Query(default=False),
    _: UserModel = Depends(require_permission(INCIDENTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> IncidentPage:
    """Paginated list of SOC phishing incidents with status, severity, and SLA breach filters."""
    items, total = await IncidentRepository(db).list_paginated(
        page=page,
        page_size=page_size,
        status=status_filter,
        severity=severity,
        overdue_only=overdue_only,
    )
    return IncidentPage(items=items, total=total, page=page, page_size=page_size)


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_incident(
    payload: ManualIncidentCreateRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Create a manual SOC incident and record immutable creation audit trail."""
    repo = IncidentRepository(db)
    inc = await repo.create_manual(
        severity=payload.severity,
        subject=payload.subject,
        sender_email=payload.sender_email,
        recipient_email=payload.recipient_email,
        summary=payload.summary,
        actor_id=current_user.email,
        verdict_id=payload.verdict_id,
        ioc_ids=payload.ioc_ids,
        notes=payload.notes,
        channel=payload.channel,
        risk_score=payload.risk_score,
    )
    await AuditRepository(db).append(
        user_email=current_user.email,
        action="INCIDENT_CREATED",
        resource=f"incident:{inc.incident_code}",
        payload={"incident_id": inc.id, "severity": inc.severity, "subject": payload.subject},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    detail = await repo.get_by_id(inc.id)
    return _clean_detail(detail or {})


@router.post("/escalate-overdue")
async def escalate_overdue_incidents(
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Sweep open incidents past their SLA deadline, escalate them, and queue n8n alerts."""
    escalated = await escalate_overdue_incidents_command(
        db=db,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {
        "escalated_count": len(escalated),
        "incident_ids": [i.id for i in escalated],
        "incident_codes": [i.incident_code for i in escalated],
    }


@router.get("/{incident_id}")
async def get_incident_detail(
    incident_id: str,
    _: UserModel = Depends(require_permission(INCIDENTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return full incident details, immutable timeline events, linked IOCs, and SLA status."""
    detail = await IncidentRepository(db).get_by_id(incident_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return _clean_detail(detail)


@router.post("/{incident_id}/transition")
async def transition_incident(
    incident_id: str,
    payload: IncidentTransitionPayload,
    request: Request,
    current_user: UserModel = Depends(require_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Transition incident state (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`)."""
    inc = await transition_incident_command(
        db=db,
        incident_id=incident_id,
        new_status=payload.new_status,
        actor_email=current_user.email,
        resolution=payload.resolution,
        notes=payload.note or payload.notes,
        client_ip=get_client_ip(request),
    )
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    await db.commit()
    detail = await IncidentRepository(db).get_by_id(inc.id)
    return _clean_detail(detail or {})


@router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    payload: IncidentAssignPayload,
    request: Request,
    current_user: UserModel = Depends(require_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Assign or reassign an incident to a SOC analyst."""
    target_assignee = payload.assignee_id if payload.assignee_id is not None else payload.user_id
    inc = await assign_incident_command(
        db=db,
        incident_id=incident_id,
        assignee_id=target_assignee,
        actor_email=current_user.email,
        client_ip=get_client_ip(request),
    )
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    await db.commit()
    detail = await IncidentRepository(db).get_by_id(inc.id)
    return _clean_detail(detail or {})


@router.post("/{incident_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_incident_note(
    incident_id: str,
    payload: NoteRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Append an immutable investigation note to the incident timeline."""
    ev = await add_incident_note_command(
        db=db,
        incident_id=incident_id,
        note=payload.note,
        actor_email=current_user.email,
        client_ip=get_client_ip(request),
    )
    if ev is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    await db.commit()
    return {
        "id": ev.id,
        "incident_id": ev.incident_id,
        "event_type": ev.event_type,
        "from_status": ev.from_status,
        "to_status": ev.to_status,
        "actor": ev.actor,
        "note": ev.note,
        "created_at": ev.created_at.isoformat() if ev.created_at else "",
    }


@router.post("/{incident_id}/summarize")
async def summarize_incident_endpoint(
    incident_id: str,
    _: UserModel = Depends(require_permission(INCIDENTS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Generate a CISO/SOC executive briefing using the LangChain incident summarizer."""
    detail = await IncidentRepository(db).get_by_id(incident_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    briefing = await summarize_incident(detail)
    return {
        "incident_id": detail["id"],
        "incident_code": detail["incident_code"],
        **briefing,
    }
