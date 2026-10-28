"""Employee phishing awareness simulation campaigns, interaction events, and human-risk KPIs."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.simulation import SimulationCampaignModel
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.simulation_repository import SimulationRepository
from app.api.deps import (
    ActorPrincipal,
    allow_service_or_permission,
    get_client_ip,
    get_db,
    require_permission,
)
from app.domain.iam.rbac import DETECTION_READ, INCIDENTS_WRITE

router = APIRouter()


class CampaignCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    channel: str = Field(default="EMAIL", pattern="^(EMAIL|SMS|QR|WEB)$")
    template_subject: str = Field(..., min_length=3, max_length=300)
    lure_type: str = Field(default="CREDENTIAL_HARVEST", max_length=80)
    target_department: str = Field(default="All Employees", max_length=120)
    total_targets: int = Field(default=50, ge=1, le=100_000)


class SimulationEventCreateRequest(BaseModel):
    employee_email: str = Field(..., min_length=5, max_length=255)
    event_type: str = Field(..., pattern="^(SENT|OPENED|CLICKED|REPORTED)$")
    department: str = Field(default="", max_length=120)
    metadata: Dict[str, Any] = Field(default_factory=dict)


def _serialize_campaign(c: SimulationCampaignModel) -> Dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "channel": c.channel,
        "template_subject": c.template_subject,
        "lure_type": c.lure_type,
        "target_department": c.target_department,
        "status": c.status,
        "total_targets": c.total_targets,
        "sent_count": c.sent_count,
        "opened_count": c.opened_count,
        "clicked_count": c.clicked_count,
        "reported_count": c.reported_count,
        "click_rate": c.click_rate,
        "report_rate": c.report_rate,
        "compromise_risk": c.compromise_risk,
        "created_by": c.created_by,
        "launched_at": c.launched_at.isoformat() if c.launched_at else "",
        "completed_at": c.completed_at.isoformat() if c.completed_at else None,
        "created_at": c.created_at.isoformat() if c.created_at else "",
    }


@router.get("/campaigns")
async def list_campaigns(
    _: UserModel = Depends(require_permission(DETECTION_READ)),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List employee phishing awareness simulation campaigns."""
    rows = await SimulationRepository(db).list_campaigns()
    return [_serialize_campaign(c) for c in rows]


@router.post("/campaigns", status_code=status.HTTP_201_CREATED)
async def create_campaign(
    payload: CampaignCreateRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Launch a new phishing awareness simulation campaign."""
    campaign = await SimulationRepository(db).create_campaign(
        name=payload.name,
        channel=payload.channel,
        template_subject=payload.template_subject,
        lure_type=payload.lure_type,
        target_department=payload.target_department,
        total_targets=payload.total_targets,
        created_by=actor.email,
    )
    await AuditRepository(db).append(
        user_email=actor.email,
        action="SIMULATION_CAMPAIGN_CREATED",
        resource=f"campaign:{campaign.id}",
        payload={
            "name": campaign.name,
            "channel": campaign.channel,
            "target_department": campaign.target_department,
            "total_targets": campaign.total_targets,
        },
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return _serialize_campaign(campaign)


@router.post("/campaigns/{campaign_id}/events", status_code=status.HTTP_201_CREATED)
async def record_campaign_event(
    campaign_id: str,
    payload: SimulationEventCreateRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Record an employee simulation event (`SENT`, `OPENED`, `CLICKED`, `REPORTED`) and recompute KPIs."""
    repo = SimulationRepository(db)
    ev = await repo.record_event(
        campaign_id=campaign_id,
        employee_email=payload.employee_email,
        event_type=payload.event_type,
        department=payload.department,
        metadata_json=payload.metadata,
    )
    if ev is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation campaign not found")

    campaign = await repo.get_campaign(campaign_id)
    await AuditRepository(db).append(
        user_email=actor.email,
        action="SIMULATION_EVENT_RECORDED",
        resource=f"campaign:{campaign_id}",
        payload={"employee_email": ev.employee_email, "event_type": ev.event_type},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {
        "event": {
            "id": ev.id,
            "campaign_id": ev.campaign_id,
            "employee_email": ev.employee_email,
            "department": ev.department,
            "event_type": ev.event_type,
            "occurred_at": ev.occurred_at.isoformat() if ev.occurred_at else "",
        },
        "campaign": _serialize_campaign(campaign) if campaign else None,
    }


@router.get("/metrics")
async def get_simulation_metrics(
    _: UserModel = Depends(require_permission(DETECTION_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return aggregate human-awareness KPIs across simulation campaigns and employee phishing reports."""
    return await SimulationRepository(db).get_aggregate_metrics()
