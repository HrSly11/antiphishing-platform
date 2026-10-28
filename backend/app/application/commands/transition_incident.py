"""Incident lifecycle transition, assignment, notes, and SLA escalation commands."""
from __future__ import annotations

from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.incident import IncidentModel
from app.adapters.persistence.models.incident_event import IncidentEventModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository


async def transition_incident_command(
    db: AsyncSession,
    incident_id: str,
    new_status: str,
    actor_email: str = "system",
    resolution: Optional[str] = None,
    notes: Optional[str] = None,
    client_ip: str = "",
) -> Optional[IncidentModel]:
    inc_repo = IncidentRepository(db)
    inc = await inc_repo.transition_status(
        incident_id=incident_id,
        new_status=new_status,
        actor_id=actor_email,
        resolution=resolution,
        notes=notes,
    )
    if inc is not None:
        await AuditRepository(db).append(
            user_email=actor_email,
            action="INCIDENT_TRANSITIONED",
            resource=f"incident:{inc.incident_code}",
            payload={"new_status": inc.status, "resolution": inc.resolution, "notes": notes},
            client_ip=client_ip,
        )
    return inc


async def assign_incident_command(
    db: AsyncSession,
    incident_id: str,
    assignee_id: Optional[str],
    actor_email: str = "system",
    client_ip: str = "",
) -> Optional[IncidentModel]:
    inc_repo = IncidentRepository(db)
    inc = await inc_repo.assign_user(
        incident_id=incident_id,
        assignee_id=assignee_id,
        actor_id=actor_email,
    )
    if inc is not None:
        await AuditRepository(db).append(
            user_email=actor_email,
            action="INCIDENT_ASSIGNED",
            resource=f"incident:{inc.incident_code}",
            payload={"assigned_user_id": inc.assigned_user_id},
            client_ip=client_ip,
        )
    return inc


async def add_incident_note_command(
    db: AsyncSession,
    incident_id: str,
    note: str,
    actor_email: str = "system",
    client_ip: str = "",
) -> Optional[IncidentEventModel]:
    inc_repo = IncidentRepository(db)
    ev = await inc_repo.add_note(incident_id=incident_id, note=note, actor_id=actor_email)
    if ev is not None:
        await AuditRepository(db).append(
            user_email=actor_email,
            action="INCIDENT_NOTE_ADDED",
            resource=f"incident:{incident_id}",
            payload={"event_id": ev.id},
            client_ip=client_ip,
        )
    return ev


async def escalate_overdue_incidents_command(
    db: AsyncSession,
    actor_email: str = "sla-worker",
    client_ip: str = "",
) -> List[IncidentModel]:
    inc_repo = IncidentRepository(db)
    escalated = await inc_repo.escalate_overdue()
    if escalated:
        await AuditRepository(db).append(
            user_email=actor_email,
            action="INCIDENT_SLA_ESCALATION",
            resource="incidents:overdue",
            payload={"escalated_codes": [i.incident_code for i in escalated]},
            client_ip=client_ip,
        )
    return escalated
