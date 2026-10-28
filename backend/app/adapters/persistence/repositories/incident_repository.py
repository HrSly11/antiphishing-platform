"""PostgreSQL repository for SOC incidents, immutable timeline events, IOC links, and SLA tracking."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from sqlalchemy import desc, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel
from app.adapters.persistence.models.incident import IncidentModel
from app.adapters.persistence.models.incident_event import IncidentEventModel
from app.adapters.persistence.models.incident_ioc import IncidentIocModel
from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.notification_outbox import NotificationOutboxModel
from app.adapters.persistence.models.user import UserModel
from app.core.metrics import INCIDENTS_ESCALATED
from app.domain.incident.lifecycle import CLOSED, OPEN, validate_transition
from app.domain.incident.sla import is_overdue, sla_deadline


def _generate_incident_code(now: datetime) -> str:
    return f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def _severity_for_score(risk_score: int) -> str:
    if risk_score >= 85:
        return "CRITICAL"
    if risk_score >= 70:
        return "HIGH"
    if risk_score >= 35:
        return "MEDIUM"
    return "LOW"


class IncidentRepository:
    """Async persistence adapter for `incidents`, `incident_events`, and `incident_iocs`."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _resolve_actor(self, actor_id: Optional[Union[str, uuid.UUID]]) -> str:
        if actor_id is None:
            return "system"
        raw = str(actor_id).strip()
        if not raw:
            return "system"
        if "@" in raw:
            return raw[:255]
        user = await self.db.scalar(select(UserModel).where(UserModel.id == raw))
        return user.email if user else raw[:255]

    async def _link_iocs(self, incident_id: str, ioc_ids: Optional[Iterable[str]]) -> None:
        if not ioc_ids:
            return
        unique_ids = list({str(i).strip() for i in ioc_ids if i and str(i).strip()})
        if not unique_ids:
            return
        values = [{"incident_id": incident_id, "ioc_id": iid} for iid in unique_ids]
        stmt = pg_insert(IncidentIocModel).values(values).on_conflict_do_nothing(
            index_elements=["incident_id", "ioc_id"]
        )
        await self.db.execute(stmt)

    async def _queue_outbox(
        self,
        dedupe_key: str,
        event_name: str,
        payload: Dict[str, Any],
        channel: str = "N8N_WEBHOOK",
    ) -> None:
        stmt = (
            pg_insert(NotificationOutboxModel)
            .values(
                id=str(uuid.uuid4()),
                dedupe_key=dedupe_key[:200],
                event_name=event_name[:80],
                channel=channel[:20],
                payload=payload,
                status="PENDING",
                attempts=0,
                created_at=datetime.now(timezone.utc),
            )
            .on_conflict_do_nothing(index_elements=["dedupe_key"])
        )
        await self.db.execute(stmt)

    async def create_from_verdict(
        self,
        verdict: DetectionVerdictModel,
        severity: Optional[str] = None,
        actor_id: Optional[Union[str, uuid.UUID]] = "system",
        ioc_ids: Optional[Iterable[str]] = None,
        notes: Optional[str] = None,
        queue_notification: bool = True,
    ) -> IncidentModel:
        now = datetime.now(timezone.utc)
        sev = (severity or _severity_for_score(verdict.risk_score)).upper()
        if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            sev = "HIGH"
        actor = await self._resolve_actor(actor_id)
        code = _generate_incident_code(now)
        deadline = sla_deadline(sev, now)

        incident = IncidentModel(
            id=str(uuid.uuid4()),
            incident_code=code,
            verdict_id=verdict.id,
            severity=sev,
            status=OPEN,
            sla_deadline=deadline,
            is_escalated=False,
            created_at=now,
        )
        self.db.add(incident)
        await self.db.flush()

        event = IncidentEventModel(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            event_type="CREATED",
            from_status=None,
            to_status=OPEN,
            actor=actor,
            note=notes
            or f"Incident created automatically from detection verdict {verdict.correlation_id} (risk_score={verdict.risk_score}).",
            created_at=now,
        )
        self.db.add(event)
        await self._link_iocs(incident.id, ioc_ids)

        if queue_notification:
            await self._queue_outbox(
                dedupe_key=f"incident.created:{incident.incident_code}",
                event_name="incident.created",
                payload={
                    "incident_id": incident.id,
                    "incident_code": incident.incident_code,
                    "severity": incident.severity,
                    "status": incident.status,
                    "sla_deadline": deadline.isoformat(),
                    "verdict_id": verdict.id,
                    "correlation_id": verdict.correlation_id,
                    "sender_email": verdict.sender_email,
                    "recipient_email": verdict.recipient_email,
                    "subject": verdict.subject,
                    "risk_score": verdict.risk_score,
                },
            )

        await self.db.flush()
        return incident

    async def create_manual(
        self,
        severity: str = "HIGH",
        subject: str = "Manual SOC Phishing Incident",
        sender_email: str = "unknown@external.invalid",
        recipient_email: str = "soc@bancocentral.com",
        summary: str = "Incident created manually by SOC analyst.",
        actor_id: Optional[Union[str, uuid.UUID]] = None,
        verdict_id: Optional[str] = None,
        ioc_ids: Optional[Iterable[str]] = None,
        notes: Optional[str] = None,
        channel: str = "EMAIL",
        risk_score: int = 85,
    ) -> IncidentModel:
        now = datetime.now(timezone.utc)
        sev = (severity or "HIGH").upper()
        if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            sev = "HIGH"

        if verdict_id:
            verdict = await self.db.scalar(
                select(DetectionVerdictModel).where(DetectionVerdictModel.id == str(verdict_id))
            )
        else:
            verdict = None

        if verdict is None:
            verdict = DetectionVerdictModel(
                id=str(uuid.uuid4()),
                correlation_id=f"MANUAL-{uuid.uuid4().hex[:12].upper()}",
                sender_email=sender_email[:255],
                recipient_email=recipient_email[:255],
                subject=subject[:500],
                channel=channel.upper()[:20],
                risk_score=max(0, min(100, int(risk_score))),
                verdict="MALICIOUS" if risk_score >= 70 else "SUSPICIOUS",
                action_taken="QUARANTINE" if risk_score >= 70 else "TAG_AND_BANNER",
                summary=summary[:1000],
                latency_ms=0,
                analyst_label="TRUE_POSITIVE",
                headers_meta={"_manual_incident": True},
                signals_meta=[
                    {
                        "name": "MANUAL_SOC_ESCALATION",
                        "weight": 85,
                        "score": 1.0,
                        "reason": summary[:300],
                    }
                ],
                created_at=now,
            )
            self.db.add(verdict)
            await self.db.flush()

        return await self.create_from_verdict(
            verdict=verdict,
            severity=sev,
            actor_id=actor_id,
            ioc_ids=ioc_ids,
            notes=notes or summary,
            queue_notification=True,
        )

    async def get_model_by_id(self, incident_id: Union[str, uuid.UUID]) -> Optional[IncidentModel]:
        ident = str(incident_id).strip()
        inc = await self.db.scalar(select(IncidentModel).where(IncidentModel.id == ident))
        if inc is None:
            inc = await self.db.scalar(
                select(IncidentModel).where(IncidentModel.incident_code == ident)
            )
        return inc

    async def get_by_id(self, incident_id: Union[str, uuid.UUID]) -> Optional[Dict[str, Any]]:
        inc = await self.get_model_by_id(incident_id)
        if inc is None:
            return None

        verdict = await self.db.scalar(
            select(DetectionVerdictModel).where(DetectionVerdictModel.id == inc.verdict_id)
        )
        assignee = (
            await self.db.scalar(select(UserModel).where(UserModel.id == inc.assigned_user_id))
            if inc.assigned_user_id
            else None
        )
        events = list(
            (
                await self.db.scalars(
                    select(IncidentEventModel)
                    .where(IncidentEventModel.incident_id == inc.id)
                    .order_by(IncidentEventModel.created_at.asc(), IncidentEventModel.id.asc())
                )
            ).all()
        )
        iocs = list(
            (
                await self.db.scalars(
                    select(IocModel)
                    .join(IncidentIocModel, IncidentIocModel.ioc_id == IocModel.id)
                    .where(IncidentIocModel.incident_id == inc.id)
                    .order_by(IocModel.created_at.desc())
                )
            ).all()
        )

        overdue = is_overdue(inc.sla_deadline, inc.status)
        return {
            "id": inc.id,
            "incident_code": inc.incident_code,
            "verdict_id": inc.verdict_id,
            "severity": inc.severity,
            "status": inc.status,
            "resolution": inc.resolution,
            "assigned_user_id": inc.assigned_user_id,
            "assigned_to": assignee.email if assignee else None,
            "assigned_user_name": assignee.full_name if assignee else None,
            "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None,
            "sla_overdue": overdue,
            "is_escalated": inc.is_escalated,
            "created_at": inc.created_at.isoformat() if inc.created_at else "",
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "sender_email": verdict.sender_email if verdict else None,
            "recipient_email": verdict.recipient_email if verdict else None,
            "subject": verdict.subject if verdict else None,
            "channel": verdict.channel if verdict else "EMAIL",
            "risk_score": verdict.risk_score if verdict else None,
            "verdict_summary": verdict.summary if verdict else "",
            "signals": list(verdict.signals_meta or []) if verdict else [],
            "events": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "from_status": e.from_status,
                    "to_status": e.to_status,
                    "actor": e.actor,
                    "note": e.note,
                    "created_at": e.created_at.isoformat() if e.created_at else "",
                }
                for e in events
            ],
            "iocs": [
                {
                    "id": i.id,
                    "ioc_type": i.ioc_type,
                    "ioc_value": i.ioc_value,
                    "list_type": i.list_type,
                    "confidence_score": i.confidence_score,
                    "source": i.source,
                    "is_active": i.is_active,
                    "created_at": i.created_at.isoformat() if i.created_at else "",
                }
                for i in iocs
            ],
            "incident_model": inc,
            "verdict_model": verdict,
        }

    async def list_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        overdue_only: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 500))
        offset = (page - 1) * page_size
        now_utc = datetime.now(timezone.utc)

        conditions = []
        if status:
            conditions.append(IncidentModel.status == status.strip().upper())
        if severity:
            conditions.append(IncidentModel.severity == severity.strip().upper())
        if overdue_only:
            conditions.append(IncidentModel.status != CLOSED)
            conditions.append(IncidentModel.sla_deadline.is_not(None))
            conditions.append(IncidentModel.sla_deadline < now_utc)

        stmt = (
            select(IncidentModel, DetectionVerdictModel, UserModel)
            .outerjoin(DetectionVerdictModel, IncidentModel.verdict_id == DetectionVerdictModel.id)
            .outerjoin(UserModel, IncidentModel.assigned_user_id == UserModel.id)
            .where(*conditions)
            .order_by(desc(IncidentModel.created_at))
            .limit(page_size)
            .offset(offset)
        )
        count_stmt = select(func.count(IncidentModel.id)).where(*conditions)

        rows = (await self.db.execute(stmt)).all()
        total = int(await self.db.scalar(count_stmt) or 0)

        items: List[Dict[str, Any]] = []
        for inc, verd, user in rows:
            items.append(
                {
                    "id": inc.id,
                    "incident_code": inc.incident_code,
                    "verdict_id": inc.verdict_id,
                    "severity": inc.severity,
                    "status": inc.status,
                    "resolution": inc.resolution,
                    "assigned_user_id": inc.assigned_user_id,
                    "assigned_to": user.email if user else None,
                    "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None,
                    "sla_overdue": is_overdue(inc.sla_deadline, inc.status, now_utc),
                    "is_escalated": inc.is_escalated,
                    "created_at": inc.created_at.isoformat() if inc.created_at else "",
                    "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
                    "sender_email": verd.sender_email if verd else None,
                    "subject": verd.subject if verd else None,
                    "risk_score": verd.risk_score if verd else None,
                }
            )
        return items, total

    async def transition_status(
        self,
        incident_id: Union[str, uuid.UUID],
        new_status: str,
        actor_id: Optional[Union[str, uuid.UUID]] = "system",
        resolution: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[IncidentModel]:
        inc = await self.get_model_by_id(incident_id)
        if inc is None:
            return None

        target_status = new_status.strip().upper()
        norm_resolution = resolution.strip().upper() if resolution else None
        validate_transition(inc.status, target_status, norm_resolution)

        prev_status = inc.status
        now = datetime.now(timezone.utc)
        inc.status = target_status
        if target_status == CLOSED:
            inc.resolution = norm_resolution
            inc.resolved_at = now

        actor = await self._resolve_actor(actor_id)
        self.db.add(
            IncidentEventModel(
                id=str(uuid.uuid4()),
                incident_id=inc.id,
                event_type="STATUS_CHANGED",
                from_status=prev_status,
                to_status=target_status,
                actor=actor,
                note=notes
                or (f"Closed with resolution {norm_resolution}" if target_status == CLOSED else None),
                created_at=now,
            )
        )
        await self.db.flush()
        return inc

    async def assign_user(
        self,
        incident_id: Union[str, uuid.UUID],
        assignee_id: Optional[Union[str, uuid.UUID]],
        actor_id: Optional[Union[str, uuid.UUID]] = "system",
    ) -> Optional[IncidentModel]:
        inc = await self.get_model_by_id(incident_id)
        if inc is None:
            return None

        assignee_str = str(assignee_id).strip() if assignee_id else None
        assignee_label = "unassigned"
        if assignee_str:
            user = await self.db.scalar(select(UserModel).where(UserModel.id == assignee_str))
            if user is None and "@" in assignee_str:
                user = await self.db.scalar(
                    select(UserModel).where(UserModel.email == assignee_str.lower())
                )
            if user is not None:
                assignee_str = user.id
                assignee_label = user.email
            else:
                assignee_label = assignee_str

        inc.assigned_user_id = assignee_str
        actor = await self._resolve_actor(actor_id)
        self.db.add(
            IncidentEventModel(
                id=str(uuid.uuid4()),
                incident_id=inc.id,
                event_type="ASSIGNED",
                from_status=inc.status,
                to_status=inc.status,
                actor=actor,
                note=f"Assigned incident to {assignee_label}",
                created_at=datetime.now(timezone.utc),
            )
        )
        await self.db.flush()
        return inc

    async def add_note(
        self,
        incident_id: Union[str, uuid.UUID],
        note: str,
        actor_id: Optional[Union[str, uuid.UUID]] = "system",
    ) -> Optional[IncidentEventModel]:
        inc = await self.get_model_by_id(incident_id)
        if inc is None:
            return None

        actor = await self._resolve_actor(actor_id)
        event = IncidentEventModel(
            id=str(uuid.uuid4()),
            incident_id=inc.id,
            event_type="NOTE_ADDED",
            from_status=inc.status,
            to_status=inc.status,
            actor=actor,
            note=note.strip(),
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(event)
        await self.db.flush()
        return event

    async def escalate_overdue(self, now: Optional[datetime] = None) -> List[IncidentModel]:
        ref_now = now or datetime.now(timezone.utc)
        stmt = (
            select(IncidentModel)
            .where(
                IncidentModel.status != CLOSED,
                IncidentModel.is_escalated.is_(False),
                IncidentModel.sla_deadline.is_not(None),
                IncidentModel.sla_deadline < ref_now,
            )
            .order_by(IncidentModel.sla_deadline.asc())
        )
        overdue_incidents = list((await self.db.scalars(stmt)).all())
        if not overdue_incidents:
            return []

        for inc in overdue_incidents:
            inc.is_escalated = True
            self.db.add(
                IncidentEventModel(
                    id=str(uuid.uuid4()),
                    incident_id=inc.id,
                    event_type="ESCALATED",
                    from_status=inc.status,
                    to_status=inc.status,
                    actor="sla-worker",
                    note=f"Automatic SLA escalation triggered: deadline {inc.sla_deadline.isoformat() if inc.sla_deadline else ''} exceeded while status={inc.status}.",
                    created_at=ref_now,
                )
            )
            await self._queue_outbox(
                dedupe_key=f"incident.escalated:{inc.id}",
                event_name="incident.escalated",
                payload={
                    "incident_id": inc.id,
                    "incident_code": inc.incident_code,
                    "severity": inc.severity,
                    "status": inc.status,
                    "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None,
                    "escalated_at": ref_now.isoformat(),
                },
            )
            INCIDENTS_ESCALATED.inc()

        await self.db.flush()
        return overdue_incidents

    async def compute_sla_metrics(self, window_days: int = 30) -> Dict[str, Any]:
        days = max(1, min(int(window_days), 365))
        now_utc = datetime.now(timezone.utc)
        cutoff = now_utc - timedelta(days=days)

        sql = text(
            """
            SELECT
                COUNT(*) FILTER (WHERE status <> 'CLOSED')::int AS open_count,
                COUNT(*) FILTER (
                    WHERE status <> 'CLOSED' AND sla_deadline IS NOT NULL AND sla_deadline < :now_utc
                )::int AS overdue_count,
                AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60.0)
                    FILTER (WHERE status = 'CLOSED' AND resolved_at IS NOT NULL AND created_at >= :cutoff)::float
                    AS mttr_minutes,
                COUNT(*) FILTER (WHERE created_at >= :cutoff)::int AS window_total,
                COUNT(*) FILTER (
                    WHERE created_at >= :cutoff AND (
                        (status = 'CLOSED' AND (sla_deadline IS NULL OR resolved_at <= sla_deadline))
                        OR (status <> 'CLOSED' AND (sla_deadline IS NULL OR sla_deadline >= :now_utc))
                    )
                )::int AS window_compliant
            FROM incidents
            """
        )
        row = (
            await self.db.execute(sql, {"now_utc": now_utc, "cutoff": cutoff})
        ).mappings().first() or {}

        triage_sql = text(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (first_triage.triage_at - i.created_at)) / 60.0)::float AS mttt_minutes
            FROM incidents i
            JOIN (
                SELECT incident_id, MIN(created_at) AS triage_at
                FROM incident_events
                WHERE event_type IN ('STATUS_CHANGED', 'TRANSITION')
                GROUP BY incident_id
            ) first_triage ON first_triage.incident_id = i.id
            WHERE i.created_at >= :cutoff
            """
        )
        triage_row = (await self.db.execute(triage_sql, {"cutoff": cutoff})).mappings().first() or {}

        window_total = int(row.get("window_total") or 0)
        window_compliant = int(row.get("window_compliant") or 0)
        compliance_rate = round(window_compliant / window_total, 4) if window_total > 0 else 1.0
        mttr = (
            round(float(row["mttr_minutes"]), 2)
            if row.get("mttr_minutes") is not None
            else None
        )
        mttt = (
            round(float(triage_row["mttt_minutes"]), 2)
            if triage_row.get("mttt_minutes") is not None
            else None
        )

        return {
            "open_count": int(row.get("open_count") or 0),
            "overdue_count": int(row.get("overdue_count") or 0),
            "mttr_minutes": mttr,
            "mttt_minutes": mttt,
            "sla_compliance_rate": compliance_rate,
        }
