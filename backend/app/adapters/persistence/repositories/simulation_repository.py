"""PostgreSQL repository for phishing awareness simulation campaigns and employee interaction events."""
from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel
from app.adapters.persistence.models.simulation import (
    SimulationCampaignModel,
    SimulationEventModel,
)
from app.domain.simulation.entities import SIMULATION_CHANNELS, SIMULATION_EVENT_TYPES
from app.domain.simulation.metrics import compute_campaign_metrics


class SimulationRepository:
    """Async persistence adapter for `simulation_campaigns` and `simulation_events`."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def list_campaigns(self, limit: int = 100) -> List[SimulationCampaignModel]:
        rows = (
            await self.db.scalars(
                select(SimulationCampaignModel)
                .order_by(desc(SimulationCampaignModel.created_at))
                .limit(max(1, min(limit, 500)))
            )
        ).all()
        return list(rows)

    async def get_campaign(self, campaign_id: str) -> Optional[SimulationCampaignModel]:
        return await self.db.scalar(
            select(SimulationCampaignModel).where(SimulationCampaignModel.id == str(campaign_id).strip())
        )

    async def create_campaign(
        self,
        name: str,
        channel: str = "EMAIL",
        template_subject: str = "Security Awareness Simulation",
        lure_type: str = "CREDENTIAL_HARVEST",
        target_department: str = "All Employees",
        total_targets: int = 50,
        created_by: str = "system",
    ) -> SimulationCampaignModel:
        now = datetime.now(timezone.utc)
        ch = (channel or "EMAIL").strip().upper()
        if ch not in SIMULATION_CHANNELS:
            ch = "EMAIL"

        campaign = SimulationCampaignModel(
            id=str(uuid.uuid4()),
            name=name.strip()[:200],
            channel=ch,
            template_subject=template_subject.strip()[:300],
            lure_type=(lure_type or "CREDENTIAL_HARVEST").strip().upper()[:80],
            target_department=(target_department or "All Employees").strip()[:120],
            status="ACTIVE",
            total_targets=max(1, int(total_targets)),
            sent_count=0,
            opened_count=0,
            clicked_count=0,
            reported_count=0,
            click_rate=0.0,
            report_rate=0.0,
            compromise_risk="LOW",
            created_by=created_by[:255],
            launched_at=now,
            created_at=now,
        )
        self.db.add(campaign)
        await self.db.flush()
        return campaign

    async def recompute_campaign_stats(self, campaign: SimulationCampaignModel) -> SimulationCampaignModel:
        rows = (
            await self.db.execute(
                select(
                    SimulationEventModel.event_type,
                    func.count(func.distinct(SimulationEventModel.employee_email)),
                )
                .where(SimulationEventModel.campaign_id == campaign.id)
                .group_by(SimulationEventModel.event_type)
            )
        ).all()
        counts = {etype: int(cnt) for etype, cnt in rows}

        campaign.sent_count = max(
            counts.get("SENT", 0),
            counts.get("OPENED", 0),
            counts.get("CLICKED", 0),
            counts.get("REPORTED", 0),
        )
        campaign.opened_count = max(counts.get("OPENED", 0), counts.get("CLICKED", 0))
        campaign.clicked_count = counts.get("CLICKED", 0)
        campaign.reported_count = counts.get("REPORTED", 0)
        if campaign.sent_count > campaign.total_targets:
            campaign.total_targets = campaign.sent_count

        computed = compute_campaign_metrics(
            total_targets=campaign.total_targets,
            sent_count=campaign.sent_count,
            opened_count=campaign.opened_count,
            clicked_count=campaign.clicked_count,
            reported_count=campaign.reported_count,
        )
        campaign.click_rate = float(computed["click_rate"])
        campaign.report_rate = float(computed["report_rate"])
        campaign.compromise_risk = str(computed["compromise_risk"])
        await self.db.flush()
        return campaign

    async def record_event(
        self,
        campaign_id: str,
        employee_email: str,
        event_type: str,
        department: str = "",
        metadata_json: Optional[Dict[str, Any]] = None,
        occurred_at: Optional[datetime] = None,
    ) -> Optional[SimulationEventModel]:
        campaign = await self.get_campaign(campaign_id)
        if campaign is None:
            return None

        ev_type = (event_type or "").strip().upper()
        if ev_type not in SIMULATION_EVENT_TYPES:
            raise ValueError(f"Unsupported simulation event_type '{event_type}'")

        dept = (department or campaign.target_department or "Corporate").strip()[:120]
        ev = SimulationEventModel(
            id=str(uuid.uuid4()),
            campaign_id=campaign.id,
            employee_email=employee_email.strip().lower()[:255],
            department=dept,
            event_type=ev_type,
            metadata_json=dict(metadata_json or {}),
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )
        self.db.add(ev)
        await self.db.flush()
        await self.recompute_campaign_stats(campaign)
        return ev

    async def get_aggregate_metrics(self) -> Dict[str, Any]:
        campaigns = await self.list_campaigns(limit=500)
        total_campaigns = len(campaigns)
        active_campaigns = sum(1 for c in campaigns if c.status == "ACTIVE")
        total_targets = sum(c.total_targets for c in campaigns)
        total_sent = sum(c.sent_count for c in campaigns)
        total_opened = sum(c.opened_count for c in campaigns)
        total_clicked = sum(c.clicked_count for c in campaigns)
        total_reported = sum(c.reported_count for c in campaigns)

        overall = compute_campaign_metrics(
            total_targets=max(1, total_targets),
            sent_count=total_sent,
            opened_count=total_opened,
            clicked_count=total_clicked,
            reported_count=total_reported,
        )

        # Count real employee phishing reports submitted via the "Reportar phishing" button
        real_reported_count = int(
            await self.db.scalar(
                select(func.count(DetectionVerdictModel.id)).where(
                    DetectionVerdictModel.headers_meta["_reported_by_user"].astext == "true"
                )
            )
            or 0
        )

        dept_map: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"targets": 0, "sent": 0, "clicked": 0, "reported": 0}
        )
        for c in campaigns:
            bucket = dept_map[c.target_department or "All Employees"]
            bucket["targets"] += c.total_targets
            bucket["sent"] += c.sent_count
            bucket["clicked"] += c.clicked_count
            bucket["reported"] += c.reported_count

        by_department = []
        for dept_name, b in sorted(dept_map.items()):
            dm = compute_campaign_metrics(
                total_targets=max(1, b["targets"]),
                sent_count=b["sent"],
                opened_count=b["clicked"],
                clicked_count=b["clicked"],
                reported_count=b["reported"],
            )
            by_department.append(
                {
                    "department": dept_name,
                    "targets": b["targets"],
                    "sent": b["sent"],
                    "clicked": b["clicked"],
                    "reported": b["reported"],
                    "click_rate": dm["click_rate"],
                    "report_rate": dm["report_rate"],
                    "compromise_risk": dm["compromise_risk"],
                }
            )

        return {
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "total_targets": total_targets,
            "total_sent": total_sent,
            "total_opened": total_opened,
            "total_clicked": total_clicked,
            "total_reported": total_reported,
            "overall_open_rate": overall["open_rate"],
            "overall_click_rate": overall["click_rate"],
            "overall_report_rate": overall["report_rate"],
            "overall_compromise_risk": overall["compromise_risk"],
            "employee_reported_phishing_count": real_reported_count,
            "by_department": by_department,
        }
