"""SQLAlchemy models for phishing awareness simulation campaigns and employee interaction events."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class SimulationCampaignModel(Base):
    __tablename__ = "simulation_campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), index=True)
    channel: Mapped[str] = mapped_column(String(20), default="EMAIL", index=True)
    template_subject: Mapped[str] = mapped_column(String(300))
    lure_type: Mapped[str] = mapped_column(String(80), default="CREDENTIAL_HARVEST")
    target_department: Mapped[str] = mapped_column(String(120), default="All Employees", index=True)
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE", index=True)
    total_targets: Mapped[int] = mapped_column(Integer, default=50)
    sent_count: Mapped[int] = mapped_column(Integer, default=0)
    opened_count: Mapped[int] = mapped_column(Integer, default=0)
    clicked_count: Mapped[int] = mapped_column(Integer, default=0)
    reported_count: Mapped[int] = mapped_column(Integer, default=0)
    click_rate: Mapped[float] = mapped_column(Float, default=0.0)
    report_rate: Mapped[float] = mapped_column(Float, default=0.0)
    compromise_risk: Mapped[str] = mapped_column(String(20), default="LOW")
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    launched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class SimulationEventModel(Base):
    __tablename__ = "simulation_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("simulation_campaigns.id", ondelete="CASCADE"),
        index=True,
    )
    employee_email: Mapped[str] = mapped_column(String(255), index=True)
    department: Mapped[str] = mapped_column(String(120), default="")
    event_type: Mapped[str] = mapped_column(String(20), index=True)  # SENT | OPENED | CLICKED | REPORTED
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
