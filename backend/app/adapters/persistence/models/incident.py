import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class IncidentModel(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    verdict_id: Mapped[str] = mapped_column(String(36), ForeignKey("detection_verdicts.id"), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="HIGH", index=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN", index=True)
    resolution: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    is_escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
