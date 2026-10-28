import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class ReportScheduleModel(Base):
    """A recurring report that is generated and e-mailed automatically."""

    __tablename__ = "report_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200))
    report_format: Mapped[str] = mapped_column(String(10))  # pdf | docx | xlsx
    frequency: Mapped[str] = mapped_column(String(10))  # DAILY | WEEKLY
    recipients: Mapped[str] = mapped_column(String(1000))  # comma separated e-mails
    filters: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
