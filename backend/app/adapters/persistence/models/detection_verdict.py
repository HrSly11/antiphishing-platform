import uuid
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class DetectionVerdictModel(Base):
    __tablename__ = "detection_verdicts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    correlation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sender_email: Mapped[str] = mapped_column(String(255), index=True)
    recipient_email: Mapped[str] = mapped_column(String(255), index=True)
    subject: Mapped[str] = mapped_column(String(500))
    channel: Mapped[str] = mapped_column(String(20), default="EMAIL", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    verdict: Mapped[str] = mapped_column(String(20), index=True)  # CLEAN, SUSPICIOUS, MALICIOUS
    action_taken: Mapped[str] = mapped_column(String(20))  # DELIVER, TAG_AND_BANNER, QUARANTINE
    summary: Mapped[str] = mapped_column(String(1000))
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    analyst_label: Mapped[str] = mapped_column(String(30), default="UNREVIEWED")  # TRUE_POSITIVE | FALSE_POSITIVE
    headers_meta: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    signals_meta: Mapped[List[Dict[str, Any]]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
