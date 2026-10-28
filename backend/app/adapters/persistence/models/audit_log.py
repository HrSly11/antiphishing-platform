from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class AuditLogModel(Base):
    """Append-only audit trail. Each row carries a hash chained to the previous row.

    UPDATE and DELETE are rejected by a database trigger (see migration 0005).
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    user_email: Mapped[str] = mapped_column(String(255), index=True)
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource: Mapped[str] = mapped_column(String(255), default="")
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    integrity_hash: Mapped[str] = mapped_column(String(64))
