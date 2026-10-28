import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class IocModel(Base):
    """Indicator of compromise. Also acts as blacklist/whitelist entry through `list_type`."""

    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("ioc_value", "list_type", name="uq_ioc_value_list"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type: Mapped[str] = mapped_column(String(30), index=True)  # DOMAIN, URL, IP, HASH, EMAIL
    ioc_value: Mapped[str] = mapped_column(String(500), index=True)
    list_type: Mapped[str] = mapped_column(String(20), default="BLACKLIST", index=True)  # BLACKLIST | WHITELIST
    confidence_score: Mapped[int] = mapped_column(Integer, default=100)
    source: Mapped[str] = mapped_column(String(100), default="MANUAL")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
