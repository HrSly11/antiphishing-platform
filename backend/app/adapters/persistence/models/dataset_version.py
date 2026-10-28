import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base
from app.adapters.persistence.models.user import utcnow


class DatasetVersionModel(Base):
    """One immutable ingestion run. `sha256` is the hash of the raw downloaded file."""

    __tablename__ = "dataset_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(100), index=True)  # OpenPhish, PhishTank, ...
    source_url: Mapped[str] = mapped_column(String(500))
    license: Mapped[str] = mapped_column(String(200), default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    raw_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    new_records: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_records: Mapped[int] = mapped_column(Integer, default=0)
    invalid_records: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="COMPLETED")
    triggered_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
