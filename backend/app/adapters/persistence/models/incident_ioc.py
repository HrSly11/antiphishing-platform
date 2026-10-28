from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.adapters.persistence.base import Base


class IncidentIocModel(Base):
    """Association between an incident and the IOCs extracted from it."""

    __tablename__ = "incident_iocs"

    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), primary_key=True)
    ioc_id: Mapped[str] = mapped_column(String(36), ForeignKey("iocs.id"), primary_key=True)
