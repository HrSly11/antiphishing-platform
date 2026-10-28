"""Import every model so they are registered on Base.metadata (used by Alembic and tests)."""
from app.adapters.persistence.models.audit_log import AuditLogModel
from app.adapters.persistence.models.dataset_version import DatasetVersionModel
from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel
from app.adapters.persistence.models.incident import IncidentModel
from app.adapters.persistence.models.incident_event import IncidentEventModel
from app.adapters.persistence.models.incident_ioc import IncidentIocModel
from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.notification_outbox import NotificationOutboxModel
from app.adapters.persistence.models.phishing_sample import PhishingSampleModel
from app.adapters.persistence.models.report_schedule import ReportScheduleModel
from app.adapters.persistence.models.simulation import (
    SimulationCampaignModel,
    SimulationEventModel,
)
from app.adapters.persistence.models.user import UserModel

__all__ = [
    "AuditLogModel",
    "DatasetVersionModel",
    "DetectionVerdictModel",
    "IncidentModel",
    "IncidentEventModel",
    "IncidentIocModel",
    "IocModel",
    "NotificationOutboxModel",
    "PhishingSampleModel",
    "ReportScheduleModel",
    "SimulationCampaignModel",
    "SimulationEventModel",
    "UserModel",
]
