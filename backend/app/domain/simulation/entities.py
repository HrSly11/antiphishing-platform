"""Domain entities and constants for employee phishing awareness simulation campaigns."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import FrozenSet, Optional

SIMULATION_CHANNELS: FrozenSet[str] = frozenset({"EMAIL", "SMS", "QR", "WEB"})
SIMULATION_EVENT_TYPES: FrozenSet[str] = frozenset({"SENT", "OPENED", "CLICKED", "REPORTED"})
SIMULATION_STATUSES: FrozenSet[str] = frozenset({"DRAFT", "ACTIVE", "COMPLETED"})


@dataclass(frozen=True)
class SimulationCampaign:
    id: str
    name: str
    channel: str
    template_subject: str
    lure_type: str
    target_department: str
    status: str
    total_targets: int
    sent_count: int
    opened_count: int
    clicked_count: int
    reported_count: int
    click_rate: float
    report_rate: float
    compromise_risk: str
    created_by: str
    created_at: datetime
    completed_at: Optional[datetime] = None


@dataclass(frozen=True)
class SimulationEvent:
    id: str
    campaign_id: str
    employee_email: str
    department: str
    event_type: str
    occurred_at: datetime
