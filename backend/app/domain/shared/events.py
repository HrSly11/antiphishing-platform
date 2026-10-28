"""Domain event base and the events emitted by the detection flow."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass(frozen=True)
class DomainEvent:
    name: str
    payload: Dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def phishing_quarantined(payload: Dict[str, Any]) -> DomainEvent:
    return DomainEvent("phishing.quarantined", payload)


def incident_escalated(payload: Dict[str, Any]) -> DomainEvent:
    return DomainEvent("incident.escalated", payload)
