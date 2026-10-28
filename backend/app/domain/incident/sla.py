"""SLA deadline calculation by severity (minutes until the first response is due)."""
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

SLA_MINUTES: Dict[str, int] = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}


def sla_deadline(severity: str, created_at: Optional[datetime] = None) -> datetime:
    start = created_at or datetime.now(timezone.utc)
    return start + timedelta(minutes=SLA_MINUTES.get(severity, SLA_MINUTES["MEDIUM"]))


def is_overdue(deadline: Optional[datetime], status: str, now: Optional[datetime] = None) -> bool:
    """An incident is overdue when it is not closed and its deadline already passed."""
    if deadline is None or status == "CLOSED":
        return False
    return deadline < (now or datetime.now(timezone.utc))
