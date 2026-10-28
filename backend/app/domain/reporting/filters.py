"""Report filters (date range / channel / severity)."""
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional, Tuple


@dataclass(frozen=True)
class ReportFilter:
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    verdict: Optional[str] = None
    channel: Optional[str] = None

    def bounds(self) -> Tuple[datetime, datetime]:
        """Inclusive UTC [start, end) window; defaults to the last 7 days."""
        end_day = self.date_to or datetime.now(timezone.utc).date()
        start_day = self.date_from or (end_day - timedelta(days=6))
        start = datetime.combine(start_day, time.min, tzinfo=timezone.utc)
        end = datetime.combine(end_day + timedelta(days=1), time.min, tzinfo=timezone.utc)
        return start, end
