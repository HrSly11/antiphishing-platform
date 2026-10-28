"""Blacklist/whitelist rules: TTL expiry and precedence (whitelist always wins over blacklist)."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional

BLACKLIST = "BLACKLIST"
WHITELIST = "WHITELIST"


@dataclass(frozen=True)
class ListEntry:
    value: str
    list_type: str
    source: str
    expires_at: Optional[datetime] = None
    is_active: bool = True


def is_effective(entry: ListEntry, now: Optional[datetime] = None) -> bool:
    if not entry.is_active:
        return False
    if entry.expires_at is None:
        return True
    return entry.expires_at > (now or datetime.now(timezone.utc))


def decide(entries: Iterable[ListEntry], now: Optional[datetime] = None) -> Optional[str]:
    """Return WHITELIST, BLACKLIST or None. Whitelist takes precedence over blacklist."""
    effective = [e for e in entries if is_effective(e, now)]
    if any(e.list_type == WHITELIST for e in effective):
        return WHITELIST
    if any(e.list_type == BLACKLIST for e in effective):
        return BLACKLIST
    return None
