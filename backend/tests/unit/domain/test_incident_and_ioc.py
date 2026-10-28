"""Unit tests for SOC incident state machine, SLA deadlines, and IOC list precedence/TTL."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.domain.incident.lifecycle import (
    CLOSED,
    CONTAINED,
    INVESTIGATING,
    OPEN,
    TRIAGED,
    validate_transition,
)
from app.domain.incident.sla import SLA_MINUTES, is_overdue, sla_deadline
from app.domain.ioc.lists import BLACKLIST, WHITELIST, ListEntry, decide, is_effective
from app.domain.shared.errors import InvalidTransition


def test_incident_lifecycle_valid_transitions() -> None:
    validate_transition(OPEN, TRIAGED)
    validate_transition(TRIAGED, INVESTIGATING)
    validate_transition(INVESTIGATING, CONTAINED)
    validate_transition(CONTAINED, CLOSED, resolution="TRUE_POSITIVE")
    validate_transition(OPEN, CLOSED, resolution="FALSE_POSITIVE")
    validate_transition(TRIAGED, CLOSED, resolution="DUPLICATE")


@pytest.mark.parametrize(
    ("current_state", "target_state", "resolution"),
    [
        (OPEN, INVESTIGATING, None),
        (OPEN, CONTAINED, None),
        (TRIAGED, CONTAINED, None),
        (CONTAINED, OPEN, None),
        (CLOSED, OPEN, None),
        (CLOSED, INVESTIGATING, None),
        (OPEN, "UNKNOWN_STATE", None),
        (OPEN, CLOSED, None),             # Missing mandatory resolution
        (CONTAINED, CLOSED, None),        # Missing mandatory resolution
        (CONTAINED, CLOSED, "NOT_VALID"), # Unsupported resolution enum
    ],
)
def test_incident_lifecycle_rejects_invalid_transitions_and_missing_resolution(
    current_state: str,
    target_state: str,
    resolution: str | None,
) -> None:
    with pytest.raises(InvalidTransition):
        validate_transition(current_state, target_state, resolution=resolution)


@pytest.mark.parametrize(
    ("severity", "expected_minutes"),
    [
        ("CRITICAL", 15),
        ("HIGH", 60),
        ("MEDIUM", 240),
        ("LOW", 1440),
    ],
)
def test_sla_deadlines_and_overdue_evaluation(severity: str, expected_minutes: int) -> None:
    assert SLA_MINUTES[severity] == expected_minutes
    created = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)
    deadline = sla_deadline(severity, created_at=created)
    assert deadline == created + timedelta(minutes=expected_minutes)

    # Before deadline -> not overdue
    assert is_overdue(deadline, status=OPEN, now=deadline - timedelta(seconds=1)) is False
    # Past deadline while open/investigating -> overdue
    assert is_overdue(deadline, status=OPEN, now=deadline + timedelta(seconds=1)) is True
    assert is_overdue(deadline, status=INVESTIGATING, now=deadline + timedelta(minutes=5)) is True
    # Closed incidents are never overdue even after the deadline passes
    assert is_overdue(deadline, status=CLOSED, now=deadline + timedelta(hours=3)) is False
    assert is_overdue(None, status=OPEN, now=created) is False


def test_ioc_whitelist_overrides_blacklist_and_respects_ttl() -> None:
    now = datetime(2026, 10, 27, 15, 0, 0, tzinfo=timezone.utc)
    wl_active = ListEntry(
        value="bancocentral.com",
        list_type=WHITELIST,
        source="OFFICIAL",
        expires_at=now + timedelta(days=30),
        is_active=True,
    )
    bl_active = ListEntry(
        value="bancocentral.com",
        list_type=BLACKLIST,
        source="FALSE_FEED",
        expires_at=now + timedelta(days=30),
        is_active=True,
    )
    # Whitelist always overrides conflicting blacklist entry when active
    assert decide([bl_active, wl_active], now=now) == WHITELIST

    # Once whitelist expires, active blacklist takes effect
    wl_expired = ListEntry(
        value="temp-partner.com",
        list_type=WHITELIST,
        source="TEMP_ALLOW",
        expires_at=now - timedelta(minutes=1),
        is_active=True,
    )
    bl_partner = ListEntry(
        value="temp-partner.com",
        list_type=BLACKLIST,
        source="OPENPHISH",
        expires_at=now + timedelta(days=7),
        is_active=True,
    )
    assert is_effective(wl_expired, now=now) is False
    assert decide([wl_expired, bl_partner], now=now) == BLACKLIST

    # Expired or deactivated blacklist yields None
    bl_expired = ListEntry(
        value="old-ioc.net",
        list_type=BLACKLIST,
        source="FEED",
        expires_at=now - timedelta(seconds=5),
        is_active=True,
    )
    bl_inactive = ListEntry(
        value="old-ioc.net",
        list_type=BLACKLIST,
        source="MANUAL",
        expires_at=None,
        is_active=False,
    )
    assert decide([bl_expired, bl_inactive], now=now) is None
