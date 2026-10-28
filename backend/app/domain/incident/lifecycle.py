"""Incident state machine: detection -> triage -> investigation -> containment -> closure."""
from typing import Dict, FrozenSet, Optional

from app.domain.shared.errors import InvalidTransition

OPEN = "OPEN"
TRIAGED = "TRIAGED"
INVESTIGATING = "INVESTIGATING"
CONTAINED = "CONTAINED"
CLOSED = "CLOSED"

ALL_STATES: FrozenSet[str] = frozenset({OPEN, TRIAGED, INVESTIGATING, CONTAINED, CLOSED})

ALLOWED_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    OPEN: frozenset({TRIAGED, CLOSED}),
    TRIAGED: frozenset({INVESTIGATING, CLOSED}),
    INVESTIGATING: frozenset({CONTAINED, CLOSED}),
    CONTAINED: frozenset({CLOSED}),
    CLOSED: frozenset(),
}

RESOLUTIONS: FrozenSet[str] = frozenset(
    {"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_POLICY_VIOLATION", "DUPLICATE"}
)


def validate_transition(current: str, new: str, resolution: Optional[str] = None) -> None:
    if new not in ALL_STATES:
        raise InvalidTransition(f"Unknown state '{new}'. Allowed: {sorted(ALL_STATES)}")
    if new not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        allowed = sorted(ALLOWED_TRANSITIONS.get(current, frozenset())) or ["none (terminal state)"]
        raise InvalidTransition(f"Cannot move from {current} to {new}. Allowed: {allowed}")
    if new == CLOSED and resolution not in RESOLUTIONS:
        raise InvalidTransition(f"Closing requires a resolution in {sorted(RESOLUTIONS)}")
