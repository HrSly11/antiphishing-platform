"""Password policy and lockout rules (ISO 27001 A.5.17 / PCI-DSS 8.3)."""
import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from app.domain.shared.errors import WeakPassword

MIN_LENGTH = 12
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
COMMON_PASSWORDS = {"12345", "123456", "password", "qwerty", "admin", "letmein", "bancocentral"}


def validate_password(password: str) -> List[str]:
    """Return the list of violated rules (empty list means the password is acceptable)."""
    problems: List[str] = []
    if len(password) < MIN_LENGTH:
        problems.append(f"at least {MIN_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^\w\s]", password):
        problems.append("a special character")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not be a commonly used password")
    return problems


def assert_strong_password(password: str) -> None:
    problems = validate_password(password)
    if problems:
        raise WeakPassword("Password must contain: " + ", ".join(problems))


def lock_deadline(failed_attempts: int, now: Optional[datetime] = None) -> Optional[datetime]:
    """Return the lock expiry once the failed attempts reach the threshold, else None."""
    if failed_attempts < MAX_FAILED_ATTEMPTS:
        return None
    return (now or datetime.now(timezone.utc)) + timedelta(minutes=LOCK_MINUTES)


def is_locked(locked_until: Optional[datetime], now: Optional[datetime] = None) -> bool:
    return locked_until is not None and locked_until > (now or datetime.now(timezone.utc))
