"""Domain errors. The API layer maps these to HTTP status codes (see core/exceptions.py)."""


class DomainError(Exception):
    """Base class for all domain rule violations."""


class InvalidTransition(DomainError):
    """An incident lifecycle transition is not allowed."""


class WeakPassword(DomainError):
    """The password does not satisfy the password policy."""


class AccountLocked(DomainError):
    """Too many failed login attempts."""


class PermissionDenied(DomainError):
    """The role does not hold the required permission."""
