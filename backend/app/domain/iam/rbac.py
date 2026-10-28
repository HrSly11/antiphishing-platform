"""Granular RBAC: permissions are per action ("resource:action"), roles are bundles of permissions."""
from typing import Dict, FrozenSet

# Permission catalogue (single source of truth).
DETECTION_ANALYZE = "detection:analyze"
DETECTION_READ = "detection:read"
DASHBOARD_READ = "dashboard:read"
INCIDENTS_READ = "incidents:read"
INCIDENTS_WRITE = "incidents:write"
IOCS_READ = "iocs:read"
IOCS_WRITE = "iocs:write"
REPORTS_READ = "reports:read"
REPORTS_MANAGE = "reports:manage"
DATASET_READ = "dataset:read"
DATASET_ADMIN = "dataset:admin"
HUNTING_READ = "hunting:read"
AUDIT_READ = "audit:read"
USERS_READ = "users:read"
USERS_WRITE = "users:write"

ALL_PERMISSIONS: FrozenSet[str] = frozenset(
    {
        DETECTION_ANALYZE, DETECTION_READ, DASHBOARD_READ, INCIDENTS_READ, INCIDENTS_WRITE,
        IOCS_READ, IOCS_WRITE, REPORTS_READ, REPORTS_MANAGE, DATASET_READ, DATASET_ADMIN,
        HUNTING_READ, AUDIT_READ, USERS_READ, USERS_WRITE,
    }
)

_READ_ONLY = frozenset(
    {DETECTION_READ, DASHBOARD_READ, INCIDENTS_READ, IOCS_READ, REPORTS_READ, DATASET_READ}
)

ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "ADMIN": ALL_PERMISSIONS,
    "SOC_L2": _READ_ONLY
    | {DETECTION_ANALYZE, INCIDENTS_WRITE, IOCS_WRITE, HUNTING_READ, REPORTS_MANAGE, AUDIT_READ},
    "SOC_L1": _READ_ONLY | {DETECTION_ANALYZE, INCIDENTS_WRITE, HUNTING_READ},
    "AUDITOR": _READ_ONLY | {AUDIT_READ, HUNTING_READ},
    "VIEWER": _READ_ONLY,
}


def permissions_for(role: str) -> FrozenSet[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for(role)
