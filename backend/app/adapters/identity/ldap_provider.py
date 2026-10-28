"""Corporate Active Directory / LDAPS identity provider readiness adapter."""
import os
from typing import Any, Dict


def get_ldap_provider_status() -> Dict[str, Any]:
    ldap_url = os.getenv("LDAP_SERVER_URL", "")
    return {
        "id": "corporate-ldaps",
        "name": "Corporate Active Directory (LDAPS :636)",
        "protocol": "LDAPS / StartTLS",
        "enabled": bool(ldap_url),
        "status": "CONFIGURED" if ldap_url else "STANDBY_ADAPTER_READY",
        "base_dn": os.getenv("LDAP_BASE_DN", "dc=bancocentral,dc=internal"),
        "group_mapping": {
            "CN=SOC-Admins,OU=Security": "ADMIN",
            "CN=SOC-Tier2,OU=Security": "SOC_L2",
            "CN=SOC-Tier1,OU=Security": "SOC_L1",
            "CN=Internal-Audit,OU=Compliance": "AUDITOR",
        },
    }
