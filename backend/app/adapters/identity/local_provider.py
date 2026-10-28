"""Local Argon2id + RFC 6238 TOTP identity provider descriptor."""
from typing import Any, Dict


def get_local_provider_status() -> Dict[str, Any]:
    return {
        "id": "local-argon2id",
        "name": "Local SOC Directory (Argon2id + RFC 6238 TOTP)",
        "protocol": "JWT/OAuth2-Bearer",
        "enabled": True,
        "status": "ACTIVE",
        "mfa_supported": True,
        "lockout_policy": "5 failed attempts -> 15 min lockout (PCI-DSS 8.3)",
    }
