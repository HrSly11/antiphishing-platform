"""Enterprise SAML 2.0 / OIDC Federation (Entra ID / Okta) readiness adapter."""
import os
from typing import Any, Dict


def get_saml_oidc_provider_status() -> Dict[str, Any]:
    idp_metadata = os.getenv("SAML_IDP_METADATA_URL", "")
    oidc_issuer = os.getenv("OIDC_ISSUER_URL", "")
    configured = bool(idp_metadata or oidc_issuer)
    return {
        "id": "enterprise-saml-oidc",
        "name": "Banking Enterprise SSO (Microsoft Entra ID / SAML 2.0 & OIDC)",
        "protocol": "SAML 2.0 / OpenID Connect",
        "enabled": configured,
        "status": "CONFIGURED" if configured else "STANDBY_ADAPTER_READY",
        "sp_entity_id": "urn:bancocentral:soc:antiphishing-platform",
        "acs_endpoint": "/api/v1/auth/sso/acs",
        "mfa_enforcement": "IdP Conditional Access + Local TOTP Step-Up",
    }
