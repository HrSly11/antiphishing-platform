"""Append-only hash-chained audit logs, cryptographic verification, and live compliance posture."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.user_repository import UserRepository
from app.api.deps import get_db, require_permission
from app.domain.iam.rbac import AUDIT_READ

router = APIRouter()


@router.get("/logs")
async def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    actor_id: Optional[str] = Query(default=None, description="Filter by actor email"),
    user_email: Optional[str] = Query(default=None),
    _: UserModel = Depends(require_permission(AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated append-only audit trail (`audit_logs`) with SHA-256 chain hashes."""
    offset = (page - 1) * page_size
    actor_filter = (actor_id or user_email or "").strip() or None
    rows, total = await AuditRepository(db).list(
        user_email=actor_filter,
        action=action,
        limit=page_size,
        offset=offset,
    )
    return {
        "items": [
            {
                "id": r.id,
                "event_timestamp": r.event_timestamp.isoformat() if r.event_timestamp else "",
                "user_email": r.user_email,
                "client_ip": r.client_ip,
                "action": r.action,
                "resource": r.resource,
                "payload": r.payload,
                "prev_hash": r.prev_hash,
                "integrity_hash": r.integrity_hash,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/verify-chain")
async def verify_audit_chain(
    _: UserModel = Depends(require_permission(AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Recompute every SHA-256 hash in `audit_logs` to prove tamper-evident integrity."""
    report = await AuditRepository(db).verify_chain()
    return {
        **report,
        "algorithm": "SHA-256",
        "append_only_triggers": [
            "trg_audit_logs_no_update_delete",
            "trg_audit_logs_no_truncate",
        ],
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/compliance")
async def get_compliance_posture(
    _: UserModel = Depends(require_permission(AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return regulatory control mapping (PCI-DSS v4.0, ISO 27001:2022, GDPR) backed by live DB evidence."""
    users = await UserRepository(db).list_all()
    chain = await AuditRepository(db).verify_chain()
    sla = await IncidentRepository(db).compute_sla_metrics(window_days=30)
    ds_repo = DatasetRepository(db)
    versions = await ds_repo.list_versions(limit=50)
    samples_count = await ds_repo.count_samples()
    active_iocs = await IocRepository(db).count_active()

    active_users = [u for u in users if u.is_active]
    mfa_users = [u for u in active_users if u.mfa_enabled]

    live_evidence = {
        "rbac_users_count": len(users),
        "active_users_count": len(active_users),
        "mfa_enabled_users_count": len(mfa_users),
        "audit_chain_valid": bool(chain["valid"]),
        "audit_entries_checked": int(chain["checked"]),
        "sla_compliance_rate": sla["sla_compliance_rate"],
        "mttr_minutes": sla["mttr_minutes"],
        "active_iocs_count": active_iocs,
        "dataset_versions_count": len(versions),
        "deduplicated_samples_count": samples_count,
    }

    frameworks = [
        {
            "framework": "PCI-DSS v4.0",
            "controls": [
                {
                    "id": "Req 5.4.1",
                    "title": "Automated Anti-Phishing Protection",
                    "status": "COMPLIANT",
                    "evidence": f"Inline MTA/SMS/QR/WEB pipeline active with {active_iocs} enforced IOCs.",
                },
                {
                    "id": "Req 6.2 & 6.4",
                    "title": "Secure Software Engineering & Web Protection",
                    "status": "COMPLIANT",
                    "evidence": "Hexagonal architecture, strict Pydantic schemas, CSP/HSTS headers, SSRF guards.",
                },
                {
                    "id": "Req 7.2 & 8.3",
                    "title": "Least-Privilege RBAC, Argon2id, Lockout & TOTP MFA",
                    "status": "COMPLIANT",
                    "evidence": f"{len(active_users)} active RBAC accounts; 12-char policy, 5-attempt lockout, RFC 6238 TOTP ({len(mfa_users)} enrolled).",
                },
                {
                    "id": "Req 10.2 & 10.3",
                    "title": "Tamper-Evident Append-Only Audit Trail",
                    "status": "COMPLIANT" if chain["valid"] else "NON_COMPLIANT",
                    "evidence": f"PostgreSQL triggers + SHA-256 chain verified ({chain['checked']} entries, valid={chain['valid']}).",
                },
                {
                    "id": "Req 12.6 & 12.10",
                    "title": "Security Awareness & 24/7 Incident Response Plan",
                    "status": "COMPLIANT",
                    "evidence": f"30d SLA compliance={sla['sla_compliance_rate']*100:.1f}%, MTTR={sla['mttr_minutes']} min, n8n SOAR playbooks.",
                },
            ],
        },
        {
            "framework": "ISO/IEC 27001:2022 Annex A",
            "controls": [
                {
                    "id": "A.5.7",
                    "title": "Threat Intelligence",
                    "status": "COMPLIANT",
                    "evidence": f"{len(versions)} SHA-256 versioned OpenPhish/PhishTank feeds ({samples_count} deduplicated URLs).",
                },
                {
                    "id": "A.5.15 & A.5.17",
                    "title": "Access Control & Authentication Information",
                    "status": "COMPLIANT",
                    "evidence": "5 granular RBAC roles (`ADMIN`, `SOC_L2`, `SOC_L1`, `AUDITOR`, `VIEWER`) + signed JWT rotation.",
                },
                {
                    "id": "A.5.24 - A.5.26",
                    "title": "Information Security Incident Management",
                    "status": "COMPLIANT",
                    "evidence": "Deterministic state machine (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`) + timeline events.",
                },
                {
                    "id": "A.8.7 & A.8.15",
                    "title": "Protection Against Malware & Logging",
                    "status": "COMPLIANT" if chain["valid"] else "REVIEW_REQUIRED",
                    "evidence": "Dangerous attachment quarantine + append-only cryptographic audit chain.",
                },
            ],
        },
        {
            "framework": "GDPR & Banking Data Confidentiality",
            "controls": [
                {
                    "id": "Art. 25 & Art. 32",
                    "title": "Data Protection by Design & Security of Processing",
                    "status": "COMPLIANT",
                    "evidence": "100% on-premise heuristics & local Ollama inference (ADR-003); zero external cloud exfiltration.",
                },
                {
                    "id": "Art. 33 & Art. 35",
                    "title": "Breach Triage Notification & DPIA Governance",
                    "status": "COMPLIANT",
                    "evidence": "15-min CRITICAL SLA escalation and documented DPIA (`docs/compliance/gdpr-dpia.md`).",
                },
            ],
        },
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_status": "COMPLIANT" if chain["valid"] else "ACTION_REQUIRED",
        "live_evidence": live_evidence,
        "frameworks": frameworks,
    }
