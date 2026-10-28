"""Multi-channel phishing detection, .eml inspection, employee reporting, and verdict labeling."""
from __future__ import annotations

from datetime import date
from typing import Dict, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel
from app.adapters.persistence.models.incident import IncidentModel
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository
from app.api.deps import (
    ActorPrincipal,
    allow_gateway_or_authenticated,
    allow_gateway_or_permission,
    get_client_ip,
    get_db,
    require_permission,
)
from app.application.commands.analyze_input import analyze_email_command, parse_eml_bytes
from app.application.dto.detection_dto import (
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    LabelRequest,
    VerdictOut,
    VerdictPage,
)
from app.core.config import settings
from app.core.rate_limit import RateLimiter, limiter_dependency
from app.domain.dataset.versioning import domain_of, normalize_url
from app.domain.iam.rbac import DETECTION_ANALYZE, DETECTION_READ, INCIDENTS_WRITE

router = APIRouter()

gateway_limiter = RateLimiter(limit=settings.RATE_LIMIT_PER_MINUTE, window_seconds=60)


class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    channel: str = Field(default="WEB", pattern="^(WEB|SMS|QR|EMAIL)$")
    sender: Optional[str] = Field(default=None, max_length=320)
    recipient: Optional[str] = Field(default=None, max_length=320)
    message_text: Optional[str] = Field(default=None, max_length=20_000)
    enrich: bool = True


class EmployeePhishingReportRequest(BaseModel):
    sender_email: Optional[str] = Field(default=None, max_length=320)
    sender: Optional[str] = Field(default=None, max_length=320)
    reported_by_email: Optional[str] = Field(default=None, max_length=320)
    recipient: Optional[str] = Field(default=None, max_length=320)
    subject: str = Field(default="Reported Suspicious Email", max_length=998)
    body_text: str = Field(default="", max_length=200_000)
    body_html: Optional[str] = Field(default=None, max_length=500_000)
    headers: Dict[str, str] = Field(default_factory=dict)
    channel: str = Field(default="EMAIL", pattern="^(EMAIL|SMS|WEB|QR)$")


def _serialize_verdict(
    row: DetectionVerdictModel,
    incident_map: Optional[Dict[str, IncidentModel]] = None,
) -> VerdictOut:
    s_email = row.sender_email or ""
    s_domain = s_email.rsplit("@", 1)[-1].lower() if "@" in s_email else ""
    linked_inc = (incident_map or {}).get(row.id)
    return VerdictOut(
        id=row.id,
        correlation_id=row.correlation_id,
        sender_email=s_email,
        sender_domain=s_domain,
        recipient_email=row.recipient_email,
        subject=row.subject,
        channel=row.channel,
        risk_score=row.risk_score,
        verdict=row.verdict,
        action_taken=row.action_taken,
        summary=row.summary,
        latency_ms=row.latency_ms,
        analyst_label=row.analyst_label,
        headers_meta=dict(row.headers_meta or {}),
        signals_meta=list(row.signals_meta or []),
        incident_id=linked_inc.id if linked_inc else None,
        incident_code=linked_inc.incident_code if linked_inc else None,
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


@router.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    dependencies=[Depends(limiter_dependency(gateway_limiter))],
)
async def analyze_email_endpoint(
    payload: EmailAnalysisRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_gateway_or_permission(DETECTION_ANALYZE)),
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    """Inline email inspection invoked by the corporate MTA gateway, n8n SOAR, or SOC analysts."""
    res = await analyze_email_command(
        request=payload,
        db=db,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
        enable_enrichment=False,
    )
    await db.commit()
    return res


@router.post(
    "/analyze-eml",
    response_model=EmailAnalysisResponse,
    openapi_extra={
        "requestBody": {
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "properties": {"file": {"type": "string", "format": "binary"}},
                    }
                },
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"raw_eml": {"type": "string"}},
                        "required": ["raw_eml"],
                    }
                },
            }
        }
    },
)
async def analyze_eml_endpoint(
    request: Request,
    actor: ActorPrincipal = Depends(allow_gateway_or_permission(DETECTION_ANALYZE)),
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    """Parse an RFC 822 `.eml` file upload or JSON `{"raw_eml": "..."}` and run inline detection."""
    ctype = (request.headers.get("content-type") or "").lower()
    raw_bytes = b""

    if "multipart/form-data" in ctype:
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            for item in form.values():
                if hasattr(item, "read"):
                    upload = item
                    break
        if upload is None or not hasattr(upload, "read"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing '.eml' file in multipart form upload",
            )
        raw_bytes = await upload.read()  # type: ignore[misc]
    else:
        try:
            body_json = await request.json()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expected multipart/form-data upload or JSON {'raw_eml': '...'}",
            ) from exc
        raw_str = str((body_json or {}).get("raw_eml") or "")
        raw_bytes = raw_str.encode("utf-8")

    try:
        parsed_req = parse_eml_bytes(raw_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    res = await analyze_email_command(
        request=parsed_req,
        db=db,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
        enable_enrichment=False,
        audit_action="DETECTION_ANALYZE_EML",
    )
    await db.commit()
    return res


@router.post("/analyze-url", response_model=EmailAnalysisResponse)
async def analyze_url_endpoint(
    payload: UrlAnalysisRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_gateway_or_permission(DETECTION_ANALYZE)),
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    """Inspect a standalone URL, SMS smishing link, or decoded QR quishing target."""
    norm = normalize_url(payload.url) or payload.url.strip()
    if "://" not in norm:
        norm = f"http://{norm}"
    host = domain_of(norm) or (urlsplit(norm).hostname or "external.invalid").lower()

    synthetic_req = EmailAnalysisRequest(
        sender=payload.sender or f"scanner@{host}",
        recipient=payload.recipient or actor.email,
        subject=f"[{payload.channel}] URL Target Inspection: {norm[:120]}",
        body_text=f"{payload.message_text or ''}\n{norm}".strip(),
        headers={"x-inspection-mode": "standalone-url"},
        channel=payload.channel,
        reported_by_user=False,
    )
    res = await analyze_email_command(
        request=synthetic_req,
        db=db,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
        enable_enrichment=payload.enrich and settings.ENRICHMENT_ENABLED,
        audit_action="DETECTION_ANALYZE_URL",
    )
    await db.commit()
    return res


@router.post("/report-phishing", response_model=EmailAnalysisResponse)
async def report_phishing_endpoint(
    payload: EmployeePhishingReportRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_gateway_or_authenticated),
    db: AsyncSession = Depends(get_db),
) -> EmailAnalysisResponse:
    """Employee 'Reportar phishing' button intake; auto-triages incidents when risk_score >= 35."""
    sender = (payload.sender_email or payload.sender or "unknown@external.invalid").strip()
    reporter = (payload.reported_by_email or payload.recipient or actor.email).strip()

    analysis_req = EmailAnalysisRequest(
        sender=sender,
        recipient=reporter,
        subject=payload.subject,
        body_text=payload.body_text,
        body_html=payload.body_html,
        headers=payload.headers,
        channel=payload.channel,
        reported_by_user=True,
    )
    res = await analyze_email_command(
        request=analysis_req,
        db=db,
        actor_email=reporter,
        client_ip=get_client_ip(request),
        enable_enrichment=False,
        audit_action="EMPLOYEE_PHISHING_REPORT",
    )
    await db.commit()
    return res


@router.get("/verdicts", response_model=VerdictPage)
async def list_verdicts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    verdict: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    analyst_label: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    date_from: Optional[date] = Query(default=None),
    date_to: Optional[date] = Query(default=None),
    _: UserModel = Depends(require_permission(DETECTION_READ)),
    db: AsyncSession = Depends(get_db),
) -> VerdictPage:
    """Paginated list of persisted detection verdicts with multi-criteria filtering."""
    repo = VerdictRepository(db)
    rows, total = await repo.list_paginated(
        page=page,
        page_size=page_size,
        verdict=verdict,
        channel=channel,
        analyst_label=analyst_label,
        q=q,
        date_from=date_from,
        date_to=date_to,
    )
    verdict_ids = [r.id for r in rows]
    inc_map: Dict[str, IncidentModel] = {}
    if verdict_ids:
        inc_rows = (
            await db.scalars(select(IncidentModel).where(IncidentModel.verdict_id.in_(verdict_ids)))
        ).all()
        inc_map = {inc.verdict_id: inc for inc in inc_rows}

    return VerdictPage(
        items=[_serialize_verdict(r, inc_map) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/verdicts/{verdict_id}", response_model=VerdictOut)
async def get_verdict_detail(
    verdict_id: str,
    _: UserModel = Depends(require_permission(DETECTION_READ)),
    db: AsyncSession = Depends(get_db),
) -> VerdictOut:
    """Return full forensic detail for a single detection verdict."""
    row = await VerdictRepository(db).get_by_id(verdict_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verdict not found")

    inc = await db.scalar(select(IncidentModel).where(IncidentModel.verdict_id == row.id))
    return _serialize_verdict(row, {row.id: inc} if inc else {})


@router.patch("/verdicts/{verdict_id}/label", response_model=VerdictOut)
async def label_verdict(
    verdict_id: str,
    payload: LabelRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission(INCIDENTS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> VerdictOut:
    """Set analyst feedback label (`TRUE_POSITIVE` | `FALSE_POSITIVE` | `UNREVIEWED`)."""
    repo = VerdictRepository(db)
    updated = await repo.set_analyst_label(
        verdict_id=verdict_id,
        label=payload.label,
        labeled_by_id=current_user.email,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verdict not found")

    await AuditRepository(db).append(
        user_email=current_user.email,
        action="VERDICT_LABELED",
        resource=f"verdict:{updated.correlation_id}",
        payload={"verdict_id": updated.id, "analyst_label": updated.analyst_label},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    inc = await db.scalar(select(IncidentModel).where(IncidentModel.verdict_id == updated.id))
    return _serialize_verdict(updated, {updated.id: inc} if inc else {})
