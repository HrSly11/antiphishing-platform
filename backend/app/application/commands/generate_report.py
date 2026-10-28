"""GenerateReport command handler: builds telemetry payload and renders PDF, DOCX, or XLSX."""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.notifications.email import send_email_notification
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository
from app.adapters.reporting.docx_renderer import render_docx_report
from app.adapters.reporting.pdf_renderer import render_pdf_report
from app.adapters.reporting.xlsx_renderer import render_xlsx_report

MIME_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


async def generate_report_command(
    db: AsyncSession,
    report_format: str = "pdf",
    template: str = "operational",
    window_days: int = 30,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    verdict: Optional[str] = None,
    channel: Optional[str] = None,
    recipient_email: Optional[str] = None,
    actor_email: str = "system",
    client_ip: str = "",
) -> Tuple[bytes, str, str]:
    """Assemble live PostgreSQL telemetry and render a PDF, DOCX, or XLSX report."""
    fmt = (report_format or "pdf").strip().lower()
    if fmt not in MIME_TYPES:
        raise ValueError(f"Unsupported report format: {report_format}")

    norm_template = (template or "operational").strip().lower()
    if norm_template not in {"executive", "management", "operational", "compliance"}:
        norm_template = "operational"

    v_repo = VerdictRepository(db)
    i_repo = IncidentRepository(db)
    ioc_repo = IocRepository(db)

    effective_days = max(1, min(int(window_days or 30), 365))
    if date_from and date_to and date_to >= date_from:
        effective_days = max(1, (date_to - date_from).days + 1)

    kpis = await v_repo.compute_kpis(window_days=effective_days)
    sla = await i_repo.compute_sla_metrics(window_days=effective_days)
    verdict_models, _ = await v_repo.list_paginated(
        page=1,
        page_size=100,
        verdict=verdict,
        channel=channel,
        date_from=date_from,
        date_to=date_to,
    )
    incident_items, _ = await i_repo.list_paginated(page=1, page_size=50)
    ioc_models, _ = await ioc_repo.list(list_type="BLACKLIST", limit=30, offset=0)

    report_payload: Dict[str, Any] = {
        "template": norm_template,
        "date_from": date_from.isoformat() if date_from else f"Last {effective_days}d",
        "date_to": date_to.isoformat() if date_to else datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "kpis": kpis,
        "sla_metrics": sla,
        "verdicts": [
            {
                "correlation_id": r.correlation_id,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "sender_email": r.sender_email,
                "recipient_email": r.recipient_email,
                "subject": r.subject,
                "channel": r.channel,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "action_taken": r.action_taken,
                "analyst_label": r.analyst_label,
                "latency_ms": r.latency_ms,
            }
            for r in verdict_models
        ],
        "incidents": incident_items,
        "top_iocs": [
            {
                "ioc_type": m.ioc_type,
                "ioc_value": m.ioc_value,
                "list_type": m.list_type,
                "confidence_score": m.confidence_score,
                "source": m.source,
                "created_at": m.created_at.isoformat() if m.created_at else "",
            }
            for m in ioc_models
        ],
    }

    if fmt == "docx":
        raw_bytes = render_docx_report(report_payload)
    elif fmt == "xlsx":
        raw_bytes = render_xlsx_report(report_payload)
    else:
        raw_bytes = render_pdf_report(report_payload)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"antiphishing_{norm_template}_{stamp}.{fmt}"

    delivery_status: Optional[Dict[str, Any]] = None
    if recipient_email and recipient_email.strip():
        recipients = [e.strip() for e in recipient_email.split(",") if e.strip()]
        delivery_status = await send_email_notification(
            recipients=recipients,
            subject=f"BancoCentral SOC Antiphishing Report ({norm_template.upper()} - {fmt.upper()})",
            body_text=(
                f"Attached is the {norm_template} antiphishing security report covering "
                f"{report_payload['date_from']} through {report_payload['date_to']}."
            ),
            attachments=[(filename, raw_bytes, MIME_TYPES[fmt])],
        )

    await AuditRepository(db).append(
        user_email=actor_email,
        action="REPORT_GENERATED",
        resource=f"report:{filename}",
        payload={
            "format": fmt,
            "template": norm_template,
            "window_days": effective_days,
            "bytes": len(raw_bytes),
            "delivery": delivery_status,
        },
        client_ip=client_ip,
    )
    return raw_bytes, MIME_TYPES[fmt], filename
