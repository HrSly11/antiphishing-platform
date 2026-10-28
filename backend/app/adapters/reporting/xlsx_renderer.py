"""Excel (.xlsx) multi-worksheet telemetry and compliance workbook renderer using `openpyxl`."""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from app.adapters.reporting.pdf_renderer import TEMPLATE_TITLES


def _style_header_row(ws: Any, col_count: int) -> None:
    fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    font = Font(color="FFFFFF", bold=True, size=10)
    for col_idx in range(1, col_count + 1):
        cell = ws.cell(row=1, column=col_idx)
        cell.fill = fill
        cell.font = font
        cell.alignment = Alignment(horizontal="left", vertical="center")


def render_xlsx_report(report_data: Dict[str, Any]) -> bytes:
    """Build a multi-tab `.xlsx` workbook (`Summary`, `Verdicts`, `Incidents`, `IOCs`)."""
    template = str(report_data.get("template") or "operational").lower()
    title = str(
        report_data.get("title")
        or TEMPLATE_TITLES.get(template, TEMPLATE_TITLES["operational"])
    )
    date_from = str(report_data.get("date_from") or "Last 30 Days")
    date_to = str(report_data.get("date_to") or datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    kpis = report_data.get("kpis") or {}
    sla = report_data.get("sla_metrics") or {}
    verdicts: List[Dict[str, Any]] = list(report_data.get("verdicts") or [])
    incidents: List[Dict[str, Any]] = list(report_data.get("incidents") or [])
    top_iocs: List[Dict[str, Any]] = list(report_data.get("top_iocs") or [])

    wb = Workbook()

    # Sheet 1: Summary KPIs & Daily Trend
    ws_summary = wb.active
    ws_summary.title = "Summary_KPIs"
    ws_summary.append(["Metric / Metadata", "Value"])
    _style_header_row(ws_summary, 2)

    by_verdict = kpis.get("by_verdict") or {}
    summary_rows = [
        ("Report Title", title),
        ("Template", template.upper()),
        ("Window From", date_from),
        ("Window To", date_to),
        ("Generated UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Total Analyzed", int(kpis.get("total_analyzed", len(verdicts)))),
        ("Malicious / Quarantined", int(by_verdict.get("MALICIOUS", by_verdict.get("PHISHING", 0)))),
        ("Suspicious (Tagged)", int(by_verdict.get("SUSPICIOUS", 0))),
        ("Clean (Delivered)", int(by_verdict.get("CLEAN", 0))),
        ("Latency Average (ms)", float(kpis.get("latency_avg_ms") or 0.0)),
        ("Latency P95 (ms)", float(kpis.get("latency_p95_ms") or 0.0)),
        ("False Positive Rate", float(kpis.get("false_positive_rate") or 0.0)),
        ("False Negative Rate", float(kpis.get("false_negative_rate") or 0.0)),
        ("Open Incidents", int(sla.get("open_count") or 0)),
        ("Overdue Incidents", int(sla.get("overdue_count") or 0)),
        ("SLA Compliance Rate", float(sla.get("sla_compliance_rate") or 1.0)),
        ("MTTR (minutes)", sla.get("mttr_minutes") if sla.get("mttr_minutes") is not None else "N/A"),
    ]
    for r in summary_rows:
        ws_summary.append(list(r))
    ws_summary.column_dimensions["A"].width = 34
    ws_summary.column_dimensions["B"].width = 48

    # Sheet 2: Verdicts
    ws_verdicts = wb.create_sheet("Verdicts")
    v_headers = [
        "Correlation ID",
        "UTC Timestamp",
        "Channel",
        "Sender Email",
        "Recipient Email",
        "Subject",
        "Risk Score",
        "Verdict",
        "Action Taken",
        "Analyst Label",
        "Latency (ms)",
    ]
    ws_verdicts.append(v_headers)
    _style_header_row(ws_verdicts, len(v_headers))
    for v in verdicts:
        ws_verdicts.append(
            [
                str(v.get("correlation_id") or ""),
                str(v.get("created_at") or v.get("timestamp") or ""),
                str(v.get("channel") or "EMAIL"),
                str(v.get("sender_email") or v.get("sender") or ""),
                str(v.get("recipient_email") or v.get("recipient") or ""),
                str(v.get("subject") or ""),
                int(v.get("risk_score") or 0),
                str(v.get("verdict") or ""),
                str(v.get("action_taken") or v.get("action") or ""),
                str(v.get("analyst_label") or "UNREVIEWED"),
                int(v.get("latency_ms") or 0),
            ]
        )

    # Sheet 3: Incidents
    ws_incidents = wb.create_sheet("Incidents")
    i_headers = [
        "Incident Code",
        "Severity",
        "Status",
        "Resolution",
        "Assigned To",
        "SLA Deadline",
        "SLA Overdue",
        "Escalated",
        "Created UTC",
        "Resolved UTC",
    ]
    ws_incidents.append(i_headers)
    _style_header_row(ws_incidents, len(i_headers))
    for inc in incidents:
        ws_incidents.append(
            [
                str(inc.get("incident_code") or ""),
                str(inc.get("severity") or ""),
                str(inc.get("status") or ""),
                str(inc.get("resolution") or ""),
                str(inc.get("assigned_to") or ""),
                str(inc.get("sla_deadline") or ""),
                bool(inc.get("sla_overdue")),
                bool(inc.get("is_escalated")),
                str(inc.get("created_at") or ""),
                str(inc.get("resolved_at") or ""),
            ]
        )

    # Sheet 4: Top IOCs
    ws_iocs = wb.create_sheet("Top_IOCs")
    ioc_headers = ["IOC Type", "Value", "List Type", "Confidence", "Source", "Created UTC"]
    ws_iocs.append(ioc_headers)
    _style_header_row(ws_iocs, len(ioc_headers))
    for ioc in top_iocs:
        ws_iocs.append(
            [
                str(ioc.get("ioc_type") or ""),
                str(ioc.get("ioc_value") or ""),
                str(ioc.get("list_type") or "BLACKLIST"),
                int(ioc.get("confidence_score") or 100),
                str(ioc.get("source") or ""),
                str(ioc.get("created_at") or ""),
            ]
        )

    buffer = io.BytesIO()
    wb.save(buffer)
    wb.close()
    data = buffer.getvalue()
    buffer.close()
    return data
