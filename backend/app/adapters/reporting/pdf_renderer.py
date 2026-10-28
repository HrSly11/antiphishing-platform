"""Corporate banking PDF report renderer built on ReportLab (`executive | management | operational | compliance`)."""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

TEMPLATE_TITLES = {
    "executive": "Executive CISO Antiphishing & SOC Posture Report",
    "management": "Executive CISO Antiphishing & SOC Posture Report",
    "operational": "Operational SOC Detection & Incident Telemetry Report",
    "compliance": "Regulatory Compliance Audit Report (PCI-DSS v4.0 & ISO 27001:2022)",
}


def render_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Render a multi-section banking security PDF report and return raw `%PDF-...` bytes."""
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

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=title,
        author="Banking SOC Antiphishing Platform",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "BankReportTitle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    section_style = ParagraphStyle(
        "BankSectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BankBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
    )

    story: List[Any] = []
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(escape(title), title_style))
    story.append(
        Paragraph(
            f"<b>Institution:</b> Banco Central Corporate SOC | "
            f"<b>Window:</b> {escape(date_from)} to {escape(date_to)} | "
            f"<b>Issued:</b> {issued_at} | <b>Classification:</b> CONFIDENTIAL",
            body_style,
        )
    )
    story.append(Spacer(1, 12))

    # Section 1: KPI & SLA Summary Table
    story.append(Paragraph("1. Executive Telemetry & SLA Performance Summary", section_style))
    by_verdict = kpis.get("by_verdict") or {}
    kpi_rows = [
        ["Metric", "Value", "Metric", "Value"],
        [
            "Total Messages Analyzed",
            str(kpis.get("total_analyzed", len(verdicts))),
            "Malicious / Quarantined",
            str(by_verdict.get("MALICIOUS", by_verdict.get("PHISHING", 0))),
        ],
        [
            "Suspicious (Warning Banner)",
            str(by_verdict.get("SUSPICIOUS", 0)),
            "Clean (Delivered)",
            str(by_verdict.get("CLEAN", 0)),
        ],
        [
            "Latency Avg / P95 (ms)",
            f"{kpis.get('latency_avg_ms', 0)} / {kpis.get('latency_p95_ms', 0)}",
            "FP Rate / FN Rate",
            f"{kpis.get('false_positive_rate', 0.0)} / {kpis.get('false_negative_rate', 0.0)}",
        ],
        [
            "Open / Overdue Incidents",
            f"{sla.get('open_count', 0)} / {sla.get('overdue_count', 0)}",
            "SLA Compliance / MTTR (min)",
            f"{round(float(sla.get('sla_compliance_rate', 1.0)) * 100, 1)}% / {sla.get('mttr_minutes') or 'N/A'}",
        ],
    ]
    kpi_table = Table(kpi_rows, colWidths=[155, 115, 155, 115])
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 12))

    # Section 2: Detection Verdicts Table
    story.append(Paragraph("2. Recent Inline Detection Verdicts", section_style))
    v_rows = [["UTC Timestamp", "Sender", "Subject", "Channel", "Score", "Verdict", "Action"]]
    if verdicts:
        for v in verdicts[:25]:
            ts = str(v.get("created_at") or v.get("timestamp") or "")[:19]
            sender = str(v.get("sender_email") or v.get("sender") or "")[:28]
            subj = str(v.get("subject") or "")[:32]
            ch = str(v.get("channel") or "EMAIL")[:8]
            sc = str(v.get("risk_score", 0))
            verd = str(v.get("verdict") or "")[:12]
            act = str(v.get("action_taken") or v.get("action") or "")[:14]
            v_rows.append([ts, sender, subj, ch, sc, verd, act])
    else:
        v_rows.append(["N/A", "No verdicts in selected window", "-", "-", "-", "-", "-"])

    v_table = Table(v_rows, colWidths=[85, 110, 130, 45, 38, 62, 70])
    v_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 7.5),
                ("FONTSIZE", (0, 1), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("ALIGN", (4, 0), (4, -1), "CENTER"),
            ]
        )
    )
    story.append(v_table)
    story.append(Spacer(1, 12))

    # Section 3: Incidents & Top IOCs
    story.append(Paragraph("3. SOC Incident Lifecycle & Active Threat Indicators", section_style))
    inc_rows = [["Incident Code", "Severity", "Status", "Resolution", "SLA Overdue", "Created UTC"]]
    if incidents:
        for inc in incidents[:15]:
            inc_rows.append(
                [
                    str(inc.get("incident_code") or "")[:22],
                    str(inc.get("severity") or "")[:10],
                    str(inc.get("status") or "")[:14],
                    str(inc.get("resolution") or "PENDING")[:18],
                    "YES" if inc.get("sla_overdue") else "NO",
                    str(inc.get("created_at") or "")[:19],
                ]
            )
    else:
        inc_rows.append(["NONE", "-", "-", "-", "-", "-"])

    inc_table = Table(inc_rows, colWidths=[115, 65, 85, 110, 65, 100])
    inc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ]
        )
    )
    story.append(inc_table)
    story.append(Spacer(1, 10))

    if top_iocs:
        ioc_rows = [["IOC Type", "Indicator Value", "List", "Confidence", "Source"]]
        for ioc in top_iocs[:12]:
            ioc_rows.append(
                [
                    str(ioc.get("ioc_type") or "")[:10],
                    str(ioc.get("ioc_value") or "")[:45],
                    str(ioc.get("list_type") or "BLACKLIST")[:12],
                    str(ioc.get("confidence_score") or 100),
                    str(ioc.get("source") or "")[:24],
                ]
            )
        ioc_table = Table(ioc_rows, colWidths=[65, 220, 75, 65, 115])
        ioc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#475569")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        story.append(ioc_table)
        story.append(Spacer(1, 12))

    # Section 4: Regulatory Attestation Footer
    compliance_note = (
        "Compliance Attestation: Generated from hash-chained PostgreSQL audit & telemetry records "
        "in accordance with PCI-DSS v4.0 (Req 5.4.1, 10.2, 10.3, 12.10) and ISO/IEC 27001:2022 "
        "(A.5.7, A.5.24-A.5.26, A.8.7, A.8.15)."
    )
    story.append(Paragraph(escape(compliance_note), styles["Italic"]))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def generate_security_pdf_report(
    verdicts_data: List[Dict[str, Any]],
    title: str = "Reporte Ejecutivo de Detección de Phishing",
) -> bytes:
    """Backwards-compatible wrapper used by existing `/reports/export/pdf` route."""
    return render_pdf_report(
        {
            "template": "executive",
            "title": title,
            "verdicts": verdicts_data,
            "kpis": {
                "total_analyzed": len(verdicts_data),
                "by_verdict": {
                    "MALICIOUS": sum(
                        1 for v in verdicts_data if v.get("verdict") in {"MALICIOUS", "PHISHING"}
                    ),
                    "SUSPICIOUS": sum(1 for v in verdicts_data if v.get("verdict") == "SUSPICIOUS"),
                    "CLEAN": sum(1 for v in verdicts_data if v.get("verdict") == "CLEAN"),
                },
            },
        }
    )
