"""Executive banking CISO/SOC incident summarizer mapped to PCI-DSS v4.0 and ISO 27001:2022."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda

from app.adapters.llm.factory import get_chat_model
from app.adapters.llm.prompts.email_classification import sanitize_xml_delimiters
from app.adapters.llm.prompts.incident_summary import INCIDENT_SUMMARY_PROMPT
from app.core.metrics import LLM_CALLS


def _deterministic_incident_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    code = incident.get("incident_code") or incident.get("id") or "UNKNOWN"
    severity = incident.get("severity") or "HIGH"
    status = incident.get("status") or "OPEN"
    sender = incident.get("sender_email") or "unknown-sender"
    subject = incident.get("subject") or "(no subject)"
    risk_score = incident.get("risk_score")
    sla_overdue = bool(incident.get("sla_overdue"))
    is_escalated = bool(incident.get("is_escalated"))
    events = incident.get("events") or []
    iocs = incident.get("iocs") or []
    signals = incident.get("signals") or []

    sig_names = ", ".join(str(s.get("name")) for s in signals[:5] if isinstance(s, dict)) or "MANUAL_TRIAGE"
    ioc_vals = ", ".join(str(i.get("ioc_value")) for i in iocs[:5] if isinstance(i, dict)) or "none linked"
    sla_posture = (
        "SLA BREACHED / ESCALATED"
        if (sla_overdue or is_escalated)
        else f"Within SLA window (deadline: {incident.get('sla_deadline') or 'N/A'})"
    )

    summary = (
        f"Executive CISO Briefing — Incident {code} [{severity} | Status: {status}]: "
        f"Detected phishing vector from '{sender}' with subject '{subject[:120]}' "
        f"(Risk Score: {risk_score if risk_score is not None else 'N/A'}/100; Signals: {sig_names}). "
        f"Timeline contains {len(events)} immutable audit event(s); SLA posture: {sla_posture}. "
        f"Linked IOCs ({len(iocs)}): {ioc_vals}."
    )

    recommended_actions: List[str] = [
        "Enforce perimeter block on sender domain and extracted URLs in active IOC BLACKLIST and Secure Email Gateway.",
        "Purge any residual copies across recipient mailboxes and verify zero credential/OTP submission in IdP logs.",
        "If recipient interacted with links or QR codes, revoke active SSO/MFA sessions and rotate credentials immediately.",
        "Complete forensic timeline notes and transition incident through CONTAINED -> CLOSED with verified resolution.",
    ]

    compliance_controls: List[str] = [
        "PCI-DSS v4.0 Req 5.4.1 (Automated anti-phishing protection & quarantine)",
        "PCI-DSS v4.0 Req 10.2 / 10.3 (Immutable hash-chained audit trail)",
        "PCI-DSS v4.0 Req 12.10 (Security incident response & 24/7 SLA escalation)",
        "ISO/IEC 27001:2022 A.5.24 - A.5.26 (Incident management lifecycle & response)",
        "ISO/IEC 27001:2022 A.8.7 & A.8.15 (Malware/phishing defense & protected logging)",
    ]

    return {
        "summary": summary,
        "recommended_actions": recommended_actions,
        "compliance_controls": compliance_controls,
        "engine": "langchain-deterministic",
    }


async def summarize_incident(incident_detail: Dict[str, Any]) -> Dict[str, Any]:
    """Generate an executive CISO/SOC briefing for an incident using LangChain Runnable + fallback."""
    safe_payload = {
        k: v
        for k, v in incident_detail.items()
        if k not in {"incident_model", "verdict_model"}
    }
    baseline = _deterministic_incident_summary(safe_payload)

    model, engine_name = get_chat_model(temperature=0.0)
    if model is not None:
        try:
            chain = INCIDENT_SUMMARY_PROMPT | model | StrOutputParser()
            raw_out = await chain.ainvoke(
                {
                    "incident_json": sanitize_xml_delimiters(
                        json.dumps(safe_payload, default=str, ensure_ascii=False)
                    )[:4000]
                }
            )
            match = re.search(r"\{.*\}", raw_out or "", flags=re.DOTALL)
            if match:
                parsed = json.loads(match.group(0))
                if isinstance(parsed, dict) and parsed.get("summary"):
                    LLM_CALLS.labels(engine=engine_name).inc()
                    return {
                        "summary": str(parsed["summary"])[:1500],
                        "recommended_actions": list(
                            parsed.get("recommended_actions") or baseline["recommended_actions"]
                        ),
                        "compliance_controls": list(
                            parsed.get("compliance_controls") or baseline["compliance_controls"]
                        ),
                        "engine": engine_name,
                    }
        except Exception:
            pass

    LLM_CALLS.labels(engine="langchain-deterministic").inc()
    return baseline


incident_summarizer_runnable = RunnableLambda(summarize_incident)
