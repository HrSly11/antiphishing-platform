"""LangChain Runnable email phishing intent classifier with prompt-injection resistance."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel, Field

from app.adapters.llm.factory import get_chat_model
from app.adapters.llm.prompts.email_classification import (
    EMAIL_CLASSIFICATION_PROMPT,
    detect_prompt_injection,
    sanitize_xml_delimiters,
)
from app.core.metrics import LLM_CALLS

VALID_LABELS = {
    "credential_harvesting",
    "bec_wire_fraud",
    "malware_delivery",
    "qr_quishing",
    "benign",
}

_QR_PATTERNS = re.compile(
    r"(escanee\s+el\s+c[oó]digo\s+qr|scan\s+(the\s+)?qr|qr\s+code|autenticaci[oó]n\s+qr|data:image/(?:png|svg\+xml);base64)",
    re.IGNORECASE,
)
_BEC_PATTERNS = re.compile(
    r"(transferencia\s+urgente|wire\s+transfer|cambio\s+de\s+cuenta\s+bancaria|swift|iban|proveedor\s+urgente|confidencial\s+gerencia|aprobaci[oó]n\s+de\s+pago|ceo|tesorer[ií]a)",
    re.IGNORECASE,
)
_MALWARE_PATTERNS = re.compile(
    r"(\.(?:exe|scr|iso|vbs|hta|js|xlsm|docm)\b|habilite\s+macros|enable\s+macros|enable\s+content|factura_adjunta\.iso|comprobante\.zip)",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERNS = re.compile(
    r"(token\s+digital|clave\s+din[aá]mica|coordenadas|ingrese\s+sus?\s+credenciales|verify\s+your\s+account|cuenta\s+suspendida|bloqueo\s+preventivo|actualizar\s+clave|cvv|contrase[ñn]a\s+expir)",
    re.IGNORECASE,
)


class EmailClassificationResult(BaseModel):
    is_phishing: bool = Field(..., description="True when phishing or adversarial intent is detected")
    confidence: float = Field(..., description="Confidence score in [0.0, 1.0]")
    primary_intent: str = Field(..., description="Intent category")
    urgency_level: str = Field(..., description="LOW, MEDIUM, or CRITICAL")
    explanation: str = Field(..., description="Technical explanation of classification")


def _deterministic_classify(
    subject: str,
    body: str,
    sender: str,
    headers: Dict[str, Any],
    injection_detected: bool,
    injection_matches: list[str],
) -> Dict[str, Any]:
    combined = f"{subject}\n{body}"

    if _QR_PATTERNS.search(combined) or str(headers.get("channel") or "").upper() == "QR":
        label = "qr_quishing"
        confidence = 0.91
        risk_delta = 35
        explanation = "Detected QR-based authentication lure (quishing) attempting to bypass inline URL inspection."
    elif _MALWARE_PATTERNS.search(combined):
        label = "malware_delivery"
        confidence = 0.93
        risk_delta = 40
        explanation = "Detected macro/executable payload lure indicative of banking malware delivery."
    elif _BEC_PATTERNS.search(combined):
        label = "bec_wire_fraud"
        confidence = 0.88
        risk_delta = 32
        explanation = "Detected Business Email Compromise (BEC) / unauthorized treasury wire instruction indicators."
    elif _CREDENTIAL_PATTERNS.search(combined):
        label = "credential_harvesting"
        confidence = 0.92
        risk_delta = 35
        explanation = "Detected coercive banking credential, OTP, or dynamic token harvesting lure."
    elif injection_detected:
        label = "credential_harvesting"
        confidence = 0.95
        risk_delta = 50
        explanation = (
            "Adversarial prompt-injection attempt detected inside untrusted email content "
            f"({', '.join(injection_matches)}); override ignored and message flagged."
        )
    else:
        label = "benign"
        confidence = 0.90
        risk_delta = 0
        explanation = "No social-engineering coercion, credential harvesting lure, or prompt injection detected."

    if injection_detected and label != "benign":
        risk_delta = max(risk_delta, 50)
        explanation = (
            f"{explanation} Adversarial prompt-injection payload ({', '.join(injection_matches)}) "
            "was isolated and neutralized."
        )

    return {
        "label": label,
        "confidence": round(confidence, 3),
        "risk_delta": int(risk_delta),
        "explanation": explanation,
        "injection_detected": injection_detected,
        "injection_matches": injection_matches,
        "engine": "langchain-deterministic",
    }


def _extract_json_dict(raw_text: str) -> Optional[Dict[str, Any]]:
    match = re.search(r"\{.*\}", raw_text or "", flags=re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


async def _run_classification_pipeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    sender = str(payload.get("sender") or "")
    subject = str(payload.get("subject") or "")
    body = str(payload.get("body") or "")
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}

    untrusted_blob = f"{sender}\n{subject}\n{body}"
    injection_detected, injection_matches = detect_prompt_injection(untrusted_blob)

    baseline = _deterministic_classify(
        subject=subject,
        body=body,
        sender=sender,
        headers=headers,
        injection_detected=injection_detected,
        injection_matches=injection_matches,
    )

    model, engine_name = get_chat_model(temperature=0.0)
    if model is None:
        LLM_CALLS.labels(engine="langchain-deterministic").inc()
        return baseline

    try:
        chain: Runnable[Dict[str, Any], str] = (
            EMAIL_CLASSIFICATION_PROMPT | model | StrOutputParser()
        )
        raw_out = await chain.ainvoke(
            {
                "sender": sanitize_xml_delimiters(sender)[:320],
                "subject": sanitize_xml_delimiters(subject)[:500],
                "headers_summary": sanitize_xml_delimiters(json.dumps(headers))[:1000],
                "body": sanitize_xml_delimiters(body)[:4000],
            }
        )
        parsed = _extract_json_dict(raw_out)
        if parsed and str(parsed.get("label") or "") in VALID_LABELS:
            llm_label = str(parsed["label"])
            llm_conf = max(0.0, min(1.0, float(parsed.get("confidence", 0.85))))
            llm_delta = max(0, min(60, int(parsed.get("risk_delta", baseline["risk_delta"]))))
            llm_exp = str(parsed.get("explanation") or baseline["explanation"])[:500]

            # Never allow prompt injection to coerce a benign verdict from the LLM.
            if injection_detected and llm_label == "benign":
                llm_label = baseline["label"]
                llm_delta = max(llm_delta, 50)
                llm_exp = baseline["explanation"]

            LLM_CALLS.labels(engine=engine_name).inc()
            return {
                "label": llm_label,
                "confidence": round(llm_conf, 3),
                "risk_delta": llm_delta,
                "explanation": llm_exp,
                "injection_detected": injection_detected,
                "injection_matches": injection_matches,
                "engine": engine_name,
            }
    except Exception:
        pass

    LLM_CALLS.labels(engine="langchain-deterministic").inc()
    return baseline


email_classifier_runnable: Runnable[Dict[str, Any], Dict[str, Any]] = RunnableLambda(
    _run_classification_pipeline
)


async def classify_email(
    subject: str,
    body: str,
    sender: str = "",
    headers: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute the LangChain Runnable email classification pipeline."""
    return await email_classifier_runnable.ainvoke(
        {
            "sender": sender,
            "subject": subject,
            "body": body,
            "headers": headers or {},
        }
    )


def analyze_email_intent(subject: str, body: str, sender: str = "") -> EmailClassificationResult:
    """Synchronous compatibility wrapper used by legacy callers."""
    inj, matches = detect_prompt_injection(f"{sender}\n{subject}\n{body}")
    res = _deterministic_classify(subject, body, sender, {}, inj, matches)
    is_phish = res["label"] != "benign"
    return EmailClassificationResult(
        is_phishing=is_phish,
        confidence=res["confidence"],
        primary_intent=res["label"].upper(),
        urgency_level="CRITICAL" if res["risk_delta"] >= 35 else ("MEDIUM" if is_phish else "LOW"),
        explanation=res["explanation"],
    )
