"""Async SMTP email notification adapter with deterministic structured log fallback."""
from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)


def _send_smtp_sync(
    recipients: List[str],
    subject: str,
    body_text: str,
    attachments: Optional[List[Tuple[str, bytes, str]]] = None,
) -> None:
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body_text)

    for filename, raw_bytes, mime_type in attachments or []:
        maintype, _, subtype = (mime_type or "application/octet-stream").partition("/")
        msg.add_attachment(
            raw_bytes,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename,
        )

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=8.0) as server:
        if settings.SMTP_STARTTLS:
            server.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.send_message(msg)


async def send_email_notification(
    recipients: List[str],
    subject: str,
    body_text: str,
    attachments: Optional[List[Tuple[str, bytes, str]]] = None,
) -> Dict[str, Any]:
    """Send an email via SMTP when configured, or record via structured log fallback."""
    clean_recipients = [r.strip() for r in recipients if r and r.strip()]
    if not clean_recipients:
        return {"delivered": False, "mode": "skipped", "error": "No recipients provided"}

    if not settings.SMTP_HOST:
        logger.info(
            "SMTP_HOST not configured; logged outbound notification to %s (subject=%s, attachments=%d)",
            clean_recipients,
            subject,
            len(attachments or []),
        )
        return {
            "delivered": True,
            "mode": "log_fallback",
            "recipients": clean_recipients,
            "subject": subject,
            "attachment_count": len(attachments or []),
        }

    try:
        await asyncio.to_thread(_send_smtp_sync, clean_recipients, subject, body_text, attachments)
        return {
            "delivered": True,
            "mode": "smtp",
            "recipients": clean_recipients,
            "subject": subject,
            "attachment_count": len(attachments or []),
        }
    except Exception as exc:
        logger.warning("SMTP delivery failed (%s); falling back to structured log.", exc)
        return {
            "delivered": False,
            "mode": "smtp_error",
            "recipients": clean_recipients,
            "subject": subject,
            "error": f"{type(exc).__name__}: {exc}",
        }
