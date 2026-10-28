"""Slack Block Kit and Microsoft Teams Adaptive Card SOC alert dispatchers."""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


def build_slack_alert_payload(
    title: str,
    severity: str,
    summary: str,
    incident_code: Optional[str] = None,
) -> Dict[str, Any]:
    header_txt = f"[{severity}] {title}" + (f" ({incident_code})" if incident_code else "")
    return {
        "text": header_txt,
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_txt[:150]},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary[:2800]},
            },
        ],
    }


def build_teams_alert_payload(
    title: str,
    severity: str,
    summary: str,
    incident_code: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": f"[{severity}] {title}",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Incident", "value": incident_code or "N/A"},
                                {"title": "Severity", "value": severity},
                            ],
                        },
                        {"type": "TextBlock", "wrap": True, "text": summary[:2500]},
                    ],
                },
            }
        ],
    }


async def send_chatops_alert(
    webhook_url: Optional[str],
    title: str,
    severity: str,
    summary: str,
    incident_code: Optional[str] = None,
    platform: str = "slack",
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Send SOC alert to Slack or Microsoft Teams incoming webhook with offline fallback."""
    body = (
        build_teams_alert_payload(title, severity, summary, incident_code)
        if platform.lower() == "teams"
        else build_slack_alert_payload(title, severity, summary, incident_code)
    )
    if not webhook_url:
        logger.info("ChatOps (%s) webhook not configured; alert logged: %s", platform, title)
        return {"delivered": True, "mode": "log_fallback", "platform": platform, "payload": body}

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(webhook_url, json=body)
            ok = 200 <= resp.status_code < 300
            return {
                "delivered": ok,
                "mode": "webhook",
                "platform": platform,
                "status_code": resp.status_code,
            }
    except Exception as exc:
        return {
            "delivered": False,
            "mode": "webhook_error",
            "platform": platform,
            "error": f"{type(exc).__name__}: {exc}",
        }
