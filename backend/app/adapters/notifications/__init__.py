"""Notification adapters: Email (SMTP/log), Slack/Teams ChatOps, and HMAC-signed Webhooks."""
from app.adapters.notifications.email import send_email_notification
from app.adapters.notifications.slack_teams import (
    build_slack_alert_payload,
    build_teams_alert_payload,
    send_chatops_alert,
)
from app.adapters.notifications.webhook import (
    compute_hmac_signature,
    send_signed_webhook,
    verify_hmac_signature,
)

__all__ = [
    "build_slack_alert_payload",
    "build_teams_alert_payload",
    "compute_hmac_signature",
    "send_chatops_alert",
    "send_email_notification",
    "send_signed_webhook",
    "verify_hmac_signature",
]
