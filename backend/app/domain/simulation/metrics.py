"""Awareness campaign KPI and compromise-risk computation (ISO 27001 A.6.3 / PCI-DSS 12.6)."""
from __future__ import annotations

from typing import Dict, Union


def compute_campaign_metrics(
    total_targets: int,
    sent_count: int,
    opened_count: int,
    clicked_count: int,
    reported_count: int,
) -> Dict[str, Union[float, str]]:
    """Compute open rate, click rate, report rate, and human compromise risk classification."""
    denominator = max(1, sent_count if sent_count > 0 else total_targets)
    open_rate = round(min(1.0, max(0.0, opened_count / denominator)), 4)
    click_rate = round(min(1.0, max(0.0, clicked_count / denominator)), 4)
    report_rate = round(min(1.0, max(0.0, reported_count / denominator)), 4)

    if click_rate >= 0.25 and report_rate < 0.20:
        compromise_risk = "CRITICAL"
    elif click_rate >= 0.15:
        compromise_risk = "HIGH"
    elif click_rate >= 0.07 or (sent_count > 0 and report_rate < 0.15):
        compromise_risk = "MEDIUM"
    else:
        compromise_risk = "LOW"

    return {
        "open_rate": open_rate,
        "click_rate": click_rate,
        "report_rate": report_rate,
        "compromise_risk": compromise_risk,
    }
