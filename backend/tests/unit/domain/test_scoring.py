"""Unit tests for RiskScore boundaries and multi-signal score aggregation."""
from __future__ import annotations

import pytest

from app.domain.detection.scoring import DetectionSignal, compute_risk_score
from app.domain.shared.value_objects import Action, RiskScore, Severity, Verdict


@pytest.mark.parametrize(
    ("raw_value", "expected_verdict", "expected_action", "expected_severity"),
    [
        (0, Verdict.CLEAN, Action.DELIVER, Severity.LOW),
        (17, Verdict.CLEAN, Action.DELIVER, Severity.LOW),
        (34, Verdict.CLEAN, Action.DELIVER, Severity.LOW),
        (35, Verdict.SUSPICIOUS, Action.TAG_AND_BANNER, Severity.MEDIUM),
        (52, Verdict.SUSPICIOUS, Action.TAG_AND_BANNER, Severity.MEDIUM),
        (69, Verdict.SUSPICIOUS, Action.TAG_AND_BANNER, Severity.MEDIUM),
        (70, Verdict.MALICIOUS, Action.QUARANTINE, Severity.HIGH),
        (84, Verdict.MALICIOUS, Action.QUARANTINE, Severity.HIGH),
        (85, Verdict.MALICIOUS, Action.QUARANTINE, Severity.CRITICAL),
        (100, Verdict.MALICIOUS, Action.QUARANTINE, Severity.CRITICAL),
    ],
)
def test_risk_score_value_object_boundaries(
    raw_value: int,
    expected_verdict: Verdict,
    expected_action: Action,
    expected_severity: Severity,
) -> None:
    score = RiskScore(raw_value)
    assert score.value == raw_value
    assert score.verdict == expected_verdict
    assert score.action == expected_action
    assert score.severity == expected_severity


@pytest.mark.parametrize("invalid_score", [-10, -1, 101, 250])
def test_risk_score_rejects_out_of_bounds_values(invalid_score: int) -> None:
    with pytest.raises(ValueError, match="between 0 and 100"):
        RiskScore(invalid_score)


def test_compute_risk_score_clean_band() -> None:
    res = compute_risk_score(
        [DetectionSignal(name="MINOR_SIGNAL", weight=20, score=0.5, reason="Low suspicion")]
    )
    assert res.risk_score == 10
    assert res.verdict == "CLEAN"
    assert res.action == "DELIVER"
    assert "Cleared for delivery" in res.summary


def test_compute_risk_score_suspicious_band() -> None:
    signals = [
        DetectionSignal(name="URL_SHORTENER", weight=25, score=1.0, reason="bit.ly shortener"),
        DetectionSignal(name="URGENCY_LURE", weight=25, score=0.75, reason="Urgent tone"),
    ]
    res = compute_risk_score(signals)
    assert 35 <= res.risk_score <= 69
    assert res.verdict == "SUSPICIOUS"
    assert res.action == "TAG_AND_BANNER"


def test_compute_risk_score_malicious_clamped_at_100() -> None:
    signals = [
        DetectionSignal(name="SENDER_HOMOGRAPH", weight=75, score=1.0, reason="Cyrillic domain"),
        DetectionSignal(name="DMARC_FAILURE", weight=40, score=1.0, reason="DMARC reject"),
        DetectionSignal(name="DOUBLE_EXT", weight=65, score=1.0, reason="attachment.pdf.exe"),
    ]
    res = compute_risk_score(signals)
    assert res.risk_score == 100
    assert res.verdict == "MALICIOUS"
    assert res.action == "QUARANTINE"


def test_compute_risk_score_hard_blacklist_and_whitelist_overrides() -> None:
    bl_eval = compute_risk_score([], hard_blacklist=True)
    assert bl_eval.risk_score == 85
    assert bl_eval.verdict == "MALICIOUS"
    assert bl_eval.action == "QUARANTINE"

    noisy_signals = [
        DetectionSignal(name="URGENCY_LURE", weight=25, score=1.0, reason="Urgent payroll notice"),
        DetectionSignal(name="URL_SHORTENER", weight=25, score=1.0, reason="Internal redirect"),
    ]
    wl_eval = compute_risk_score(noisy_signals, hard_whitelist=True)
    assert wl_eval.risk_score == 0
    assert wl_eval.verdict == "CLEAN"
    assert wl_eval.action == "DELIVER"
