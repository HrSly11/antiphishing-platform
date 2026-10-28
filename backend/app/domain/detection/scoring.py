from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.domain.shared.value_objects import RiskScore


@dataclass
class DetectionSignal:
    name: str
    weight: int
    score: float  # 0.0 to 1.0
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskEvaluation:
    risk_score: int  # 0 to 100
    verdict: str     # CLEAN (0-34), SUSPICIOUS (35-69), MALICIOUS (70-100)
    action: str      # DELIVER, TAG_AND_BANNER, QUARANTINE
    signals: List[DetectionSignal]
    summary: str


def compute_risk_score(
    signals: List[DetectionSignal],
    hard_blacklist: bool = False,
    hard_whitelist: bool = False,
) -> RiskEvaluation:
    """Consolidate weighted detection signals into a RiskScore, Verdict, and Gateway Action."""
    if hard_whitelist:
        return RiskEvaluation(
            risk_score=0,
            verdict="CLEAN",
            action="DELIVER",
            signals=signals,
            summary="Verified institutional sender and URLs matched active WHITELIST with valid authentication.",
        )

    raw_score = sum(float(s.weight) * float(s.score) for s in signals)
    final_val = max(0, min(100, int(round(raw_score))))

    if hard_blacklist:
        final_val = max(85, final_val)

    rs = RiskScore(final_val)
    verdict = rs.verdict.value
    action = rs.action.value

    if hard_blacklist:
        summary = "Confirmed threat intelligence match against active IOC BLACKLIST or verified phishing dataset."
    elif verdict == "CLEAN":
        summary = "No significant phishing, spoofing, or deceptive link indicators detected. Cleared for delivery."
    elif verdict == "SUSPICIOUS":
        summary = "Moderate phishing risk indicators detected. Delivered with prominent employee warning banner."
    else:
        summary = "Critical phishing or brand impersonation threat detected. Message quarantined and SOC incident triggered."

    return RiskEvaluation(
        risk_score=final_val,
        verdict=verdict,
        action=action,
        signals=signals,
        summary=summary,
    )
