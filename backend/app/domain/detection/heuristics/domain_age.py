"""Domain age heuristic. Newly registered domains are a classic phishing indicator."""
from typing import Optional, Tuple


def score_domain_age(age_days: Optional[int]) -> Tuple[float, str]:
    """Return (score 0..1, reason). Unknown age yields a neutral score."""
    if age_days is None:
        return 0.0, ""
    if age_days < 7:
        return 1.0, f"Domain registered only {age_days} day(s) ago"
    if age_days < 30:
        return 0.7, f"Domain registered {age_days} days ago (under 30 days)"
    if age_days < 90:
        return 0.3, f"Domain registered {age_days} days ago (under 90 days)"
    return 0.0, ""
