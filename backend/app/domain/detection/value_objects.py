"""Shared value objects. Pure Python: no framework imports allowed in the domain layer."""
from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Action(str, Enum):
    DELIVER = "DELIVER"
    TAG_AND_BANNER = "TAG_AND_BANNER"
    QUARANTINE = "QUARANTINE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Channel(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    WEB = "WEB"
    QR = "QR"


@dataclass(frozen=True)
class RiskScore:
    """Risk score bounded to [0, 100] with operational bands: 0-34 CLEAN, 35-69 SUSPICIOUS, 70-100 MALICIOUS."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 100:
            raise ValueError("RiskScore must be between 0 and 100")

    @property
    def verdict(self) -> Verdict:
        if self.value < 35:
            return Verdict.CLEAN
        if self.value < 70:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

    @property
    def action(self) -> Action:
        return {
            Verdict.CLEAN: Action.DELIVER,
            Verdict.SUSPICIOUS: Action.TAG_AND_BANNER,
            Verdict.MALICIOUS: Action.QUARANTINE,
        }[self.verdict]

    @property
    def severity(self) -> Severity:
        if self.value >= 85:
            return Severity.CRITICAL
        if self.value >= 70:
            return Severity.HIGH
        if self.value >= 35:
            return Severity.MEDIUM
        return Severity.LOW
