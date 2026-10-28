"""Ports (interfaces) the detection domain needs from the outside world."""
from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class EnrichmentResult:
    domain: str
    age_days: Optional[int] = None
    resolves: Optional[bool] = None
    tls_valid: Optional[bool] = None
    tls_age_days: Optional[int] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class IntentResult:
    is_phishing: bool
    confidence: float
    primary_intent: str
    explanation: str
    engine: str  # e.g. "langchain:ollama/llama3" or "heuristic-fallback"


class EnrichmentPort(Protocol):
    async def enrich(self, domain: str) -> EnrichmentResult: ...


class LLMPort(Protocol):
    async def classify_email(self, sender: str, subject: str, body: str) -> IntentResult: ...


class ThreatFeedPort(Protocol):
    async def fetch(self) -> bytes: ...
