from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EmailAttachmentDto(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    size_bytes: Optional[int] = Field(default=0, ge=0, le=2_000_000_000)
    content_type: Optional[str] = Field(default=None, max_length=150)


class EmailAnalysisRequest(BaseModel):
    """Email or multi-channel message as forwarded by the corporate mail gateway (MTA) or SOC."""

    sender: str = Field(..., min_length=3, max_length=320)
    recipient: str = Field(default="soc@bancocentral.com", min_length=3, max_length=320)
    subject: str = Field(default="(no subject)", max_length=998)
    body_text: str = Field(default="", max_length=200_000)
    body_html: Optional[str] = Field(default=None, max_length=500_000)
    headers: Dict[str, str] = Field(default_factory=dict)
    attachments: List[EmailAttachmentDto] = Field(default_factory=list, max_length=50)
    channel: str = Field(default="EMAIL", pattern="^(EMAIL|SMS|WEB|QR)$")
    reported_by_user: bool = False  # true when an employee used the "Report phishing" button

    @field_validator("headers")
    @classmethod
    def _limit_headers(cls, value: Dict[str, str]) -> Dict[str, str]:
        if len(value) > 100:
            raise ValueError("too many headers (max 100)")
        return {str(k).lower()[:100]: str(v)[:2000] for k, v in value.items()}

    @field_validator("sender", "recipient")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class SignalDto(BaseModel):
    name: str
    weight: int
    score: float
    reason: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EmailAnalysisResponse(BaseModel):
    id: str = ""
    correlation_id: str
    timestamp: str
    created_at: str = ""
    channel: str = "EMAIL"
    sender: str
    sender_email: str = ""
    sender_domain: str = ""
    recipient: str
    subject: str
    risk_score: int
    severity: str = "LOW"
    verdict: str
    action: str
    summary: str
    incident_triggered: bool
    incident_id: Optional[str] = None
    incident_code: Optional[str] = None
    latency_ms: int = 0
    urls: List[str] = Field(default_factory=list)
    attachments: List[EmailAttachmentDto] = Field(default_factory=list)
    llm_classification: Dict[str, Any] = Field(default_factory=dict)
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    signals: List[SignalDto]


class VerdictOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    correlation_id: str
    sender_email: str
    sender_domain: str = ""
    recipient_email: str
    subject: str
    channel: str
    risk_score: int
    verdict: str
    action_taken: str
    summary: str
    latency_ms: int
    analyst_label: str
    headers_meta: Dict[str, Any] = Field(default_factory=dict)
    signals_meta: List[dict]
    incident_id: Optional[str] = None
    incident_code: Optional[str] = None
    created_at: str


class VerdictPage(BaseModel):
    items: List[VerdictOut]
    total: int
    page: int
    page_size: int


class LabelRequest(BaseModel):
    label: str = Field(..., pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|UNREVIEWED)$")
