from datetime import date
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ReportRequest(BaseModel):
    report_format: str = Field(default="pdf", pattern="^(pdf|docx|xlsx)$")
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    verdict: Optional[str] = Field(default=None, pattern="^(CLEAN|SUSPICIOUS|MALICIOUS)$")
    template: str = Field(default="operational", pattern="^(operational|management|compliance)$")


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=200)
    report_format: str = Field(default="pdf", pattern="^(pdf|docx|xlsx)$")
    frequency: str = Field(..., pattern="^(DAILY|WEEKLY)$")
    recipients: List[str] = Field(..., min_length=1, max_length=20)
    template: str = Field(default="management", pattern="^(operational|management|compliance)$")


class ScheduleOut(BaseModel):
    id: str
    name: str
    report_format: str
    frequency: str
    recipients: List[str]
    template: str
    is_active: bool
    next_run_at: str
    last_run_at: Optional[str] = None
    last_status: Optional[str] = None


class IocCreate(BaseModel):
    ioc_type: str = Field(..., pattern="^(DOMAIN|URL|IP|HASH|EMAIL)$")
    ioc_value: str = Field(..., min_length=3, max_length=500)
    list_type: str = Field(default="BLACKLIST", pattern="^(BLACKLIST|WHITELIST)$")
    confidence_score: int = Field(default=100, ge=0, le=100)
    ttl_days: Optional[int] = Field(default=None, ge=1, le=3650)
    source: str = Field(default="MANUAL", max_length=100)


class IocOut(BaseModel):
    id: str
    ioc_type: str
    ioc_value: str
    list_type: str
    confidence_score: int
    source: str
    is_active: bool
    expires_at: Optional[str] = None
    created_at: str
    similarity: Optional[float] = None


class DatasetVersionOut(BaseModel):
    id: str
    source: str
    source_url: str
    license: str
    sha256: str
    total_records: int
    new_records: int
    duplicate_records: int
    invalid_records: int
    status: str
    triggered_by: str
    created_at: str


class DashboardKpis(BaseModel):
    window_days: int
    total_detections: int
    by_verdict: Dict[str, int]
    by_channel: Dict[str, int]
    open_incidents: int
    overdue_incidents: int
    active_iocs: int
    dataset_samples: int
    latency_avg_ms: Optional[float] = None
    latency_p95_ms: Optional[float] = None
    labeled_count: int
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    mean_time_to_resolve_minutes: Optional[float] = None
    mean_time_to_triage_minutes: Optional[float] = None
    trend: List[dict]
    top_sender_domains: List[dict]
    top_attacker_ips: List[dict]
