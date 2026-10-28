from typing import List, Optional

from pydantic import BaseModel, Field


class IncidentOut(BaseModel):
    id: str
    incident_code: str
    severity: str
    status: str
    resolution: Optional[str] = None
    assigned_user_id: Optional[str] = None
    assigned_to: Optional[str] = None
    sla_deadline: Optional[str] = None
    sla_overdue: bool = False
    is_escalated: bool
    created_at: str
    resolved_at: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[int] = None


class IncidentEventOut(BaseModel):
    id: str
    event_type: str
    from_status: Optional[str] = None
    to_status: Optional[str] = None
    actor: str
    note: Optional[str] = None
    created_at: str


class IncidentDetailOut(IncidentOut):
    summary: str
    summary_engine: str
    signals: List[dict]
    events: List[IncidentEventOut]


class IncidentPage(BaseModel):
    items: List[IncidentOut]
    total: int
    page: int
    page_size: int


class TransitionRequest(BaseModel):
    new_status: str = Field(..., min_length=1, max_length=20)
    resolution: Optional[str] = Field(default=None, max_length=40)
    note: Optional[str] = Field(default=None, max_length=2000)


class AssignRequest(BaseModel):
    user_id: Optional[str] = Field(default=None, max_length=36)


class NoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)
