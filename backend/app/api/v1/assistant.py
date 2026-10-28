"""SOC AI Assistant endpoints: RAG runbook chat, URL investigation agent, and LangFlow sandboxes."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.llm.langchain.chat_soc_assistant import ask_soc_assistant
from app.adapters.llm.langchain.url_agent import investigate_url
from app.adapters.llm.langflow_bridge import FLOWS_DIR, list_langflow_sandboxes
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.api.deps import get_client_ip, get_current_user, get_db

router = APIRouter()


class AssistantChatRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=2000)
    incident_id: Optional[str] = Field(default=None, max_length=64)
    top_k: int = Field(default=4, ge=1, le=8)


class UrlInvestigationRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    enable_network_tools: bool = True


@router.post("/chat")
async def chat_with_soc_assistant(
    payload: AssistantChatRequest,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Answer SOC analyst questions grounded on `docs/{runbooks,compliance,architecture}` and live DB KPIs."""
    incident_ctx: Optional[Dict[str, Any]] = None
    effective_question = payload.question

    if payload.incident_id:
        detail = await IncidentRepository(db).get_by_id(payload.incident_id)
        if detail is not None:
            incident_ctx = {
                "id": detail["id"],
                "incident_code": detail["incident_code"],
                "severity": detail["severity"],
                "status": detail["status"],
                "sender_email": detail.get("sender_email"),
                "subject": detail.get("subject"),
                "risk_score": detail.get("risk_score"),
                "sla_overdue": detail.get("sla_overdue"),
            }
            effective_question = (
                f"{payload.question}\n"
                f"[Incident Context: {detail['incident_code']} severity={detail['severity']} "
                f"status={detail['status']} score={detail.get('risk_score')}]"
            )

    result = await ask_soc_assistant(
        question=effective_question,
        session=db,
        top_k=payload.top_k,
    )
    result["incident_context"] = incident_ctx

    await AuditRepository(db).append(
        user_email=current_user.email,
        action="ASSISTANT_CHAT_QUERY",
        resource=f"incident:{payload.incident_id}" if payload.incident_id else "assistant:kb",
        payload={
            "citations": result.get("citations", []),
            "injection_detected": result.get("injection_detected", False),
            "engine": result.get("engine"),
        },
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return result


@router.post("/investigate-url")
async def investigate_url_endpoint(
    payload: UrlInvestigationRequest,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Run the multi-tool LangChain URL threat investigation agent."""
    result = await investigate_url(
        url=payload.url,
        session=db,
        enable_network_tools=payload.enable_network_tools,
    )
    await AuditRepository(db).append(
        user_email=current_user.email,
        action="ASSISTANT_URL_INVESTIGATION",
        resource=f"url:{result.get('domain') or payload.url[:120]}",
        payload={
            "verdict": result.get("verdict"),
            "risk_score": result.get("risk_score"),
            "engine": result.get("engine"),
        },
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return result


@router.get("/flows")
async def get_langflow_sandboxes(
    _: UserModel = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return exported LangFlow v1 visual sandbox flows (`email_classifier_sandbox`, `url_agent_sandbox`)."""
    summaries = list_langflow_sandboxes()
    detailed: List[Dict[str, Any]] = []
    for item in summaries:
        flow_path = FLOWS_DIR / item["filename"]
        raw_definition = (
            json.loads(flow_path.read_text(encoding="utf-8"))
            if flow_path.exists()
            else {}
        )
        detailed.append({**item, "flow": raw_definition})
    return {"count": len(detailed), "flows": detailed}
