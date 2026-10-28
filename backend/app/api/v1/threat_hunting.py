"""Unified `pg_trgm` fuzzy threat-hunting search across verdicts, IOCs, and dataset samples."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.user import UserModel
from app.api.deps import get_db, require_permission
from app.application.queries.search_threats import search_threats_query
from app.domain.iam.rbac import HUNTING_READ

router = APIRouter()


@router.get("/search")
async def search_threats(
    q: str = Query(..., min_length=2, description="Domain, sender, subject, IP, or lookalike string"),
    channel: Optional[str] = Query(default=None, pattern="^(EMAIL|SMS|WEB|QR)$"),
    verdict: Optional[str] = Query(default=None, pattern="^(CLEAN|SUSPICIOUS|MALICIOUS)$"),
    min_score: Optional[int] = Query(default=None, ge=0, le=100),
    limit: int = Query(default=25, ge=1, le=100),
    _: UserModel = Depends(require_permission(HUNTING_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Execute unified trigram similarity threat hunting across verdicts, IOCs, and dataset samples."""
    return await search_threats_query(
        db=db,
        query=q,
        channel=channel,
        verdict=verdict,
        min_score=min_score,
        limit=limit,
    )
