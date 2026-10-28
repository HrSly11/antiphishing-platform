"""Indicators of Compromise (IOC) BLACKLIST/WHITELIST CRUD & pg_trgm fuzzy search endpoints."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.api.deps import get_client_ip, get_db, require_permission
from app.application.commands.manage_ioc import deactivate_ioc_command, upsert_ioc_command
from app.application.dto.report_dto import IocCreate, IocOut
from app.domain.iam.rbac import IOCS_READ, IOCS_WRITE

router = APIRouter()

_THREAT_LEVEL_SCORES = {
    "CRITICAL": 100,
    "HIGH": 85,
    "MEDIUM": 60,
    "LOW": 35,
}


class IocUpsertRequest(BaseModel):
    ioc_type: str = Field(..., pattern="^(DOMAIN|URL|IP|HASH|EMAIL)$")
    ioc_value: Optional[str] = Field(default=None, min_length=2, max_length=500)
    value: Optional[str] = Field(default=None, min_length=2, max_length=500)
    list_type: str = Field(default="BLACKLIST", pattern="^(BLACKLIST|WHITELIST)$")
    confidence_score: Optional[int] = Field(default=None, ge=0, le=100)
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    threat_level: Optional[str] = Field(default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    ttl_days: Optional[int] = Field(default=None, ge=1, le=3650)
    ttl_hours: Optional[int] = Field(default=None, ge=1, le=87600)
    source: Optional[str] = Field(default=None, max_length=100)
    reason: Optional[str] = Field(default=None, max_length=100)


def _serialize_ioc(row: IocModel, similarity: Optional[float] = None) -> IocOut:
    return IocOut(
        id=row.id,
        ioc_type=row.ioc_type,
        ioc_value=row.ioc_value,
        list_type=row.list_type,
        confidence_score=row.confidence_score,
        source=row.source,
        is_active=row.is_active,
        expires_at=row.expires_at.isoformat() if row.expires_at else None,
        created_at=row.created_at.isoformat() if row.created_at else "",
        similarity=round(float(similarity), 4) if similarity is not None else None,
    )


@router.get("")
@router.get("/", include_in_schema=False)
async def list_iocs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    list_type: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None),
    active_only: bool = Query(default=True),
    q: Optional[str] = Query(default=None),
    _: UserModel = Depends(require_permission(IOCS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated list of BLACKLIST and WHITELIST indicators of compromise."""
    offset = (page - 1) * page_size
    rows, total = await IocRepository(db).list(
        list_type=list_type,
        ioc_type=ioc_type,
        q=q,
        limit=page_size,
        offset=offset,
        active_only=active_only,
    )
    return {
        "items": [_serialize_ioc(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/search")
async def search_iocs(
    q: str = Query(..., min_length=2),
    threshold: float = Query(default=0.25, ge=0.05, le=1.0),
    limit: int = Query(default=20, ge=1, le=100),
    _: UserModel = Depends(require_permission(IOCS_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Fuzzy trigram (`pg_trgm`) IOC search for homographs, typosquats, and partial domains."""
    matches = await IocRepository(db).search_fuzzy(q=q, limit=limit, threshold=threshold)
    return {
        "query": q,
        "threshold": threshold,
        "items": [_serialize_ioc(row, sim) for row, sim in matches],
    }


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_or_upsert_ioc(
    payload: IocUpsertRequest,
    request: Request,
    current_user: UserModel = Depends(require_permission(IOCS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Create or upsert a BLACKLIST or WHITELIST IOC entry with optional TTL and n8n alert."""
    raw_value = (payload.ioc_value or payload.value or "").strip()
    if len(raw_value) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IOC value must be at least 3 characters",
        )

    resolved_conf = 100
    if payload.confidence_score is not None:
        resolved_conf = payload.confidence_score
    elif payload.confidence is not None:
        resolved_conf = payload.confidence
    elif payload.threat_level:
        resolved_conf = _THREAT_LEVEL_SCORES.get(payload.threat_level, 85)

    resolved_source = (payload.source or payload.reason or "MANUAL").strip()[:100]

    dto = IocCreate(
        ioc_type=payload.ioc_type,
        ioc_value=raw_value,
        list_type=payload.list_type,
        confidence_score=resolved_conf,
        ttl_days=payload.ttl_days,
        source=resolved_source,
    )
    ioc, created = await upsert_ioc_command(
        db=db,
        payload=dto,
        actor_email=current_user.email,
        client_ip=get_client_ip(request),
        ttl_hours=payload.ttl_hours,
    )
    await db.commit()
    return {**_serialize_ioc(ioc).model_dump(), "created": created}


@router.delete("/{ioc_id}")
async def deactivate_ioc(
    ioc_id: str,
    request: Request,
    current_user: UserModel = Depends(require_permission(IOCS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Deactivate an IOC entry while preserving forensic audit history."""
    ioc = await deactivate_ioc_command(
        db=db,
        ioc_id=ioc_id,
        actor_email=current_user.email,
        client_ip=get_client_ip(request),
    )
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    await db.commit()
    return {"id": ioc.id, "ioc_value": ioc.ioc_value, "is_active": False, "status": "deactivated"}
