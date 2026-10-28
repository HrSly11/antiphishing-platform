"""Analytical SOC Dashboard KPIs endpoint (CQRS selective read path)."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ActorPrincipal, allow_service_or_permission, get_db
from app.application.queries.get_dashboard_kpis import get_dashboard_kpis_query
from app.domain.iam.rbac import DASHBOARD_READ

router = APIRouter()


@router.get("/kpis")
async def get_dashboard_kpis(
    window_days: int = Query(default=30, ge=1, le=365),
    _: ActorPrincipal = Depends(allow_service_or_permission(DASHBOARD_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Compute real-time analytical SOC KPIs, confusion rates, latencies, trends, and SLA compliance."""
    return await get_dashboard_kpis_query(db=db, window_days=window_days)
