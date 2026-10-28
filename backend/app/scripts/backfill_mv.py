"""Refresh PostgreSQL analytical statistics (`ANALYZE`) and verify KPI rollup queries."""
from __future__ import annotations

import asyncio
import json

from sqlalchemy import text

from app.adapters.persistence.database import async_session_factory, engine
from app.application.queries.get_dashboard_kpis import get_dashboard_kpis_query


async def refresh_analytical_stats() -> dict:
    async with async_session_factory() as db:
        for tbl in (
            "detection_verdicts",
            "incidents",
            "iocs",
            "phishing_samples",
            "dataset_versions",
            "simulation_campaigns",
            "simulation_events",
            "audit_logs",
        ):
            await db.execute(text(f"ANALYZE {tbl}"))
        await db.commit()
        kpis = await get_dashboard_kpis_query(db=db, window_days=30)
        return {
            "status": "analyzed",
            "total_analyzed": kpis["total_analyzed"],
            "active_iocs_count": kpis["active_iocs_count"],
            "dataset_samples_count": kpis["dataset_samples_count"],
        }


async def _main() -> None:
    try:
        res = await refresh_analytical_stats()
        print(json.dumps(res, indent=2))
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
