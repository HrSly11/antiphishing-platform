"""Threat intelligence dataset ETL worker (OpenPhish & PhishTank with SHA-256 versioning)."""
from __future__ import annotations

import argparse
import asyncio
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.database import async_session_factory, engine
from app.application.commands.ingest_dataset import ingest_dataset_command
from app.core.logging import get_logger

log = get_logger("worker.etl")


async def _run_on_session(
    db: AsyncSession,
    sources: Iterable[str],
    prefer_live: bool,
    sync_blacklist: bool,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for src in sources:
        version = await ingest_dataset_command(
            db=db,
            source=src,
            prefer_live=prefer_live,
            sync_blacklist=sync_blacklist,
            actor_email="etl-worker@bancocentral.com",
        )
        summary = {
            "version_id": version.id,
            "source": version.source,
            "sha256": version.sha256,
            "status": version.status,
            "total_rows": version.total_records,
            "new_rows": version.new_records,
            "duplicate_rows": version.duplicate_records,
            "created_at": version.created_at.isoformat() if version.created_at else "",
        }
        log.info("ETL ingested %s (new=%d, dup=%d)", version.source, version.new_records, version.duplicate_records)
        results.append(summary)
    return results


async def run_etl_cycle(
    db: Optional[AsyncSession] = None,
    sources: Iterable[str] = ("openphish", "phishtank"),
    prefer_live: bool = False,
    sync_blacklist: bool = True,
) -> List[Dict[str, Any]]:
    """Execute one idempotent ETL cycle across configured public phishing feeds."""
    if db is not None:
        return await _run_on_session(db, sources, prefer_live, sync_blacklist)

    async with async_session_factory() as session:
        res = await _run_on_session(session, sources, prefer_live, sync_blacklist)
        await session.commit()
        return res


async def _cli() -> None:
    parser = argparse.ArgumentParser(description="Run phishing threat dataset ETL cycle.")
    parser.add_argument("--live", action="store_true", help="Attempt live HTTPS feed download before local fallback.")
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["openphish", "phishtank"],
        help="Feed sources to ingest (openphish, phishtank).",
    )
    args = parser.parse_args()
    try:
        summaries = await run_etl_cycle(sources=args.sources, prefer_live=args.live)
        for item in summaries:
            print(item)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_cli())
