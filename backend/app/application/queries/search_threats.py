"""Unified `pg_trgm` fuzzy threat-hunting query across verdicts, IOCs, and public dataset samples."""
from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository


async def search_threats_query(
    db: AsyncSession,
    query: str,
    channel: Optional[str] = None,
    verdict: Optional[str] = None,
    min_score: Optional[int] = None,
    limit: int = 25,
) -> Dict[str, Any]:
    """Execute fuzzy trigram search across verdicts, IOCs, and dataset samples."""
    q_clean = (query or "").strip()
    if not q_clean:
        return {
            "query": "",
            "total_matches": 0,
            "verdicts": [],
            "iocs": [],
            "dataset_samples": [],
        }

    v_repo = VerdictRepository(db)
    ioc_repo = IocRepository(db)
    ds_repo = DatasetRepository(db)

    verdict_hits = await v_repo.search_fuzzy(q_clean, limit=limit * 2)
    if channel:
        ch_norm = channel.strip().upper()
        verdict_hits = [v for v in verdict_hits if v.get("channel") == ch_norm]
    if verdict:
        v_norm = verdict.strip().upper()
        if v_norm in {"MALICIOUS", "PHISHING"}:
            verdict_hits = [v for v in verdict_hits if v.get("verdict") in {"MALICIOUS", "PHISHING"}]
        else:
            verdict_hits = [v for v in verdict_hits if v.get("verdict") == v_norm]
    if min_score is not None:
        verdict_hits = [v for v in verdict_hits if int(v.get("risk_score") or 0) >= int(min_score)]
    verdict_hits = verdict_hits[:limit]

    ioc_tuples = await ioc_repo.search_fuzzy(q_clean, limit=limit)
    sample_hits = await ds_repo.search_fuzzy(q_clean, limit=limit)

    ioc_hits = [
        {
            "id": row.id,
            "ioc_type": row.ioc_type,
            "ioc_value": row.ioc_value,
            "list_type": row.list_type,
            "confidence_score": row.confidence_score,
            "source": row.source,
            "is_active": row.is_active,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "similarity": round(float(sim), 4),
        }
        for row, sim in ioc_tuples
        if min_score is None or int(row.confidence_score or 0) >= int(min_score)
    ]

    return {
        "query": q_clean,
        "total_matches": len(verdict_hits) + len(ioc_hits) + len(sample_hits),
        "verdicts": verdict_hits,
        "iocs": ioc_hits,
        "dataset_samples": sample_hits,
    }
