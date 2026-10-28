"""LangChain @tool wrapper for trigram brand similarity and PostgreSQL pg_trgm lookups."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from langchain_core.tools import tool
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.domain.detection.heuristics.homograph import PROTECTED_BANK_DOMAINS, normalize_confusables


def _trigrams(text: str) -> set[str]:
    padded = f"  {text.lower().strip()} "
    if len(padded) < 3:
        return {padded}
    return {padded[i : i + 3] for i in range(len(padded) - 2)}


def trigram_similarity(a: str, b: str) -> float:
    ta, tb = _trigrams(a), _trigrams(b)
    union = len(ta | tb)
    return round(len(ta & tb) / union, 4) if union else 0.0


async def run_pg_trgm_brand_check(
    domain: str,
    session: Optional[AsyncSession] = None,
) -> Dict[str, Any]:
    """Compute brand trigram similarity locally and against PostgreSQL `pg_trgm` indexes when session is present."""
    clean = (domain or "").strip().lower().split(":")[0]
    norm = normalize_confusables(clean)
    brand_matches: List[Dict[str, Any]] = []
    for brand_dom in PROTECTED_BANK_DOMAINS:
        if clean == brand_dom:
            continue
        sim = max(trigram_similarity(clean, brand_dom), trigram_similarity(norm, brand_dom))
        if sim >= 0.42:
            brand_matches.append({"protected_domain": brand_dom, "similarity": sim})
    brand_matches.sort(key=lambda x: x["similarity"], reverse=True)

    db_ioc_matches: List[Dict[str, Any]] = []
    db_sample_matches: List[Dict[str, Any]] = []
    if session is not None and clean:
        ioc_repo = IocRepository(session)
        sample_repo = DatasetRepository(session)
        for ioc_row, sim_val in await ioc_repo.search_fuzzy(clean, limit=5):
            db_ioc_matches.append(
                {
                    "ioc_value": ioc_row.ioc_value,
                    "list_type": ioc_row.list_type,
                    "similarity": round(sim_val, 4),
                }
            )
        db_sample_matches = await sample_repo.search_fuzzy(clean, limit=5)

    return {
        "domain": clean,
        "brand_lookalikes": brand_matches[:5],
        "fuzzy_iocs": db_ioc_matches,
        "fuzzy_samples": db_sample_matches[:5],
    }


@tool("pg_trgm_similarity_tool")
async def pg_trgm_similarity_tool(domain: str) -> Dict[str, Any]:
    """Compute trigram similarity of a domain against protected banking brands."""
    return await run_pg_trgm_brand_check(domain, session=None)
