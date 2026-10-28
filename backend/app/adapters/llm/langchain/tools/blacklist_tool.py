"""LangChain @tool wrapper for IOC blacklist/whitelist and public phishing dataset lookups."""
from __future__ import annotations

from typing import Any, Dict, Optional

from langchain_core.tools import tool
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.domain.dataset.versioning import domain_of, normalize_url, url_hash
from app.domain.ioc.lists import ListEntry, decide


async def run_blacklist_lookup(
    url_or_domain: str,
    session: Optional[AsyncSession] = None,
) -> Dict[str, Any]:
    """Check active IOC blacklist/whitelist entries and `phishing_samples` hashes in PostgreSQL."""
    norm_url = normalize_url(url_or_domain) or url_or_domain.strip().lower()
    dom = domain_of(norm_url) if "://" in norm_url else norm_url.split("/")[0].split(":")[0]
    uhash = url_hash(norm_url) if "://" in norm_url else None

    if session is None:
        return {
            "target": norm_url,
            "domain": dom,
            "list_decision": None,
            "sample_match": False,
            "matched_source": None,
        }

    ioc_repo = IocRepository(session)
    entries = await ioc_repo.find_entries([norm_url, dom])
    domain_entries = [
        ListEntry(
            value=e.ioc_value,
            list_type=e.list_type,
            source=e.source,
            expires_at=e.expires_at,
            is_active=e.is_active,
        )
        for e in entries
    ]
    decision = decide(domain_entries)

    ds_repo = DatasetRepository(session)
    sample = await ds_repo.lookup_url_or_domain(uhash, dom)

    matched_source = None
    if entries:
        matched_source = entries[0].source
    elif sample is not None:
        matched_source = sample.source

    return {
        "target": norm_url,
        "domain": dom,
        "list_decision": decision,
        "sample_match": sample is not None,
        "matched_source": matched_source,
    }


@tool("blacklist_lookup_tool")
async def blacklist_lookup_tool(url_or_domain: str) -> Dict[str, Any]:
    """Check whether a URL or domain appears in institutional IOC lists or phishing feeds."""
    return await run_blacklist_lookup(url_or_domain, session=None)
