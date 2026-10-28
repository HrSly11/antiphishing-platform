"""LangChain @tool wrapper for RDAP/WHOIS domain-age enrichment."""
from __future__ import annotations

from typing import Any, Dict

from langchain_core.tools import tool

from app.adapters.feeds.whois_dns_tls import inspect_domain_age_rdap


@tool("whois_domain_age_tool")
async def whois_domain_age_tool(domain: str) -> Dict[str, Any]:
    """Query RDAP registration age (in days), creation date, and registrar for a public domain."""
    return await inspect_domain_age_rdap(domain, timeout=2.5)
