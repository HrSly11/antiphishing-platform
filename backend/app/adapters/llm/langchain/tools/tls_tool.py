"""LangChain @tool wrapper for TLS 443 certificate inspection."""
from __future__ import annotations

from typing import Any, Dict

from langchain_core.tools import tool

from app.adapters.feeds.whois_dns_tls import inspect_tls


@tool("tls_certificate_tool")
async def tls_certificate_tool(domain: str) -> Dict[str, Any]:
    """Inspect TLS 443 certificate chain validity, issuer, and expiration window for a domain."""
    return await inspect_tls(domain, timeout=2.5)
