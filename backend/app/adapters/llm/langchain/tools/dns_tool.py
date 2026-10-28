"""LangChain @tool wrapper for SSRF-guarded async DNS resolution."""
from __future__ import annotations

from typing import Any, Dict

from langchain_core.tools import tool

from app.adapters.feeds.whois_dns_tls import inspect_dns


@tool("dns_lookup_tool")
async def dns_lookup_tool(domain: str) -> Dict[str, Any]:
    """Resolve public A/AAAA DNS records for a domain while blocking RFC1918/loopback SSRF targets."""
    return await inspect_dns(domain, timeout=2.5)
