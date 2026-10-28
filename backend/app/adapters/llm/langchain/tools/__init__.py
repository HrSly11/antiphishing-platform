"""LangChain tools suite for URL and domain threat investigation."""
from app.adapters.llm.langchain.tools.blacklist_tool import (
    blacklist_lookup_tool,
    run_blacklist_lookup,
)
from app.adapters.llm.langchain.tools.dns_tool import dns_lookup_tool
from app.adapters.llm.langchain.tools.pg_trgm_tool import (
    pg_trgm_similarity_tool,
    run_pg_trgm_brand_check,
    trigram_similarity,
)
from app.adapters.llm.langchain.tools.tls_tool import tls_certificate_tool
from app.adapters.llm.langchain.tools.whois_tool import whois_domain_age_tool

ALL_URL_TOOLS = [
    whois_domain_age_tool,
    dns_lookup_tool,
    tls_certificate_tool,
    pg_trgm_similarity_tool,
    blacklist_lookup_tool,
]

__all__ = [
    "ALL_URL_TOOLS",
    "blacklist_lookup_tool",
    "dns_lookup_tool",
    "pg_trgm_similarity_tool",
    "run_blacklist_lookup",
    "run_pg_trgm_brand_check",
    "tls_certificate_tool",
    "trigram_similarity",
    "whois_domain_age_tool",
]
