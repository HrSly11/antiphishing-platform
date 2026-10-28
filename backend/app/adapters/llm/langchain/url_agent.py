"""LangChain URL threat investigation agent orchestrating heuristics, DB IOCs, pg_trgm, and network tools."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnableLambda
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.feeds.whois_dns_tls import enrich_domain
from app.adapters.llm.factory import get_chat_model
from app.adapters.llm.langchain.tools import (
    ALL_URL_TOOLS,
    run_blacklist_lookup,
    run_pg_trgm_brand_check,
)
from app.adapters.llm.prompts.email_classification import sanitize_xml_delimiters
from app.adapters.llm.prompts.url_analysis import URL_ANALYSIS_PROMPT
from app.core.config import settings
from app.core.metrics import LLM_CALLS
from app.domain.dataset.versioning import domain_of, normalize_url
from app.domain.detection.heuristics.entropy import detect_high_entropy
from app.domain.detection.heuristics.homograph import detect_homograph_attack
from app.domain.detection.heuristics.typosquatting import detect_typosquatting
from app.domain.detection.heuristics.url_shortener import detect_url_shortener
from app.domain.detection.scoring import DetectionSignal, compute_risk_score

_RAW_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LOGIN_PATH_RE = re.compile(
    r"/(login|signin|auth|token|banca|coordenadas|verify|password|sso|owa)\b",
    re.IGNORECASE,
)


async def investigate_url(
    url: str,
    session: Optional[AsyncSession] = None,
    enable_network_tools: bool = True,
) -> Dict[str, Any]:
    """Run multi-tool LangChain investigation workflow on a suspicious URL."""
    norm_url = normalize_url(url) or url.strip()
    parsed = urlsplit(norm_url if "://" in norm_url else f"http://{norm_url}")
    domain = domain_of(norm_url) if "://" in norm_url else (parsed.hostname or "").lower()

    signals: List[DetectionSignal] = []
    hard_blacklist = False
    hard_whitelist = False

    # 1. Database IOC list + public dataset lookup tool
    bl_obs = await run_blacklist_lookup(norm_url, session=session)
    if bl_obs.get("list_decision") == "WHITELIST":
        hard_whitelist = True
    elif bl_obs.get("list_decision") == "BLACKLIST" or bl_obs.get("sample_match"):
        hard_blacklist = True
        signals.append(
            DetectionSignal(
                name="IOC_BLACKLIST_MATCH",
                weight=85,
                score=1.0,
                reason=f"URL or domain matched active threat intelligence ({bl_obs.get('matched_source') or 'BLACKLIST'}).",
                metadata={"url": norm_url, "domain": domain},
            )
        )

    # 2. Local lexical & Unicode heuristics
    is_homo, homo_desc, homo_conf = detect_homograph_attack(domain)
    if is_homo:
        signals.append(
            DetectionSignal(
                name="URL_HOMOGRAPH",
                weight=75,
                score=homo_conf,
                reason=f"Homograph/IDN spoofing detected: {homo_desc}",
                metadata={"url": norm_url, "domain": domain},
            )
        )

    is_typo, typo_desc, typo_conf = detect_typosquatting(domain)
    if is_typo:
        signals.append(
            DetectionSignal(
                name="URL_TYPOSQUATTING",
                weight=60,
                score=typo_conf,
                reason=f"Brand typosquatting/combosquatting: {typo_desc}",
                metadata={"url": norm_url, "domain": domain},
            )
        )

    is_ent, ent_val, ent_desc = detect_high_entropy(domain)
    if is_ent:
        signals.append(
            DetectionSignal(
                name="URL_HIGH_ENTROPY",
                weight=20,
                score=0.85,
                reason=ent_desc,
                metadata={"url": norm_url, "entropy": round(ent_val, 3)},
            )
        )

    is_short, short_desc = detect_url_shortener(domain)
    if is_short:
        signals.append(
            DetectionSignal(
                name="URL_SHORTENER",
                weight=25,
                score=1.0,
                reason=short_desc,
                metadata={"url": norm_url, "domain": domain},
            )
        )

    if _RAW_IP_RE.match(domain):
        signals.append(
            DetectionSignal(
                name="URL_RAW_IP",
                weight=45,
                score=1.0,
                reason=f"URL uses raw IPv4 host '{domain}' bypassing domain reputation.",
                metadata={"url": norm_url, "domain": domain},
            )
        )

    if parsed.scheme.lower() == "http" and _LOGIN_PATH_RE.search(parsed.path or ""):
        signals.append(
            DetectionSignal(
                name="HTTP_INSECURE_LOGIN_PATH",
                weight=30,
                score=1.0,
                reason="Unencrypted HTTP transport combined with authentication/credential path.",
                metadata={"url": norm_url, "path": parsed.path},
            )
        )

    # 3. Trigram similarity tool (`pg_trgm`)
    trgm_obs = await run_pg_trgm_brand_check(domain, session=session)
    official_set = {d.lower() for d in settings.OFFICIAL_DOMAINS}
    is_official = domain in official_set or any(domain.endswith("." + od) for od in official_set)
    if trgm_obs["brand_lookalikes"] and not is_official and not is_typo and not is_homo:
        top_brand = trgm_obs["brand_lookalikes"][0]
        signals.append(
            DetectionSignal(
                name="PG_TRGM_BRAND_SIMILARITY",
                weight=35,
                score=min(1.0, float(top_brand["similarity"])),
                reason=(
                    f"High trigram similarity ({top_brand['similarity']}) to protected brand "
                    f"'{top_brand['protected_domain']}'."
                ),
                metadata=top_brand,
            )
        )

    # 4. DNS / TLS / RDAP tools
    net_obs: Dict[str, Any] = {"enabled": False}
    if enable_network_tools and domain and not hard_whitelist:
        net_obs = await enrich_domain(domain)
        age_score = float(net_obs.get("age_risk_score") or 0.0)
        if age_score > 0:
            signals.append(
                DetectionSignal(
                    name="NEWLY_REGISTERED_DOMAIN",
                    weight=35,
                    score=age_score,
                    reason=str(net_obs.get("age_reason") or "Newly registered domain via RDAP"),
                    metadata={"domain": domain, "age_days": net_obs.get("rdap", {}).get("age_days")},
                )
            )
        tls_info = net_obs.get("tls", {})
        if parsed.scheme.lower() == "https" and tls_info.get("status") == "invalid_certificate":
            signals.append(
                DetectionSignal(
                    name="INVALID_TLS_CERTIFICATE",
                    weight=30,
                    score=1.0,
                    reason="Domain failed TLS X.509 certificate verification.",
                    metadata={"domain": domain},
                )
            )

    evaluation = compute_risk_score(
        signals,
        hard_blacklist=hard_blacklist,
        hard_whitelist=hard_whitelist,
    )

    tool_observations = {
        "blacklist_tool": bl_obs,
        "pg_trgm_tool": trgm_obs,
        "network_enrichment": net_obs,
        "registered_tools": [t.name for t in ALL_URL_TOOLS],
    }

    summary = evaluation.summary
    model, engine_name = get_chat_model(temperature=0.0)
    if model is not None:
        try:
            chain = URL_ANALYSIS_PROMPT | model | StrOutputParser()
            raw_llm = await chain.ainvoke(
                {
                    "url": sanitize_xml_delimiters(norm_url)[:500],
                    "observations_json": json.dumps(tool_observations, default=str)[:3000],
                }
            )
            match = re.search(r"\{.*\}", raw_llm or "", flags=re.DOTALL)
            if match:
                parsed_llm = json.loads(match.group(0))
                if isinstance(parsed_llm, dict) and parsed_llm.get("summary"):
                    summary = str(parsed_llm["summary"])[:900]
            LLM_CALLS.labels(engine=engine_name).inc()
        except Exception:
            engine_name = "langchain-url-agent-deterministic"
            LLM_CALLS.labels(engine=engine_name).inc()
    else:
        engine_name = "langchain-url-agent-deterministic"
        LLM_CALLS.labels(engine=engine_name).inc()

    return {
        "url": url,
        "normalized_url": norm_url,
        "domain": domain,
        "risk_score": evaluation.risk_score,
        "verdict": evaluation.verdict,
        "action": evaluation.action,
        "summary": summary,
        "signals": [
            {
                "name": s.name,
                "weight": s.weight,
                "score": s.score,
                "reason": s.reason,
                "metadata": s.metadata,
            }
            for s in evaluation.signals
        ],
        "tool_observations": tool_observations,
        "engine": engine_name,
    }


url_agent_runnable = RunnableLambda(lambda payload: investigate_url(payload["url"], payload.get("session")))
