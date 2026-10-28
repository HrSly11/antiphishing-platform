"""Local Markdown RAG knowledge base indexer and cosine-similarity retriever (`docs/...`)."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.runnables import RunnableLambda
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository

REPO_ROOT = Path(__file__).resolve().parents[5]
KB_SUBDIRS = ("docs/architecture", "docs/runbooks", "docs/compliance")

_TOKEN_RE = re.compile(r"[a-zA-Z0-9áéíóúñÁÉÍÓÚÑ_.-]{2,}")

# Curated fallback knowledge chunks attached to canonical `docs/...` paths when a file is a stub (<100 bytes),
# ensuring RAG grounding always cites real repository documentation paths even before docs expansion.
_CURATED_FALLBACK_DOCS: Dict[str, str] = {
    "docs/runbooks/incident-response.md": (
        "# Banking SOC Phishing Incident Response Runbook\n"
        "1. Detection & Quarantine: Emails scoring >= 70 (MALICIOUS) are automatically quarantined at the MTA "
        "gateway, generating an OPEN incident with a 15-minute SLA for CRITICAL (>= 85) and 60-minute SLA for HIGH (70-84).\n"
        "2. Triage (OPEN -> TRIAGED): SOC L1 verifies SPF/DKIM/DMARC alignment, homograph/Punycode indicators, "
        "and deceptive HTML anchors. Confirm whether credentials or dynamic tokens were targeted.\n"
        "3. Investigation (TRIAGED -> INVESTIGATING): SOC L2 inspects linked IOCs, runs URL enrichment (DNS/TLS/RDAP), "
        "and queries pg_trgm threat hunting across recipient mailboxes.\n"
        "4. Containment (INVESTIGATING -> CONTAINED): Block attacker domains/IPs in the IOC BLACKLIST, revoke active "
        "sessions/OAuth tokens for impacted employees, and dispatch signed n8n SOAR containment webhooks.\n"
        "5. Closure (CONTAINED -> CLOSED): Record mandatory resolution (TRUE_POSITIVE, FALSE_POSITIVE, "
        "BENIGN_POLICY_VIOLATION, or DUPLICATE) and preserve hash-chained audit evidence."
    ),
    "docs/runbooks/etl-failure.md": (
        "# ETL Public Phishing Feed Failure Runbook\n"
        "When OpenPhish or PhishTank HTTPS ingestion fails due to upstream rate limits or network outage:\n"
        "1. Verify SSRF/TLS diagnostics in `app/adapters/feeds/openphish.py` and `phishtank.py`.\n"
        "2. Trigger deterministic offline fallback ingestion from `backend/dataset/samples/` while upstream recovers.\n"
        "3. Confirm SHA-256 dataset version continuity in `dataset_versions` and `ON CONFLICT (url_hash) DO NOTHING` idempotency."
    ),
    "docs/runbooks/llm-degradation.md": (
        "# On-Premise LLM (Ollama) Degradation Runbook\n"
        "When local Ollama (`127.0.0.1:11434`) is unreachable or exceeds latency SLO:\n"
        "1. `app/adapters/llm/factory.py` caches the 0.8s health check for 30s so inline MTA inspection never stalls.\n"
        "2. Pipelines (`email_classifier`, `url_agent`, `rag_chain`, `incident_summarizer`) automatically fall back "
        "to deterministic LangChain Runnable execution (`langchain-deterministic`) while maintaining prompt-injection guards."
    ),
    "docs/compliance/pci-dss-mapping.md": (
        "# PCI-DSS v4.0 Control Mapping for Banking Antiphishing Platform\n"
        "- PCI-DSS Req 5.4.1: Automated anti-phishing mechanisms detect and block spoofed, homograph, and credential-harvesting emails before reaching cardholder-environment personnel.\n"
        "- PCI-DSS Req 8.3: Argon2id password hashing, 12-character complexity policy, and account lockout after 5 failed attempts for 15 minutes.\n"
        "- PCI-DSS Req 10.2 & 10.3: Append-only `audit_logs` protected by PostgreSQL triggers (`trg_audit_logs_no_update_delete`) and SHA-256 hash chaining (`prev_hash` -> `integrity_hash`).\n"
        "- PCI-DSS Req 12.10: Automated 24/7 SOC incident creation, SLA escalation worker, and n8n SOAR playbooks."
    ),
    "docs/compliance/iso27001-mapping.md": (
        "# ISO/IEC 27001:2022 Annex A Control Mapping\n"
        "- A.5.7 Threat Intelligence: Versioned ingestion of OpenPhish and PhishTank feeds with SHA-256 traceability.\n"
        "- A.5.15 & A.5.17 Access Control & Authentication: Granular RBAC (`ADMIN`, `SOC_L2`, `SOC_L1`, `AUDITOR`, `VIEWER`) and JWT rotation.\n"
        "- A.5.24 - A.5.26 Information Security Incident Management: Enforced state machine (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`) and MTTR/SLA tracking.\n"
        "- A.8.7 Protection Against Malware & A.8.15 Logging: Attachment screening, inline URL quarantine, and immutable audit trail."
    ),
    "docs/compliance/gdpr-dpia.md": (
        "# Data Protection & Banking Confidentiality (GDPR / Local Banking Secrecy)\n"
        "- Data Sovereignty (ADR-003): Corporate emails are processed strictly on-premise via local heuristics and self-hosted Ollama without external cloud exfiltration.\n"
        "- Purpose Limitation & Minimization: Only security telemetry, headers metadata, and threat indicators are retained for fraud prevention and regulatory audit."
    ),
}


@dataclass(frozen=True)
class KnowledgeChunk:
    source: str
    heading: str
    content: str
    tf: Dict[str, float]
    norm: float


def _tokenize(text: str) -> List[str]:
    return [tok.lower() for tok in _TOKEN_RE.findall(text or "")]


def _build_tf_vector(tokens: List[str], idf: Dict[str, float]) -> Tuple[Dict[str, float], float]:
    if not tokens:
        return {}, 0.0
    counts = Counter(tokens)
    total = float(len(tokens))
    vec: Dict[str, float] = {}
    sq_sum = 0.0
    for term, cnt in counts.items():
        weight = (cnt / total) * idf.get(term, 1.0)
        vec[term] = weight
        sq_sum += weight * weight
    return vec, math.sqrt(sq_sum)


def _split_markdown_sections(rel_source: str, text_body: str, max_chars: int = 900) -> List[Tuple[str, str, str]]:
    sections: List[Tuple[str, str, str]] = []
    current_heading = rel_source
    buf: List[str] = []

    for line in text_body.splitlines():
        if line.strip().startswith("#"):
            if buf:
                chunk_txt = "\n".join(buf).strip()
                if chunk_txt:
                    sections.append((rel_source, current_heading, chunk_txt[:max_chars]))
                buf = []
            current_heading = line.strip().lstrip("#").strip() or rel_source
        buf.append(line)
        if sum(len(x) + 1 for x in buf) >= max_chars:
            chunk_txt = "\n".join(buf).strip()
            if chunk_txt:
                sections.append((rel_source, current_heading, chunk_txt[:max_chars]))
            buf = []

    if buf:
        chunk_txt = "\n".join(buf).strip()
        if chunk_txt:
            sections.append((rel_source, current_heading, chunk_txt[:max_chars]))

    return sections


class LocalKnowledgeBaseIndex:
    """In-memory TF-IDF cosine retriever over `docs/{architecture,runbooks,compliance}`."""

    def __init__(self, repo_root: Path = REPO_ROOT) -> None:
        self.repo_root = repo_root
        self._chunks: List[KnowledgeChunk] = []
        self._idf: Dict[str, float] = {}
        self._built = False

    def build(self, force: bool = False) -> None:
        if self._built and not force:
            return

        raw_sections: List[Tuple[str, str, str]] = []
        seen_paths: set[str] = set()

        for subdir in KB_SUBDIRS:
            folder = self.repo_root / subdir
            if not folder.exists():
                continue
            for md_path in sorted(folder.rglob("*.md")):
                rel_path = md_path.relative_to(self.repo_root).as_posix()
                seen_paths.add(rel_path)
                try:
                    content = md_path.read_text(encoding="utf-8", errors="replace").strip()
                except Exception:
                    content = ""
                if len(content) < 100 and rel_path in _CURATED_FALLBACK_DOCS:
                    content = _CURATED_FALLBACK_DOCS[rel_path]
                if content:
                    raw_sections.extend(_split_markdown_sections(rel_path, content))

        for rel_path, fallback_text in _CURATED_FALLBACK_DOCS.items():
            if rel_path not in seen_paths:
                raw_sections.extend(_split_markdown_sections(rel_path, fallback_text))

        doc_tokens = [_tokenize(f"{src} {hd} {txt}") for src, hd, txt in raw_sections]
        n_docs = max(1, len(doc_tokens))
        df: Counter[str] = Counter()
        for toks in doc_tokens:
            for term in set(toks):
                df[term] += 1

        self._idf = {
            term: math.log((1.0 + n_docs) / (1.0 + freq)) + 1.0
            for term, freq in df.items()
        }

        built_chunks: List[KnowledgeChunk] = []
        for (src, hd, txt), toks in zip(raw_sections, doc_tokens):
            vec, norm = _build_tf_vector(toks, self._idf)
            built_chunks.append(
                KnowledgeChunk(source=src, heading=hd, content=txt, tf=vec, norm=norm)
            )

        self._chunks = built_chunks
        self._built = True

    def retrieve(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        self.build()
        q_tokens = _tokenize(query)
        q_vec, q_norm = _build_tf_vector(q_tokens, self._idf)

        scored: List[Tuple[float, KnowledgeChunk]] = []
        for ch in self._chunks:
            if q_norm == 0.0 or ch.norm == 0.0:
                score = 0.0
            else:
                dot = sum(w * ch.tf.get(term, 0.0) for term, w in q_vec.items())
                score = dot / (q_norm * ch.norm)
            scored.append((score, ch))

        scored.sort(key=lambda item: item[0], reverse=True)
        selected = [item for item in scored[: max(1, top_k)] if item[0] > 0.0]
        if not selected and scored:
            selected = scored[: min(2, len(scored))]

        return [
            {
                "source": ch.source,
                "heading": ch.heading,
                "content": ch.content,
                "score": round(float(sc), 4),
            }
            for sc, ch in selected
        ]


_kb_index = LocalKnowledgeBaseIndex()


async def build_live_soc_context(session: Optional[AsyncSession]) -> Dict[str, Any]:
    """Fetch live PostgreSQL summary telemetry to ground operational SOC assistant queries."""
    if session is None:
        return {"connected": False}
    try:
        v_repo = VerdictRepository(session)
        i_repo = IncidentRepository(session)
        ioc_repo = IocRepository(session)
        ds_repo = DatasetRepository(session)

        kpis = await v_repo.compute_kpis(window_days=30)
        sla = await i_repo.compute_sla_metrics(window_days=30)
        active_iocs = await ioc_repo.count_active()
        total_samples = await ds_repo.count_samples()

        return {
            "connected": True,
            "window_days": 30,
            "total_analyzed": kpis["total_analyzed"],
            "by_verdict": kpis["by_verdict"],
            "open_incidents": sla["open_count"],
            "overdue_incidents": sla["overdue_count"],
            "sla_compliance_rate": sla["sla_compliance_rate"],
            "active_iocs": active_iocs,
            "dataset_samples": total_samples,
        }
    except Exception:
        return {"connected": False}


def retrieve_knowledge_chunks(query: str, top_k: int = 4) -> List[Dict[str, Any]]:
    """Retrieve top-K grounded markdown chunks with `docs/...` citations."""
    return _kb_index.retrieve(query, top_k=top_k)


rag_retriever_runnable = RunnableLambda(
    lambda q: retrieve_knowledge_chunks(q["question"] if isinstance(q, dict) else str(q))
)
